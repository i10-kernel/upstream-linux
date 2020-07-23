// SPDX-License-Identifier: GPL-2.0
/*
 * The i10 I/O scheduler - supports batching at blk-mq.
 * 
 * An early version of the idea is described and evaluated in
 * "TCP ≈ RDMA: CPU-efficient Remote Storage Access with i10",
 * USENIX NSDI 2020.
 *
 * Copyright (C) 2020 Cornell University
 *	Jaehyun Hwang <jaehyun.hwang@cornell.edu>
 *	Qizhe Cai <qc228@cornell.edu>
 *	Ao Tang <atang@cornell.edu>
 *	Rachit Agarwal <ragarwal@cornell.edu>	
 */

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

/* Default batch size in number of requests */
#define I10_BATCH_NR		16
/* Default batch size in bytes (for write requests) */
#define	I10_BATCH_BYTES		65536
/* Default timeout value for delayed doorbell (us units) */
#define I10_BATCH_TIMEOUT	50

enum i10_state {
	/* Batching state:
	 * Do not run dispatching until we have
	 * a certain amount of requests or a timer expires.
	 */
	I10_STATE_BATCH = 0,

	/* Dispatching state:
	 * Run dispatching until all requests in the
	 * scheduler's hctx queue are dispatched.
	 */
	I10_STATE_DISPATCH,
};

struct i10_queue_data {
	struct request_queue *q;

	unsigned int	def_batch_nr;
	unsigned int	def_batch_bytes;
	unsigned int	def_batch_timeout;
};

struct i10_hctx_queue {
	spinlock_t	lock;
	struct		list_head rq_list;

	struct blk_mq_hw_ctx	*hctx;

	unsigned int	batch_nr;
	unsigned int	batch_bytes;
	unsigned int	batch_timeout;

	unsigned int	qlen_nr;
	unsigned int	qlen_bytes;

	struct hrtimer	doorbell_timer;
	enum i10_state	state;
};

static struct i10_queue_data *i10_queue_data_alloc(struct request_queue *q)
{
	struct i10_queue_data *qdata;

	qdata = kzalloc_node(sizeof(*qdata), GFP_KERNEL, q->node);
	if (!qdata)
		return ERR_PTR(-ENOMEM);

	qdata->q = q;
	qdata->def_batch_nr = I10_BATCH_NR;
	qdata->def_batch_bytes = I10_BATCH_BYTES;
	qdata->def_batch_timeout = I10_BATCH_TIMEOUT;

	return qdata;
}

static int i10_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct i10_queue_data *qdata;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	qdata = i10_queue_data_alloc(q);
	if (IS_ERR(qdata)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(qdata);
	}

	blk_stat_enable_accounting(q);

	eq->elevator_data = qdata;
	q->elevator = eq;

	return 0;
}

static void i10_exit_sched(struct elevator_queue *e)
{
	struct i10_queue_data *qdata = e->elevator_data;
	kfree(qdata);
}

enum hrtimer_restart i10_hctx_doorbell_timeout(struct hrtimer *timer)
{
	struct i10_hctx_queue *queue =
		container_of(timer, struct i10_hctx_queue,
			doorbell_timer);

	queue->state = I10_STATE_DISPATCH;
	blk_mq_run_hw_queue(queue->hctx, true);

	return HRTIMER_NORESTART;
}

static void i10_hctx_queue_reset(struct i10_hctx_queue *queue)
{
	queue->qlen_nr = 0;
	queue->qlen_bytes = 0;
	queue->state = I10_STATE_BATCH;
}

static int i10_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct i10_hctx_queue *queue;

	queue = kmalloc_node(sizeof(*queue), GFP_KERNEL, hctx->numa_node);
	if (!queue)
		return -ENOMEM;

	spin_lock_init(&queue->lock);
	INIT_LIST_HEAD(&queue->rq_list);

	queue->hctx = hctx;
	queue->batch_nr = 0;
	queue->batch_bytes = 0;
	queue->batch_timeout = 0;

	hrtimer_init(&queue->doorbell_timer,
		CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	queue->doorbell_timer.function = &i10_hctx_doorbell_timeout;

	i10_hctx_queue_reset(queue);

	hctx->sched_data = queue;

	return 0;
}

static void i10_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct i10_hctx_queue *queue = hctx->sched_data;

	if (hrtimer_active(&queue->doorbell_timer))
		hrtimer_cancel(&queue->doorbell_timer);
	kfree(hctx->sched_data);
}

static bool i10_hctx_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio,
		unsigned int nr_segs)
{
	struct i10_hctx_queue *queue = hctx->sched_data;
	struct list_head *rq_list = &queue->rq_list;
	bool merged;

	spin_lock(&queue->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, rq_list, bio, nr_segs);
	spin_unlock(&queue->lock);

	if (merged && (bio->bi_opf & REQ_OP_MASK) == REQ_OP_WRITE)
		queue->qlen_bytes += bio->bi_iter.bi_size;

	return merged;
}

/*
 * The batch size can be adjusted dynamically on a per-hctx basis. Use per-hctx
 * variables in that case.
 */
static inline unsigned int i10_hctx_batch_nr(struct blk_mq_hw_ctx *hctx)
{
	struct i10_queue_data *qdata = hctx->queue->elevator->elevator_data;
	struct i10_hctx_queue *queue = hctx->sched_data;

	return queue->batch_nr ?
		queue->batch_nr : qdata->def_batch_nr;
}

static inline unsigned int i10_hctx_batch_bytes(struct blk_mq_hw_ctx *hctx)
{
	struct i10_queue_data *qdata = hctx->queue->elevator->elevator_data;
	struct i10_hctx_queue *queue = hctx->sched_data;

	return queue->batch_bytes ?
		queue->batch_bytes : qdata->def_batch_bytes;
}

static inline unsigned int i10_hctx_batch_timeout(struct blk_mq_hw_ctx *hctx)
{
	struct i10_queue_data *qdata = hctx->queue->elevator->elevator_data;
	struct i10_hctx_queue *queue = hctx->sched_data;

	return queue->batch_timeout ?
		queue->batch_timeout : qdata->def_batch_timeout;
}

static void i10_hctx_insert_update(struct i10_hctx_queue *queue,
				struct request *rq)
{
	if ((rq->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE)
		queue->qlen_bytes += blk_rq_bytes(rq);
	queue->qlen_nr++;
}

static void i10_hctx_insert_requests(struct blk_mq_hw_ctx *hctx,
				struct list_head *rq_list, bool at_head)
{
	struct i10_hctx_queue *queue = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rq_list, queuelist) {
		struct list_head *head = &queue->rq_list;

		spin_lock(&queue->lock);
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		i10_hctx_insert_update(queue, rq);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&queue->lock);
	}

	/* Start a new timer */
	if (queue->state == I10_STATE_BATCH &&
		!hrtimer_active(&queue->doorbell_timer))
		hrtimer_start(&queue->doorbell_timer,
			ns_to_ktime(i10_hctx_batch_timeout(hctx)
				* NSEC_PER_USEC),
			HRTIMER_MODE_REL);
}

static struct request *i10_hctx_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct i10_hctx_queue *queue = hctx->sched_data;
	struct request *rq;

	spin_lock(&queue->lock);
	rq = list_first_entry_or_null(&queue->rq_list,
				struct request, queuelist);
	if (rq)
	 	list_del_init(&rq->queuelist);
	else
		i10_hctx_queue_reset(queue);
	spin_unlock(&queue->lock);

	return rq;
}

static inline bool i10_hctx_dispatch_now(struct blk_mq_hw_ctx *hctx)
{
	struct i10_hctx_queue *queue = hctx->sched_data;

	return (queue->qlen_nr >= i10_hctx_batch_nr(hctx)) ||
		(queue->qlen_bytes >= i10_hctx_batch_bytes(hctx));
}

/*
 * Return true if we are in the dispatching state.
 */
static bool i10_hctx_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct i10_hctx_queue *queue = hctx->sched_data;

	if (queue->state == I10_STATE_BATCH) {
		if (i10_hctx_dispatch_now(hctx)) {
			queue->state = I10_STATE_DISPATCH;
			if (hrtimer_active(&queue->doorbell_timer))
				hrtimer_cancel(&queue->doorbell_timer);
		}
	}

	return (queue->state == I10_STATE_DISPATCH);
}

#define I10_DEF_BATCH_SHOW_STORE(name)					\
static ssize_t i10_def_batch_##name##_show(struct elevator_queue *e,	\
				char *page)				\
{									\
	struct i10_queue_data *qdata = e->elevator_data;		\
									\
	return sprintf(page, "%u\n", qdata->def_batch_##name);		\
}									\
									\
static ssize_t i10_def_batch_##name##_store(struct elevator_queue *e,	\
			const char *page, size_t count)			\
{									\
	struct i10_queue_data *qdata = e->elevator_data;		\
	unsigned long long value;					\
	int ret;							\
									\
	ret = kstrtoull(page, 10, &value);				\
	if (ret)							\
		return ret;						\
									\
	qdata->def_batch_##name = value;				\
									\
	return count;							\
}
I10_DEF_BATCH_SHOW_STORE(nr);
I10_DEF_BATCH_SHOW_STORE(bytes);
I10_DEF_BATCH_SHOW_STORE(timeout);
#undef I10_DEF_BATCH_SHOW_STORE

#define I10_SCHED_ATTR(name)	\
	__ATTR(batch_##name, 0644, i10_def_batch_##name##_show, i10_def_batch_##name##_store)
static struct elv_fs_entry i10_sched_attrs[] = {
	I10_SCHED_ATTR(nr),
	I10_SCHED_ATTR(bytes),
	I10_SCHED_ATTR(timeout),
	__ATTR_NULL
};
#undef I10_SCHED_ATTR

#ifdef CONFIG_BLK_DEBUG_FS
#define I10_DEBUGFS_SHOW(name)	\
static int i10_hctx_batch_##name##_show(void *data, struct seq_file *m)	\
{									\
	struct blk_mq_hw_ctx *hctx = data;				\
	struct i10_hctx_queue *queue = hctx->sched_data;		\
									\
	seq_printf(m, "%u\n", queue->batch_##name);			\
	return 0;							\
}									\
									\
static int i10_hctx_qlen_##name##_show(void *data, struct seq_file *m)	\
{									\
	struct blk_mq_hw_ctx *hctx = data;				\
	struct i10_hctx_queue *queue = hctx->sched_data;		\
									\
	seq_printf(m, "%u\n", queue->qlen_##name);			\
	return 0;							\
}
I10_DEBUGFS_SHOW(nr);
I10_DEBUGFS_SHOW(bytes);
#undef I10_DEBUGFS_SHOW

static int i10_hctx_state_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct i10_hctx_queue *queue = hctx->sched_data;

	seq_printf(m, "%d\n", queue->state);
	return 0;
}

#define I10_HCTX_QUEUE_ATTR(name)					\
	{"batch_" #name, 0400, i10_hctx_batch_##name##_show},		\
	{"qlen_" #name, 0400, i10_hctx_qlen_##name##_show}
static const struct blk_mq_debugfs_attr i10_hctx_debugfs_attrs[] = {
	I10_HCTX_QUEUE_ATTR(nr),
	I10_HCTX_QUEUE_ATTR(bytes),
	{"state", 0400, i10_hctx_state_show},
	{},
};
#undef I10_HCTX_QUEUE_ATTR
#endif

static struct elevator_type i10_sched = {
	.ops = {
		.init_sched = i10_init_sched,
		.exit_sched = i10_exit_sched,
		.init_hctx = i10_init_hctx,
		.exit_hctx = i10_exit_hctx,
		.bio_merge = i10_hctx_bio_merge,
		.insert_requests = i10_hctx_insert_requests,
		.dispatch_request = i10_hctx_dispatch_request,
		.has_work = i10_hctx_has_work,
	},
#ifdef CONFIG_BLK_DEBUG_FS
	.hctx_debugfs_attrs = i10_hctx_debugfs_attrs,
#endif
	.elevator_attrs = i10_sched_attrs,
	.elevator_name = "i10",
	.elevator_owner = THIS_MODULE,
};

static int __init i10_init(void)
{
	return elv_register(&i10_sched);
}

static void __exit i10_exit(void)
{
	elv_unregister(&i10_sched);
}

module_init(i10_init);
module_exit(i10_exit);

MODULE_AUTHOR("Jaehyun Hwang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("i10 I/O scheduler");
