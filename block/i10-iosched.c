// SPDX-License-Identifier: GPL-2.0
/*
 * The i10 I/O Scheduler - supports batching at blk-mq.
 *	The main use case is disaggregated storage access
 *	using NVMe-over-Fabric (e.g., NVMe-over-TCP device driver).
 *
 * An early version of the idea is described and evaluated in
 * "TCP ≈ RDMA: CPU-efficient Remote Storage Access with i10",
 * USENIX NSDI 2020.
 *
 * Copyright (C) 2020 Cornell University
 *	Jaehyun Hwang <jaehyun.hwang@cornell.edu>
 *	Qizhe Cai <qc228@cornell.edu>
 *	Midhul Vuppalapati <mvv25@cornell.edu%>
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
#define I10_DEF_BATCH_NR	16
/* Default batch size in bytes (for write requests) */
#define I10_DEF_BATCH_BYTES	65536
/* Default timeout value for batching (us units) */
#define I10_DEF_BATCH_TIMEOUT	50

enum i10_state {
	/* Batching state:
	 * Do not run dispatching until we have
	 * a certain amount of requests or a timer expires.
	 */
	I10_STATE_BATCH,

	/* Dispatching state:
	 * Run dispatching until all requests in the
	 * scheduler's hctx ihq are dispatched.
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
	spinlock_t		lock;
	struct list_head	rq_list;

	struct blk_mq_hw_ctx	*hctx;

	unsigned int	batch_nr;
	unsigned int	batch_bytes;
	unsigned int	batch_timeout;

	unsigned int	qlen_nr;
	unsigned int	qlen_bytes;

	struct hrtimer	dispatch_timer;
	enum i10_state	state;
};

static struct i10_queue_data *i10_queue_data_alloc(struct request_queue *q)
{
	struct i10_queue_data *iqd;

	iqd = kzalloc_node(sizeof(*iqd), GFP_KERNEL, q->node);
	if (!iqd)
		return ERR_PTR(-ENOMEM);

	iqd->q = q;
	iqd->def_batch_nr = I10_DEF_BATCH_NR;
	iqd->def_batch_bytes = I10_DEF_BATCH_BYTES;
	iqd->def_batch_timeout = I10_DEF_BATCH_TIMEOUT;

	return iqd;
}

static int i10_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct i10_queue_data *iqd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	iqd = i10_queue_data_alloc(q);
	if (IS_ERR(iqd)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(iqd);
	}

	blk_stat_enable_accounting(q);

	eq->elevator_data = iqd;
	q->elevator = eq;

	return 0;
}

static void i10_exit_sched(struct elevator_queue *e)
{
	struct i10_queue_data *iqd = e->elevator_data;

	kfree(iqd);
}

enum hrtimer_restart i10_hctx_timeout_handler(struct hrtimer *timer)
{
	struct i10_hctx_queue *ihq =
		container_of(timer, struct i10_hctx_queue,
			dispatch_timer);

	ihq->state = I10_STATE_DISPATCH;
	blk_mq_run_hw_queue(ihq->hctx, true);

	return HRTIMER_NORESTART;
}

static void i10_hctx_queue_reset(struct i10_hctx_queue *ihq)
{
	ihq->qlen_nr = 0;
	ihq->qlen_bytes = 0;
	ihq->state = I10_STATE_BATCH;
}

static int i10_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct i10_hctx_queue *ihq;

	ihq = kzalloc_node(sizeof(*ihq), GFP_KERNEL, hctx->numa_node);
	if (!ihq)
		return -ENOMEM;

	spin_lock_init(&ihq->lock);
	INIT_LIST_HEAD(&ihq->rq_list);

	ihq->hctx = hctx;
	ihq->batch_nr = 0;
	ihq->batch_bytes = 0;
	ihq->batch_timeout = 0;

	hrtimer_init(&ihq->dispatch_timer,
		CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	ihq->dispatch_timer.function = &i10_hctx_timeout_handler;

	i10_hctx_queue_reset(ihq);

	hctx->sched_data = ihq;

	return 0;
}

static void i10_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct i10_hctx_queue *ihq = hctx->sched_data;

	hrtimer_cancel(&ihq->dispatch_timer);
	kfree(hctx->sched_data);
}

static bool i10_hctx_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio,
		unsigned int nr_segs)
{
	struct i10_hctx_queue *ihq = hctx->sched_data;
	struct list_head *rq_list = &ihq->rq_list;
	bool merged;

	spin_lock(&ihq->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, rq_list, bio, nr_segs);
	spin_unlock(&ihq->lock);

	if (merged && bio_data_dir(bio) == WRITE)
		ihq->qlen_bytes += bio->bi_iter.bi_size;

	return merged;
}

/*
 * The batch size can be adjusted dynamically on a per-hctx basis.
 * Use per-hctx variables in that case.
 */
static inline unsigned int i10_hctx_batch_nr(struct blk_mq_hw_ctx *hctx)
{
	struct i10_queue_data *iqd = hctx->queue->elevator->elevator_data;
	struct i10_hctx_queue *ihq = hctx->sched_data;

	return ihq->batch_nr ?
		ihq->batch_nr : iqd->def_batch_nr;
}

static inline unsigned int i10_hctx_batch_bytes(struct blk_mq_hw_ctx *hctx)
{
	struct i10_queue_data *iqd = hctx->queue->elevator->elevator_data;
	struct i10_hctx_queue *ihq = hctx->sched_data;

	return ihq->batch_bytes ?
		ihq->batch_bytes : iqd->def_batch_bytes;
}

static inline unsigned int i10_hctx_batch_timeout(struct blk_mq_hw_ctx *hctx)
{
	struct i10_queue_data *iqd = hctx->queue->elevator->elevator_data;
	struct i10_hctx_queue *ihq = hctx->sched_data;

	return ihq->batch_timeout ?
		ihq->batch_timeout : iqd->def_batch_timeout;
}

static void i10_hctx_insert_update(struct i10_hctx_queue *ihq,
				struct request *rq)
{
	if (rq_data_dir(rq) == WRITE)
		ihq->qlen_bytes += blk_rq_bytes(rq);
	ihq->qlen_nr++;
}

static void i10_hctx_insert_requests(struct blk_mq_hw_ctx *hctx,
				struct list_head *rq_list, bool at_head)
{
	struct i10_hctx_queue *ihq = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rq_list, queuelist) {
		struct list_head *head = &ihq->rq_list;

		spin_lock(&ihq->lock);
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		i10_hctx_insert_update(ihq, rq);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&ihq->lock);
	}

	/* Start a new timer */
	if (ihq->state == I10_STATE_BATCH &&
	   !hrtimer_active(&ihq->dispatch_timer))
		hrtimer_start(&ihq->dispatch_timer,
			ns_to_ktime(i10_hctx_batch_timeout(hctx)
				* NSEC_PER_USEC),
			HRTIMER_MODE_REL);
}

static struct request *i10_hctx_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct i10_hctx_queue *ihq = hctx->sched_data;
	struct request *rq;

	spin_lock(&ihq->lock);
	rq = list_first_entry_or_null(&ihq->rq_list,
				struct request, queuelist);
	if (rq)
		list_del_init(&rq->queuelist);
	else
		i10_hctx_queue_reset(ihq);
	spin_unlock(&ihq->lock);

	return rq;
}

static inline bool i10_hctx_dispatch_now(struct blk_mq_hw_ctx *hctx)
{
	struct i10_hctx_queue *ihq = hctx->sched_data;

	return (ihq->qlen_nr >= i10_hctx_batch_nr(hctx)) ||
		(ihq->qlen_bytes >= i10_hctx_batch_bytes(hctx));
}

/*
 * Return true if we are in the dispatching state.
 */
static bool i10_hctx_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct i10_hctx_queue *ihq = hctx->sched_data;

	if (ihq->state == I10_STATE_BATCH) {
		if (i10_hctx_dispatch_now(hctx)) {
			ihq->state = I10_STATE_DISPATCH;
			if (hrtimer_active(&ihq->dispatch_timer))
				hrtimer_cancel(&ihq->dispatch_timer);
		}
	}

	return (ihq->state == I10_STATE_DISPATCH);
}

#define I10_DEF_BATCH_SHOW_STORE(name)					\
static ssize_t i10_def_batch_##name##_show(struct elevator_queue *e,	\
				char *page)				\
{									\
	struct i10_queue_data *iqd = e->elevator_data;			\
									\
	return sprintf(page, "%u\n", iqd->def_batch_##name);		\
}									\
									\
static ssize_t i10_def_batch_##name##_store(struct elevator_queue *e,	\
			const char *page, size_t count)			\
{									\
	struct i10_queue_data *iqd = e->elevator_data;			\
	unsigned long long value;					\
	int ret;							\
									\
	ret = kstrtoull(page, 10, &value);				\
	if (ret)							\
		return ret;						\
									\
	iqd->def_batch_##name = value;					\
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
	struct i10_hctx_queue *ihq = hctx->sched_data;			\
									\
	seq_printf(m, "%u\n", ihq->batch_##name);			\
	return 0;							\
}									\
									\
static int i10_hctx_qlen_##name##_show(void *data, struct seq_file *m)	\
{									\
	struct blk_mq_hw_ctx *hctx = data;				\
	struct i10_hctx_queue *ihq = hctx->sched_data;			\
									\
	seq_printf(m, "%u\n", ihq->qlen_##name);			\
	return 0;							\
}
I10_DEBUGFS_SHOW(nr);
I10_DEBUGFS_SHOW(bytes);
#undef I10_DEBUGFS_SHOW

static int i10_hctx_state_show(void *data, struct seq_file *m)
{
	struct blk_mq_hw_ctx *hctx = data;
	struct i10_hctx_queue *ihq = hctx->sched_data;

	seq_printf(m, "%d\n", ihq->state);
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

MODULE_AUTHOR("Jaehyun Hwang, Qizhe Cai, Midhul Vuppalapati, Rachit Agarwal");
MODULE_LICENSE("GPLv2");
MODULE_DESCRIPTION("i10 I/O scheduler");
