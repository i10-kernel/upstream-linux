==========================
i10 I/O scheduler overview
==========================

I/O batching is beneficial for optimizing IOPS and throughput for various
applications. For instance, several kernel block drivers would
benefit from batching, including mmc [1] and tcp-based storage drivers like
nvme-tcp [2,3]. While we have support for batching dispatch [4], we need an
I/O scheduler to efficiently enable batching. Such a scheduler is particularly
interesting for disaggregated storage, where the access latency of remote
disaggregated storage may be higher than local storage access; thus, batching
can significantly help in amortizing the remote access latency while increasing
the throughput.

This patch introduces the i10 I/O scheduler, which performs batching per hctx in terms
of #requests, #bytes, and timeouts (at microseconds granularity). i10 starts
dispatching only when #requests or #bytes is larger than a default threshold or when
a timer expires. After that, batching dispatch [3] would happen, allowing batching
at device drivers along with "bd->last" and ".commit_rqs".

The i10 I/O scheduler builds upon recent work on [6]. We have tested the i10 I/O
scheduler with nvme-tcp optimizaitons [2,3] and batching dispatch [4], varying number
of cores, varying read/write ratios, and varying request sizes, and with NVMe SSD and
RAM block device. For NVMe SSDs, the i10 I/O scheduler achieves ~60% improvements in
terms of IOPS per core over "noop" I/O scheduler. These results are available at [5],
and many additional results are presented in [6].

While other schedulers may also batch I/O (e.g., mq-deadline), the optimization target
in the i10 I/O scheduler is throughput maximization. Hence there is no latency target
nor a need for a global tracking context, so a new scheduler is needed rather than
to build this functionality to an existing scheduler.

We currently use fixed default values as batching thresholds (e.g., 16 for #requests,
64KB for #bytes, and 50us for timeout). These default values are based on sensitivity
tests in [6]. For our future work, we plan to support adaptive batching according to
system load and to extend the scheduler to support isolation in multi-tenant deployments
(to simultaneously achieve low tail latency for latency-sensitive applications and high
throughput for throughput-bound applications).

References
[1] https://lore.kernel.org/linux-block/cover.1587888520.git.baolin.wang7@gmail.com/T/#mc48a8fb6069843827458f5fea722e1179d32af2a
[2] https://git.infradead.org/nvme.git/commit/122e5b9f3d370ae11e1502d14ff5c7ea9b144a76
[3] https://git.infradead.org/nvme.git/commit/86f0348ace1510d7ac25124b096fb88a6ab45270
[4] https://lore.kernel.org/linux-block/20200630102501.2238972-1-ming.lei@redhat.com/
[5] https://github.com/i10-kernel/upstream-linux/blob/master/i10-evaluation.pdf
[6] https://www.usenix.org/conference/nsdi20/presentation/hwang

==========================
i10 I/O scheduler tunables
==========================

The three tunables for the i10 scheduler are the number of requests for
reads/writes, the number of bytes for writes, and a timeout value.
i10 will use these values for batching requests.

batch_nr
--------
Number of requests for batching read/write requests
Default: 16

batch_bytes
-----------
Number of bytes for batching write requests
Default: 65536 (bytes)

batch_timeout
-------------
Timeout value for batching (in microseconds)
Default: 50 (us)
