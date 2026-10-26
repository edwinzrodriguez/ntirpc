/*
 * TCP SO_ZEROCOPY / MSG_ZEROCOPY helpers for ntirpc.
 *
 * Completions arrive on the socket error queue (MSG_ERRQUEUE), signaled as
 * EPOLLERR — not as ordinary EPOLLIN/EPOLLOUT data events.
 */
#ifndef SVC_ZC_H
#define SVC_ZC_H

#include <rpc/svc.h>
#include <rpc/xdr_ioq.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

struct rpc_dplx_rec;

/** Try setsockopt(SO_ZEROCOPY); set SVC_XPRT_FLAG_SO_ZEROCOPY on success. */
void svc_zc_try_enable(SVCXPRT *xprt, int fd);

/**
 * True if this sendmsg size should use MSG_ZEROCOPY.
 * @new_frag_hdr  true when this send includes a fresh RPC record-mark that
 *                would overwrite xioq->frag_hdr_be (illegal while a prior ZC
 *                on this ioq still pins that storage).
 */
bool svc_zc_eligible(SVCXPRT *xprt, struct xdr_ioq *xioq, size_t send_bytes,
		     bool new_frag_hdr);

/**
 * sendmsg with optional MSG_ZEROCOPY. When ZC is used, the predicted send ID
 * is installed on zcq under writeq.qmutex *before* the syscall (mutex is not
 * held across sendmsg — that stalled ERRQUEUE drains and hung under load).
 *
 * @flags_base    e.g. MSG_DONTWAIT (MSG_ZEROCOPY may be OR'd in)
 * @new_frag_hdr  see svc_zc_eligible()
 * @used_zc       set true if this call consumed a kernel ZC send id
 * @err_out       errno after the final sendmsg attempt
 */
ssize_t svc_zc_sendmsg(SVCXPRT *xprt, struct xdr_ioq *xioq, struct msghdr *msg,
		       int flags_base, bool new_frag_hdr, bool *used_zc,
		       int *err_out);

/** True if @xioq has outstanding ZC IDs awaiting ERRQUEUE completion. */
bool svc_zc_pending(const struct xdr_ioq *xioq);

/**
 * Park a fully-flushed reply on the xprt zcq until completions arrive.
 * Caller has already removed it from writeq; holds an xprt ref for the entry.
 */
void svc_zc_park(SVCXPRT *xprt, struct xdr_ioq *xioq);

/**
 * Drain MSG_ERRQUEUE on xp_fd; release completed zcq entries.
 * Safe to call with or without writeq.qmutex held (uses @have_writeq_lock).
 *
 * @resume_writes  If true, kick svc_ioq_write_resume after drain (ET EPOLLOUT
 *                 may not re-edge when completions free skbuffs). Pass false
 *                 when the caller is about to run the SEND task for this
 *                 event — otherwise resume can finish/free xioq_send while
 *                 epoll still holds that ioq for ioq_wpe.fun.
 */
void svc_zc_drain(SVCXPRT *xprt, bool have_writeq_lock, bool resume_writes);

/** Destroy all parked ZC replies (xprt teardown). */
void svc_zc_clear(struct rpc_dplx_rec *rec);

#endif /* SVC_ZC_H */
