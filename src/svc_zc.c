/*
 * TCP SO_ZEROCOPY / MSG_ZEROCOPY support for ntirpc.
 *
 * Kernel docs: https://docs.kernel.org/networking/msg_zerocopy.html
 * Completions: recvmsg(MSG_ERRQUEUE) after EPOLLERR / opportunistic drain.
 *
 * Tracking must be installed *before* sendmsg returns: on localhost the
 * ERRQUEUE notification can be drained by another thread in the gap between
 * a successful MSG_ZEROCOPY sendmsg and a post-send note_send, permanently
 * leaking zc_pending_bytes until max_pending forces copy fallback.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/errqueue.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <rpc/types.h>
#include <misc/portable.h>
#include <rpc/rpc.h>
#include <rpc/svc.h>
#include <rpc/xdr_ioq.h>

#include "rpc_dplx_internal.h"
#include "svc_internal.h"
#include "svc_ioq.h"
#include "svc_zc.h"

#ifndef HAVE_SO_ZEROCOPY

void svc_zc_try_enable(SVCXPRT *xprt, int fd)
{
	(void)xprt;
	(void)fd;
}

bool svc_zc_eligible(SVCXPRT *xprt, struct xdr_ioq *xioq, size_t send_bytes,
		     bool new_frag_hdr)
{
	(void)xprt;
	(void)xioq;
	(void)send_bytes;
	(void)new_frag_hdr;
	return false;
}

ssize_t svc_zc_sendmsg(SVCXPRT *xprt, struct xdr_ioq *xioq, struct msghdr *msg,
		       int flags_base, bool new_frag_hdr, bool *used_zc,
		       int *err_out)
{
	ssize_t result;

	(void)xioq;
	(void)new_frag_hdr;
	*used_zc = false;
	errno = 0;
	result = sendmsg(xprt->xp_fd, msg, flags_base);
	*err_out = errno;
	return result;
}

bool svc_zc_pending(const struct xdr_ioq *xioq)
{
	(void)xioq;
	return false;
}

void svc_zc_park(SVCXPRT *xprt, struct xdr_ioq *xioq)
{
	(void)xprt;
	(void)xioq;
}

void svc_zc_drain(SVCXPRT *xprt, bool have_writeq_lock)
{
	(void)xprt;
	(void)have_writeq_lock;
}

void svc_zc_clear(struct rpc_dplx_rec *rec)
{
	(void)rec;
}

#else /* HAVE_SO_ZEROCOPY */

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif

/** Cap drain loop so a wedged socket cannot spin forever. */
#define SVC_ZC_DRAIN_MAX 4096

static inline bool zc_id_in_range(uint32_t id, uint32_t lo, uint32_t hi)
{
	/* Handle uint32 wrap of the kernel counter. */
	if (lo <= hi)
		return id >= lo && id <= hi;
	return id >= lo || id <= hi;
}

static inline uint32_t zc_id_span(uint32_t lo, uint32_t hi)
{
	return (hi - lo) + 1;
}

void svc_zc_try_enable(SVCXPRT *xprt, int fd)
{
	int on = 1;

	if (!__svc_params->socket_zerocopy) {
		__warnx(TIRPC_DEBUG_FLAG_EVENT,
			"%s: fd %d skipped (Enable_Socket_Zerocopy=false)",
			__func__, fd);
		return;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &on, sizeof(on)) == 0) {
		atomic_set_uint16_t_bits(&xprt->xp_flags,
					SVC_XPRT_FLAG_SO_ZEROCOPY);
		__warnx(TIRPC_DEBUG_FLAG_EVENT,
			"%s: fd %d SO_ZEROCOPY enabled (threshold %u max_pending %u)",
			__func__, fd,
			__svc_params->socket_zerocopy_threshold,
			__svc_params->socket_zerocopy_max_pending);
	} else {
		__warnx(TIRPC_DEBUG_FLAG_ERROR,
			"%s: fd %d SO_ZEROCOPY failed (%d)",
			__func__, fd, errno);
	}
}

bool svc_zc_eligible(SVCXPRT *xprt, struct xdr_ioq *xioq, size_t send_bytes,
		     bool new_frag_hdr)
{
	struct rpc_dplx_rec *rec = REC_XPRT(xprt);
	struct poolq_entry *have;
	bool has_refer = false;
	u_int threshold;

	if (!__svc_params->socket_zerocopy)
		return false;
	if (!(xprt->xp_flags & SVC_XPRT_FLAG_SO_ZEROCOPY))
		return false;

	threshold = __svc_params->socket_zerocopy_threshold;
	/* Prefer gifted/REFER payloads (e.g. FSAL_CEPH ZC READ); require
	 * 2x threshold for ordinary copied buffers. */
	TAILQ_FOREACH(have, &xioq->ioq_uv.uvqh.qh, q) {
		struct xdr_ioq_uv *uv = IOQ_(have);

		if (uv->u.uio_flags & UIO_FLAG_REFER) {
			has_refer = true;
			break;
		}
	}
	if (!has_refer)
		threshold *= 2;

	if (send_bytes < threshold)
		return false;
	/*
	 * One durable frag_hdr_be per ioq. A new record-mark with MSG_ZEROCOPY
	 * would overwrite it while the kernel may still pin the first. Payload
	 * continuations after a partial ZC send (no new header) are OK.
	 */
	if (new_frag_hdr && xioq->zc_id_lo != UINT32_MAX)
		return false;
	if (rec->zc_pending_bytes + send_bytes >
	    __svc_params->socket_zerocopy_max_pending)
		return false;
	return true;
}

/*
 * Orphan completions: ID arrived on ERRQUEUE with no zcq match. Rare once
 * tracking is installed before sendmsg; kept as a safety net.
 * Caller holds writeq.qmutex.
 */
static void
svc_zc_orphan_push(struct rpc_dplx_rec *rec, uint32_t id)
{
	unsigned i;

	for (i = 0; i < rec->zc_orphan_n; i++) {
		if (rec->zc_orphan[i] == id)
			return;
	}
	if (rec->zc_orphan_n >= RPC_DPLX_ZC_ORPHAN_MAX) {
		__warnx(TIRPC_DEBUG_FLAG_ERROR,
			"%s: fd %d orphan ring full, drop zc id %u",
			__func__, rec->xprt.xp_fd, id);
		return;
	}
	rec->zc_orphan[rec->zc_orphan_n++] = id;
	__warnx(TIRPC_DEBUG_FLAG_SVC_VC,
		"%s: %p fd %d orphan zc id %u (n=%u)",
		__func__, &rec->xprt, rec->xprt.xp_fd, id, rec->zc_orphan_n);
}

/* Apply any orphaned IDs that fall in this ioq's range. Caller holds lock. */
static void
svc_zc_orphan_apply(struct rpc_dplx_rec *rec, struct xdr_ioq *xioq)
{
	unsigned i = 0;

	if (xioq->zc_id_lo == UINT32_MAX || rec->zc_orphan_n == 0)
		return;

	while (i < rec->zc_orphan_n) {
		uint32_t id = rec->zc_orphan[i];

		if (zc_id_in_range(id, xioq->zc_id_lo, xioq->zc_id_hi)) {
			xioq->zc_ids_done++;
			__sync_fetch_and_add(
				&__svc_params->zc_stats.completions, 1);
			rec->zc_orphan[i] = rec->zc_orphan[--rec->zc_orphan_n];
			continue;
		}
		i++;
	}
}

/* Install predicted kernel send ID on zcq before sendmsg. Caller holds lock. */
static void
svc_zc_prepare_locked(struct rpc_dplx_rec *rec, struct xdr_ioq *xioq,
		      size_t send_bytes, uint32_t *id_out)
{
	uint32_t id = rec->zc_next_id++;

	if (xioq->zc_id_lo == UINT32_MAX) {
		xioq->zc_id_lo = id;
		xioq->zc_id_hi = id;
		xioq->zc_ids_done = 0;
	} else {
		xioq->zc_id_hi = id;
	}
	xioq->zc_bytes += (uint32_t)send_bytes;
	rec->zc_pending_bytes += (uint32_t)send_bytes;
	if (!xioq->zc_tracked) {
		TAILQ_INSERT_TAIL(&rec->zcq.qh, &xioq->zc_s, q);
		rec->zcq.qcount++;
		xioq->zc_tracked = true;
	}
	*id_out = id;
}

/* Undo prepare after failed sendmsg (kernel did not consume an ID). */
static void
svc_zc_unprepare_locked(struct rpc_dplx_rec *rec, struct xdr_ioq *xioq,
			uint32_t id, size_t send_bytes)
{
	rec->zc_next_id = id; /* was id+1 after prepare */
	if (xioq->zc_bytes >= (uint32_t)send_bytes)
		xioq->zc_bytes -= (uint32_t)send_bytes;
	else
		xioq->zc_bytes = 0;
	if (rec->zc_pending_bytes >= (uint32_t)send_bytes)
		rec->zc_pending_bytes -= (uint32_t)send_bytes;
	else
		rec->zc_pending_bytes = 0;

	if (xioq->zc_id_lo == id && xioq->zc_id_hi == id) {
		xioq->zc_id_lo = UINT32_MAX;
		xioq->zc_id_hi = UINT32_MAX;
		xioq->zc_ids_done = 0;
		if (xioq->zc_tracked) {
			TAILQ_REMOVE(&rec->zcq.qh, &xioq->zc_s, q);
			rec->zcq.qcount--;
			xioq->zc_tracked = false;
		}
	} else {
		xioq->zc_id_hi = id - 1;
	}
}

ssize_t
svc_zc_sendmsg(SVCXPRT *xprt, struct xdr_ioq *xioq, struct msghdr *msg,
	       int flags_base, bool new_frag_hdr, bool *used_zc, int *err_out)
{
	struct rpc_dplx_rec *rec = REC_XPRT(xprt);
	size_t send_bytes = 0;
	ssize_t result;
	uint32_t id = 0;
	u_int si;
	bool want_zc;

	*used_zc = false;
	for (si = 0; si < (u_int)msg->msg_iovlen; si++)
		send_bytes += msg->msg_iov[si].iov_len;

	want_zc = svc_zc_eligible(xprt, xioq, send_bytes, new_frag_hdr);
	if (!want_zc) {
		errno = 0;
		result = sendmsg(xprt->xp_fd, msg, flags_base);
		*err_out = errno;
		return result;
	}

	/*
	 * Install the predicted kernel send ID on zcq *before* sendmsg, then
	 * drop writeq.qmutex for the syscall. Holding the lock across sendmsg
	 * stalls ERRQUEUE drains (EPOLLERR) and can hang the socket under load;
	 * prepare-before-send is enough so a racing drain still matches.
	 */
	mutex_lock(&rec->writeq.qmutex);
	if (rec->zc_pending_bytes + send_bytes >
	    __svc_params->socket_zerocopy_max_pending) {
		mutex_unlock(&rec->writeq.qmutex);
		errno = 0;
		result = sendmsg(xprt->xp_fd, msg, flags_base);
		*err_out = errno;
		return result;
	}
	svc_zc_prepare_locked(rec, xioq, send_bytes, &id);
	mutex_unlock(&rec->writeq.qmutex);

	errno = 0;
	result = sendmsg(xprt->xp_fd, msg, flags_base | MSG_ZEROCOPY);
	*err_out = errno;

	if (unlikely(result < 0)) {
		mutex_lock(&rec->writeq.qmutex);
		svc_zc_unprepare_locked(rec, xioq, id, send_bytes);
		mutex_unlock(&rec->writeq.qmutex);

		if (*err_out == ENOBUFS || *err_out == EOPNOTSUPP) {
			__sync_fetch_and_add(
				&__svc_params->zc_stats.enobufs, 1);
			__sync_fetch_and_add(
				&__svc_params->zc_stats.fallback, 1);
			errno = 0;
			result = sendmsg(xprt->xp_fd, msg, flags_base);
			*err_out = errno;
		}
		return result;
	}

	mutex_lock(&rec->writeq.qmutex);
	/* Partial send: still one kernel ID; shrink pending to bytes sent. */
	if ((size_t)result < send_bytes) {
		uint32_t dropped = (uint32_t)(send_bytes - (size_t)result);

		if (xioq->zc_bytes >= dropped)
			xioq->zc_bytes -= dropped;
		else
			xioq->zc_bytes = 0;
		if (rec->zc_pending_bytes >= dropped)
			rec->zc_pending_bytes -= dropped;
		else
			rec->zc_pending_bytes = 0;
	}
	/* Orphans that raced between prepare and this confirm. */
	svc_zc_orphan_apply(rec, xioq);
	mutex_unlock(&rec->writeq.qmutex);

	*used_zc = true;
	__sync_fetch_and_add(&__svc_params->zc_stats.sends, 1);
	return result;
}

bool svc_zc_pending(const struct xdr_ioq *xioq)
{
	return xioq->zc_id_lo != UINT32_MAX &&
	       xioq->zc_ids_done < zc_id_span(xioq->zc_id_lo, xioq->zc_id_hi);
}

/*
 * Unlink a fully-completed parked ioq from zcq. Caller holds writeq.qmutex.
 * Returns xioq for svc_zc_finish_one() *after* unlock — never XDR_DESTROY
 * under writeq (FSAL_CEPH ceph_bufferlist_put can block and deadlock with
 * writers that hold CEPH locks then wait on writeq).
 */
static struct xdr_ioq *
svc_zc_take_one(struct rpc_dplx_rec *rec, struct xdr_ioq *xioq)
{
	SVCXPRT *xprt = &rec->xprt;

	if (!xioq->zc_awaiting)
		return NULL;
	if (xioq->zc_ids_done < zc_id_span(xioq->zc_id_lo, xioq->zc_id_hi))
		return NULL;

	TAILQ_REMOVE(&rec->zcq.qh, &xioq->zc_s, q);
	rec->zcq.qcount--;
	if (rec->zc_pending_bytes >= xioq->zc_bytes)
		rec->zc_pending_bytes -= xioq->zc_bytes;
	else
		rec->zc_pending_bytes = 0;
	xioq->zc_tracked = false;
	xioq->zc_awaiting = false;

	__warnx(TIRPC_DEBUG_FLAG_SVC_VC,
		"%s: %p fd %d complete ioq zc ids %u..%u",
		__func__, xprt, xprt->xp_fd, xioq->zc_id_lo, xioq->zc_id_hi);
	return xioq;
}

static void
svc_zc_finish_one(SVCXPRT *xprt, struct xdr_ioq *xioq, int status)
{
	svc_ioq_reply_done(xioq, status);
	SVC_RELEASE(xprt, SVC_RELEASE_FLAG_NONE);
	XDR_DESTROY(xioq->xdrs);
}

/* doneq entries are linked via zc_s (already removed from zcq). */
static void
svc_zc_finish_q(SVCXPRT *xprt, struct poolq_head *doneq, int status)
{
	struct poolq_entry *have;
	struct xdr_ioq *xioq;

	while ((have = TAILQ_FIRST(&doneq->qh)) != NULL) {
		TAILQ_REMOVE(&doneq->qh, have, q);
		doneq->qcount--;
		xioq = _ZC_IOQ(have);
		svc_zc_finish_one(xprt, xioq, status);
	}
}

static void
svc_zc_collect_ready(struct rpc_dplx_rec *rec, struct poolq_head *doneq)
{
	struct poolq_entry *have, *next;
	struct xdr_ioq *xioq, *taken;

	have = TAILQ_FIRST(&rec->zcq.qh);
	while (have != NULL) {
		next = TAILQ_NEXT(have, q);
		xioq = _ZC_IOQ(have);
		taken = svc_zc_take_one(rec, xioq);
		if (taken != NULL) {
			TAILQ_INSERT_TAIL(&doneq->qh, &taken->zc_s, q);
			doneq->qcount++;
		}
		have = next;
	}
}

void svc_zc_park(SVCXPRT *xprt, struct xdr_ioq *xioq)
{
	struct rpc_dplx_rec *rec = REC_XPRT(xprt);
	struct xdr_ioq *done = NULL;

	mutex_lock(&rec->writeq.qmutex);
	xioq->zc_awaiting = true;
	if (!xioq->zc_tracked) {
		/* prepare should have tracked; keep safe if not. */
		TAILQ_INSERT_TAIL(&rec->zcq.qh, &xioq->zc_s, q);
		rec->zcq.qcount++;
		xioq->zc_tracked = true;
	}
	svc_zc_orphan_apply(rec, xioq);

	__warnx(TIRPC_DEBUG_FLAG_SVC_VC,
		"%s: %p fd %d park ioq zc ids %u..%u bytes %u done %u",
		__func__, xprt, xprt->xp_fd, xioq->zc_id_lo, xioq->zc_id_hi,
		xioq->zc_bytes, xioq->zc_ids_done);

	done = svc_zc_take_one(rec, xioq);
	mutex_unlock(&rec->writeq.qmutex);

	if (done != NULL)
		svc_zc_finish_one(xprt, done, 0);
	else
		svc_zc_drain(xprt, false);
}

static void
svc_zc_apply_range(struct rpc_dplx_rec *rec, uint32_t lo, uint32_t hi,
		   bool copied, struct poolq_head *doneq)
{
	struct poolq_entry *have, *next;
	struct xdr_ioq *xioq;
	uint32_t id;

	if (copied)
		__sync_fetch_and_add(&__svc_params->zc_stats.copied, 1);

	/* Inclusive range; handle wrap. */
	id = lo;
	for (;;) {
		bool matched = false;

		have = TAILQ_FIRST(&rec->zcq.qh);
		while (have != NULL) {
			next = TAILQ_NEXT(have, q);
			xioq = _ZC_IOQ(have);
			if (zc_id_in_range(id, xioq->zc_id_lo,
					   xioq->zc_id_hi)) {
				xioq->zc_ids_done++;
				matched = true;
			}
			have = next;
		}
		if (matched)
			__sync_fetch_and_add(
				&__svc_params->zc_stats.completions, 1);
		else
			svc_zc_orphan_push(rec, id);
		if (id == hi)
			break;
		id++;
	}

	svc_zc_collect_ready(rec, doneq);
}

/*
 * Parse one ERRQUEUE message under the writeq lock. Returns true if a ZC
 * notification was applied. Completed ioqs are queued on @doneq for finish
 * after unlock.
 */
static bool
svc_zc_recv_and_apply(SVCXPRT *xprt, struct poolq_head *doneq)
{
	char control[128];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *serr;
	struct rpc_dplx_rec *rec = REC_XPRT(xprt);
	int ret;
	bool copied;

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(xprt->xp_fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (ret < 0)
		return false;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (!((cmsg->cmsg_level == SOL_IP &&
		       cmsg->cmsg_type == IP_RECVERR) ||
		      (cmsg->cmsg_level == SOL_IPV6 &&
		       cmsg->cmsg_type == IPV6_RECVERR)))
			continue;

		serr = (struct sock_extended_err *)CMSG_DATA(cmsg);
		if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY)
			continue;
		if (serr->ee_errno != 0)
			continue;

		copied = (serr->ee_code & SO_EE_CODE_ZEROCOPY_COPIED) != 0;
		svc_zc_apply_range(rec, serr->ee_info, serr->ee_data, copied,
				   doneq);
		return true;
	}
	return false;
}

void svc_zc_drain(SVCXPRT *xprt, bool have_writeq_lock)
{
	struct rpc_dplx_rec *rec = REC_XPRT(xprt);
	struct poolq_head doneq;
	int n = 0;

	if (!(xprt->xp_flags & SVC_XPRT_FLAG_SO_ZEROCOPY))
		return;

	TAILQ_INIT(&doneq.qh);
	doneq.qcount = 0;

	if (!have_writeq_lock)
		mutex_lock(&rec->writeq.qmutex);

	/* Drain until empty; EPOLLONESHOT will not re-signal leftover ERRQUEUE
	 * until a new completion arrives, so a low batch cap leaks pending. */
	while (svc_zc_recv_and_apply(xprt, &doneq) && n < SVC_ZC_DRAIN_MAX)
		n++;

	/*
	 * Drop writeq before XDR_DESTROY. If the caller held the lock, release
	 * it for the finish window and reacquire afterward.
	 */
	mutex_unlock(&rec->writeq.qmutex);
	svc_zc_finish_q(xprt, &doneq, 0);
	if (have_writeq_lock)
		mutex_lock(&rec->writeq.qmutex);
	else {
		/*
		 * Completions free skbuff/optmem; a writeq head blocked on
		 * EWOULDBLOCK may not see EPOLLOUT (edge-triggered). Kick it.
		 */
		svc_ioq_write_resume(xprt);
	}
}

void svc_zc_clear(struct rpc_dplx_rec *rec)
{
	struct poolq_entry *have;
	struct xdr_ioq *xioq;
	struct poolq_head doneq;

	TAILQ_INIT(&doneq.qh);
	doneq.qcount = 0;

	mutex_lock(&rec->writeq.qmutex);
	have = TAILQ_FIRST(&rec->zcq.qh);
	while (have != NULL) {
		xioq = _ZC_IOQ(have);
		TAILQ_REMOVE(&rec->zcq.qh, have, q);
		rec->zcq.qcount--;
		xioq->zc_tracked = false;
		if (xioq->zc_awaiting) {
			xioq->zc_awaiting = false;
			TAILQ_INSERT_TAIL(&doneq.qh, &xioq->zc_s, q);
			doneq.qcount++;
		}
		/*
		 * !zc_awaiting: still flushing; write path owns the ref and
		 * buffers. Leave them alone so sendmsg cannot UAF.
		 */
		have = TAILQ_FIRST(&rec->zcq.qh);
	}
	rec->zc_pending_bytes = 0;
	rec->zc_orphan_n = 0;
	mutex_unlock(&rec->writeq.qmutex);

	svc_zc_finish_q(&rec->xprt, &doneq, ECONNABORTED);
}

#endif /* HAVE_SO_ZEROCOPY */
