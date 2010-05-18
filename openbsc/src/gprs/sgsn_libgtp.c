/* GPRS SGSN integration with libgtp of OpenGGSN */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocore/talloc.h>
#include <osmocore/select.h>
#include <osmocore/rate_ctr.h>
#include <openbsc/gsm_04_08_gprs.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>

#include <gtp.h>
#include <pdp.h>

const struct value_string gtp_cause_strs[] = {
	{ GTPCAUSE_REQ_IMSI, "Request IMSI" },
	{ GTPCAUSE_REQ_IMEI, "Request IMEI" },
	{ GTPCAUSE_REQ_IMSI_IMEI, "Request IMSI and IMEI" },
	{ GTPCAUSE_NO_ID_NEEDED, "No identity needed" },
	{ GTPCAUSE_MS_REFUSES_X, "MS refuses" },
	{ GTPCAUSE_MS_NOT_RESP_X, "MS is not GPRS responding" },
	{ GTPCAUSE_ACC_REQ, "Request accepted" },
	{ GTPCAUSE_NON_EXIST, "Non-existent" },
	{ GTPCAUSE_INVALID_MESSAGE, "Invalid message format" },
	{ GTPCAUSE_IMSI_NOT_KNOWN, "IMSI not known" },
	{ GTPCAUSE_MS_DETACHED, "MS is GPRS detached" },
	{ GTPCAUSE_MS_NOT_RESP, "MS is not GPRS responding" },
	{ GTPCAUSE_MS_REFUSES, "MS refuses" },
	{ GTPCAUSE_NO_RESOURCES, "No resources available" },
	{ GTPCAUSE_NOT_SUPPORTED, "Service not supported" },
	{ GTPCAUSE_MAN_IE_INCORRECT, "Mandatory IE incorrect" },
	{ GTPCAUSE_MAN_IE_MISSING, "Mandatory IE missing" },
	{ GTPCAUSE_OPT_IE_INCORRECT, "Optional IE incorrect" },
	{ GTPCAUSE_SYS_FAIL, "System failure" },
	{ GTPCAUSE_ROAMING_REST, "Roaming restrictions" },
	{ GTPCAUSE_PTIMSI_MISMATCH, "P-TMSI Signature mismatch" },
	{ GTPCAUSE_CONN_SUSP, "GPRS connection suspended" },
	{ GTPCAUSE_AUTH_FAIL, "Authentication failure" },
	{ GTPCAUSE_USER_AUTH_FAIL, "User authentication failed" },
	{ GTPCAUSE_CONTEXT_NOT_FOUND, "Context not found" },
	{ GTPCAUSE_ADDR_OCCUPIED, "All dynamic PDP addresses occupied" },
	{ GTPCAUSE_NO_MEMORY, "No memory is available" },
	{ GTPCAUSE_RELOC_FAIL, "Relocation failure" },
	{ GTPCAUSE_UNKNOWN_MAN_EXTHEADER, "Unknown mandatory ext. header" },
	{ GTPCAUSE_SEM_ERR_TFT, "Semantic error in TFT operation" },
	{ GTPCAUSE_SYN_ERR_TFT, "Syntactic error in TFT operation" },
	{ GTPCAUSE_SEM_ERR_FILTER, "Semantic errors in packet filter" },
	{ GTPCAUSE_SYN_ERR_FILTER, "Syntactic errors in packet filter" },
	{ GTPCAUSE_MISSING_APN, "Missing or unknown APN" },
	{ GTPCAUSE_UNKNOWN_PDP, "Unknown PDP address or PDP type" },
	{ 0, NULL }
};

/* generate a PDP context based on the IE's from the 04.08 message,
 * and send the GTP create pdp context request to the GGSN */
struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp)
{
	struct sgsn_pdp_ctx *pctx;
	struct pdp_t *pdp;
	uint64_t imsi_ui64;
	int rc;

	LOGP(DGPRS, LOGL_ERROR, "Create PDP Context\n");
	pctx = sgsn_pdp_ctx_alloc(mmctx, nsapi);
	if (!pctx) {
		LOGP(DGPRS, LOGL_ERROR, "Couldn't allocate PDP Ctx\n");
		return NULL;
	}

	rc = pdp_newpdp(&pdp, imsi_ui64, nsapi, NULL);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Out of libgtp PDP Contexts\n");
		return NULL;
	}
	pctx->lib = pdp;
	pctx->ggsn = ggsn;

	//pdp->peer =	/* sockaddr_in of GGSN (receive) */
	//pdp->ipif =	/* not used by library */
	pdp->version = ggsn->gtp_version;
	pdp->hisaddr0 =	ggsn->remote_addr;
	pdp->hisaddr1 = ggsn->remote_addr;
	//pdp->cch_pdp = 512;	/* Charging Flat Rate */

	/* MS provided APN, subscription not verified */
	pdp->selmode = 0x01;

	/* IMSI, TEID/TEIC, FLLU/FLLC, TID, NSAPI set in pdp_newpdp */

	/* FIXME: MSISDN in BCD format from mmctx */
	//pdp->msisdn.l/.v

	/* End User Address from GMM requested PDP address */
	pdp->eua.l = TLVP_LEN(tp, OSMO_IE_GSM_REQ_PDP_ADDR);
	if (pdp->eua.l > sizeof(pdp->eua.v))
		pdp->eua.l = sizeof(pdp->eua.v);
	memcpy(pdp->eua.v, TLVP_VAL(tp, OSMO_IE_GSM_REQ_PDP_ADDR),
		pdp->eua.l);
	/* Highest 4 bits of first byte need to be set to 1, otherwise
	 * the IE is identical with the 04.08 PDP Address IE */
	pdp->eua.v[0] |= 0xf0;

	/* APN name from GMM */
	pdp->apn_use.l = TLVP_LEN(tp, GSM48_IE_GSM_APN);
	if (pdp->apn_use.l > sizeof(pdp->apn_use.v))
		pdp->apn_use.l = sizeof(pdp->apn_use.v);
	memcpy(pdp->apn_use.v, TLVP_VAL(tp, GSM48_IE_GSM_APN),
		pdp->apn_use.l);

	/* Protocol Configuration Options from GMM */
	pdp->pco_req.l = TLVP_LEN(tp, GSM48_IE_GSM_PROTO_CONF_OPT);
	if (pdp->pco_req.l > sizeof(pdp->pco_req.v))
		pdp->pco_req.l = sizeof(pdp->pco_req.v);
	memcpy(pdp->pco_req.v, TLVP_VAL(tp, GSM48_IE_GSM_PROTO_CONF_OPT),
		pdp->pco_req.l);

	/* QoS options from GMM */
	pdp->qos_req.l = TLVP_LEN(tp, OSMO_IE_GSM_REQ_QOS);
	if (pdp->qos_req.l > sizeof(pdp->qos_req.v))
		pdp->qos_req.l = sizeof(pdp->qos_req.v);
	memcpy(pdp->qos_req.v, TLVP_VAL(tp, OSMO_IE_GSM_REQ_QOS),
		pdp->qos_req.l);

	/* SGSN address for control plane */
	pdp->gsnlc.l = sizeof(sgsn->cfg.gtp_listenaddr);
	memcpy(pdp->gsnlc.v, &sgsn->cfg.gtp_listenaddr,
		sizeof(sgsn->cfg.gtp_listenaddr));

	/* SGSN address for user plane */
	pdp->gsnlu.l = sizeof(sgsn->cfg.gtp_listenaddr);
	memcpy(pdp->gsnlu.v, &sgsn->cfg.gtp_listenaddr,
		sizeof(sgsn->cfg.gtp_listenaddr));

	/* change pdp state to 'requested' */
	pctx->state = PDP_STATE_CR_REQ;

	rc = gtp_create_context_req(ggsn->gsn, pdp, pctx);
	/* FIXME */

	return pctx;
}

int sgsn_delete_pdp_ctx(struct sgsn_pdp_ctx *pctx)
{
	LOGP(DGPRS, LOGL_ERROR, "Delete PDP Context\n");

	/* FIXME: decide if we need teardown or not ! */
	return gtp_delete_context_req(pctx->ggsn->gsn, pctx->lib, pctx, 1);
}

struct cause_map {
	uint8_t cause_in;
	uint8_t cause_out;
};

static uint8_t cause_map(const struct cause_map *map, uint8_t in, uint8_t deflt)
{
	const struct cause_map *m;

	for (m = map; m->cause_in && m->cause_out; m++) {
		if (m->cause_in == in)
			return m->cause_out;
	}
	return deflt;
}

/* how do we map from gtp cause to SM cause */
static const struct cause_map gtp2sm_cause_map[] = {
	{ GTPCAUSE_NO_RESOURCES, 	GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_NOT_SUPPORTED,	GSM_CAUSE_SERV_OPT_NOTSUPP },
	{ GTPCAUSE_MAN_IE_INCORRECT,	GSM_CAUSE_INV_MAND_INFO },
	{ GTPCAUSE_MAN_IE_MISSING,	GSM_CAUSE_INV_MAND_INFO },
	{ GTPCAUSE_OPT_IE_INCORRECT,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_SYS_FAIL,		GSM_CAUSE_NET_FAIL },
	{ GTPCAUSE_ROAMING_REST,	GSM_CAUSE_REQ_SERV_OPT_NOTSUB },
	{ GTPCAUSE_PTIMSI_MISMATCH,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_CONN_SUSP,		GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_AUTH_FAIL,		GSM_CAUSE_AUTH_FAILED },
	{ GTPCAUSE_USER_AUTH_FAIL,	GSM_CAUSE_ACT_REJ_GGSN },
	{ GTPCAUSE_CONTEXT_NOT_FOUND,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_ADDR_OCCUPIED,	GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_NO_MEMORY,		GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_RELOC_FAIL,		GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_UNKNOWN_MAN_EXTHEADER, GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_MISSING_APN,		GSM_CAUSE_MISSING_APN },
	{ GTPCAUSE_UNKNOWN_PDP,		GSM_CAUSE_UNKNOWN_PDP },
	{ 0, 0 }
};

/* The GGSN has confirmed the creation of a PDP Context */
static int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_pdp_ctx *pctx = cbp;
	uint8_t reject_cause;

	DEBUGP(DGPRS, "Received CREATE PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	/* Check for cause value if it was really successful */
	if (cause < 0) {
		LOGP(DGPRS, LOGL_NOTICE, "Create PDP ctx req timed out\n");
		if (pdp->version == 1) {
			pdp->version = 0;
			gtp_create_context_req(sgsn->gsn, pdp, cbp);
			return 0;
		} else {
			reject_cause = GSM_CAUSE_NET_FAIL;
			goto reject;
		}
	}

	/* Check for cause value if it was really successful */
	if (cause != GTPCAUSE_ACC_REQ) {
		reject_cause = cause_map(gtp2sm_cause_map, cause,
					 GSM_CAUSE_ACT_REJ_GGSN);
		goto reject;
	}

	/* Send PDP CTX ACT to MS */
	return gsm48_tx_gsm_act_pdp_acc(pctx);

reject:
	pctx->state = PDP_STATE_NONE;
	pdp_freepdp(pdp);
	sgsn_pdp_ctx_free(pctx);
	/* Send PDP CTX ACT REJ to MS */
	return gsm48_tx_gsm_act_pdp_rej(pctx->mm, pdp->ti, reject_cause,
					0, NULL);

	return EOF;
}

/* Confirmation of a PDP Context Delete */
static int delete_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_pdp_ctx *pctx = cbp;
	int rc;

	DEBUGP(DGPRS, "Received DELETE PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	/* Confirm deactivation of PDP context to MS */
	rc = gsm48_tx_gsm_deact_pdp_acc(pctx);

	sgsn_pdp_ctx_free(pctx);

	return rc;
}

/* Confirmation of an GTP ECHO request */
static int echo_conf(int recovery)
{
	if (recovery < 0) {
		DEBUGP(DGPRS, "GTP Echo Request timed out\n");
		/* FIXME: if version == 1, retry with version 0 */
	} else {
		DEBUGP(DGPRS, "GTP Rx Echo Response\n");
	}
	return 0;
}

/* libgtp callback for confirmations */
static int cb_conf(int type, int cause, struct pdp_t *pdp, void *cbp)
{
	DEBUGP(DGPRS, "libgtp cb_conf(type=%d, cause=%d, pdp=%p, cbp=%p)\n",
		type, cause, pdp, cbp);

	if (cause == EOF)
		LOGP(DGPRS, LOGL_ERROR, "libgtp EOF (type=%u, pdp=%p, cbp=%p)\n",
			type, pdp, cbp);

	switch (type) {
	case GTP_ECHO_REQ:
		return echo_conf(cause);
	case GTP_CREATE_PDP_REQ:
		return create_pdp_conf(pdp, cbp, cause);
	case GTP_DELETE_PDP_REQ:
		return delete_pdp_conf(pdp, cbp, cause);
	default:
		break;
	}
	return 0;
}

/* Called whenever a PDP context is deleted for any reason */
static int cb_delete_context(struct pdp_t *pdp)
{
	LOGP(DGPRS, LOGL_INFO, "PDP Context was deleted\n");
	return 0;
}

/* Called when we receive a Version Not Supported message */
static int cb_unsup_ind(struct sockaddr_in *peer)
{
	LOGP(DGPRS, LOGL_INFO, "GTP Version not supported Indication "
		"from %s:%u\n", inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port));
	return 0;
}

/* Called when we receive a Supported Ext Headers Notification */
static int cb_extheader_ind(struct sockaddr_in *peer)
{
	LOGP(DGPRS, LOGL_INFO, "GTP Supported Ext Headers Noficiation "
		"from %s:%u\n", inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port));
	return 0;
}

/* Called whenever we recive a DATA packet */
static int cb_data_ind(struct pdp_t *pdp, void *packet, unsigned int len)
{
	DEBUGP(DGPRS, "GTP DATA IND from GGSN, length=%u\n", len);
	/* FIXME: resolve PDP/MM context, forward to SNDCP layer */

	return 0;
}

/* libgtp select loop integration */
static int sgsn_gtp_fd_cb(struct bsc_fd *fd, unsigned int what)
{
	struct sgsn_instance *sgi = fd->data;
	int rc;

	if (!(what & BSC_FD_READ))
		return 0;

	switch (fd->priv_nr) {
	case 0:
		rc = gtp_decaps0(sgi->gsn);
		break;
	case 1:
		rc = gtp_decaps1c(sgi->gsn);
		break;
	case 2:
		rc = gtp_decaps1u(sgi->gsn);
		break;
	}
	return rc;
}

static void timeval_normalize(struct timeval *tv)
{
	unsigned int sec = tv->tv_usec / 1000000;
	tv->tv_sec += sec;
	tv->tv_usec -= sec * 1000000;
}

/* diff = a - b */
static int timeval_diff(struct timeval *diff,
			struct timeval *a,
			struct timeval *b)
{
	/* Step 1: normalize input values */
	timeval_normalize(a);
	timeval_normalize(b);

	if (b->tv_sec > a->tv_sec ||
	    b->tv_sec == a->tv_sec && b->tv_usec > a->tv_usec) {
		b->tv_sec = b->tv_usec = 0;
		return -ERANGE;
	}

	if (b->tv_usec > a->tv_usec) {
		a->tv_sec -= 1;
		a->tv_usec += 1000000;
	}

	diff->tv_usec = a->tv_usec - b->tv_usec;
	diff->tv_sec = a->tv_sec - b->tv_sec;

	return 0;
}

static void sgsn_gtp_tmr_start(struct sgsn_instance *sgi)
{
	struct timeval now, next, diff;

	/* Retrieve next retransmission as struct timeval */
	gtp_retranstimeout(sgi->gsn, &next);

	/* Calculate the difference to now */
	gettimeofday(&now, NULL);
	timeval_diff(&diff, &next, &now);

	/* re-schedule the timer */
	bsc_schedule_timer(&sgi->gtp_timer, diff.tv_sec, diff.tv_usec/1000);
}

/* timer callback for libgtp retransmissions and ping */
static void sgsn_gtp_tmr_cb(void *data)
{
	struct sgsn_instance *sgi = data;

	/* Do all the retransmissions as needed */
	gtp_retrans(sgi->gsn);

	sgsn_gtp_tmr_start(sgi);
}

int sgsn_gtp_init(struct sgsn_instance *sgi)
{
	int rc;
	struct gsn_t *gsn;

	rc = gtp_new(&sgi->gsn, sgi->cfg.gtp_statedir,
		     &sgi->cfg.gtp_listenaddr.sin_addr, GTP_MODE_SGSN);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to create GTP: %d\n", rc);
		return rc;
	}
	gsn = sgi->gsn;

	sgi->gtp_fd0.fd = gsn->fd0;
	sgi->gtp_fd0.priv_nr = 0;
	sgi->gtp_fd0.data = sgi;
	sgi->gtp_fd0.when = BSC_FD_READ;
	sgi->gtp_fd0.cb = sgsn_gtp_fd_cb;
	rc = bsc_register_fd(&sgi->gtp_fd0);
	if (rc < 0)
		return rc;

	sgi->gtp_fd1c.fd = gsn->fd1c;
	sgi->gtp_fd1c.priv_nr = 1;
	sgi->gtp_fd1c.data = sgi;
	sgi->gtp_fd1c.when = BSC_FD_READ;
	sgi->gtp_fd1c.cb = sgsn_gtp_fd_cb;
	bsc_register_fd(&sgi->gtp_fd1c);
	if (rc < 0)
		return rc;

	sgi->gtp_fd1u.fd = gsn->fd1u;
	sgi->gtp_fd1u.priv_nr = 2;
	sgi->gtp_fd1u.data = sgi;
	sgi->gtp_fd1u.when = BSC_FD_READ;
	sgi->gtp_fd1u.cb = sgsn_gtp_fd_cb;
	bsc_register_fd(&sgi->gtp_fd1u);
	if (rc < 0)
		return rc;

	/* Start GTP re-transmission timer */
	sgi->gtp_timer.cb = sgsn_gtp_tmr_cb;
	sgsn_gtp_tmr_start(sgi);

	/* Register callbackcs with libgtp */
	gtp_set_cb_delete_context(gsn, cb_delete_context);
	gtp_set_cb_conf(gsn, cb_conf);
	gtp_set_cb_data_ind(gsn, cb_data_ind);
	gtp_set_cb_unsup_ind(gsn, cb_unsup_ind);
	gtp_set_cb_extheader_ind(gsn, cb_extheader_ind);

	return 0;
}
