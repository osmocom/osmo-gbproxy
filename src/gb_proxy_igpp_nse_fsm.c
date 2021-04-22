/* Inter GbProxy Protocol Finite State Machine */

/* (C) 2021 sysmocom s.f.m.c. GmbH
 * Author: Daniel Willmann <dwillmann@sysmocom.de>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "debug.h"
#include <string.h>
#include <stdio.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/tdef.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gbproxy/gb_proxy_igpp.h>
#include <osmocom/gbproxy/gb_proxy_igpp_fsm.h>

#define S(x)	(1 << (x))

struct osmo_tdef igpp_fsm_tdefs[] = {
	{
		.T = 1,
		.default_val = 200,
		.min_val = 100,
		.max_val = 3000,
		.unit = OSMO_TDEF_MS,
		.desc = "Guards the PING/PONG procedure",
	}, {
		.T = 2,
		.default_val = 1000,
		.min_val = 500,
		.max_val = 5000,
		.unit = OSMO_TDEF_MS,
		.desc = "Guards all IGPP procedures requiring an ACK",
	},
	{}
};

#define T1	1
#define T2	2

/* We cannot use osmo_tdef_fsm_* as it makes hard-coded assumptions that
 * each new/target state will always use the same timer and timeout - or
 * a timeout at all */
#define T1_MSECS	osmo_tdef_get(igpp_nse_fsm_tdefs, T1, OSMO_TDEF_MS, 200)
#define T2_MSECS	osmo_tdef_get(igpp_nse_fsm_tdefs, T2, OSMO_TDEF_MS, 1000)

/* forward declaration */
static struct osmo_fsm igpp_nse_fsm;

/* FIXME: Incomplete */
static const struct value_string igpp_nse_event_names[] = {
	{ IGPP_NSE_FSM_E_RX_PING, "RX-PING" },
	{ IGPP_NSE_FSM_E_RX_PONG, "RX-PONG" },

	{ IGPP_NSE_FSM_E_RX_RESET, "RX-RESET" },
	{ IGPP_NSE_FSM_E_RX_RESET_ACK, "RX-RESET-ACK" },
        /* PROMOTE/DEMOTE */
        /* CREATE/DELETE */
	{ IGPP_NSE_FSM_E_RX_BLOCK_BVC, "RX-BLOCK-BVC" },
	{ IGPP_NSE_FSM_E_RX_BLOCK_BVC_ACK, "RX-BLOCK-BVC-ACK" },
	{ IGPP_NSE_FSM_E_RX_UNBLOCK_BVC, "RX-UNBLOCK-BVC" },
	{ IGPP_NSE_FSM_E_RX_UNBLOCK_BVC_ACK, "RX-UNBLOCK-BVC-ACK" },
	/* FORWARD */
	/* IP-SNS ADD/DEL/CHG */
	{ 0, NULL }
};

struct igpp_nse_fsm_priv {
	/* NSEI of the underlying NS Entity */
	uint16_t nsei;

	/* Are we by default primary or secondary for this NSE */
	enum igpp_role initial_role;

	/* call-backs provided by the user */
	const struct igpp_nse_fsm_ops *ops;
	/* private data pointer passed to each call-back invocation */
	void *ops_priv;
};


/* XXX XXX====================================*/
#if 0
static int fi_tx_ptp(struct osmo_fsm_inst *fi, struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &igpp_nse_fsm);

	LOGPFSM(fi, "Tx BSSGP %s\n", osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));

	return bssgp2_nsi_tx_ptp(bfp->nsi, bfp->nsei, bfp->bvci, msg, 0);
}

static int fi_tx_sig(struct osmo_fsm_inst *fi, struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &igpp_nse_fsm);

	LOGPFSM(fi, "Tx BSSGP %s\n", osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));

	return bssgp2_nsi_tx_sig(bfp->nsi, bfp->nsei, msg, 0);
}

/* helper function to transmit BVC-RESET with right combination of conditional/optional IEs */
static void _tx_bvc_reset(struct osmo_fsm_inst *fi, uint8_t cause)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	const uint8_t *features = NULL;
	const uint8_t *features_ext = NULL;
	uint8_t _features[2] = {
		(bfp->features.advertised >> 0) & 0xff,
		(bfp->features.advertised >> 8) & 0xff,
	};
	struct msgb *tx;

	OSMO_ASSERT(fi->fsm == &igpp_nse_fsm);

	/* transmit BVC-RESET to peer; RA-ID only present for PTP from BSS */
	if (bfp->bvci == 0) {
		features = &_features[0];
		features_ext = &_features[1];
	}
	tx = bssgp2_enc_bvc_reset(bfp->bvci, cause,
				  bfp->bvci && !bfp->role_sgsn ? &bfp->ra_id : NULL,
				  bfp->cell_id, features, features_ext);
	fi_tx_sig(fi, tx);
}

/* helper function to transmit BVC-RESET-ACK with right combination of conditional/optional IEs */
static void _tx_bvc_reset_ack(struct osmo_fsm_inst *fi)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	const uint8_t *features = NULL;
	const uint8_t *features_ext = NULL;
	uint8_t _features[2] = {
		(bfp->features.advertised >> 0) & 0xff,
		(bfp->features.advertised >> 8) & 0xff,
	};
	struct msgb *tx;

	OSMO_ASSERT(fi->fsm == &igpp_nse_fsm);

	/* transmit BVC-RESET-ACK to peer; RA-ID only present for PTP from BSS -> SGSN */
	if (bfp->bvci == 0) {
		features = &_features[0];
		features_ext = &_features[1];
	}
	tx = bssgp2_enc_bvc_reset_ack(bfp->bvci, bfp->bvci && !bfp->role_sgsn ? &bfp->ra_id : NULL,
				     bfp->cell_id, features, features_ext);
	fi_tx_sig(fi, tx);
}

/* helper function to transmit BVC-STATUS with right combination of conditional/optional IEs */
static void _tx_status(struct osmo_fsm_inst *fi, enum gprs_bssgp_cause cause, const struct msgb *rx)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	struct msgb *tx;
	uint16_t *bvci = NULL;

	/* GSM 08.18, 10.4.14.1: The BVCI must be included if (and only if) the
	 * cause is either "BVCI blocked" or "BVCI unknown" */
	if (cause == BSSGP_CAUSE_UNKNOWN_BVCI || cause == BSSGP_CAUSE_BVCI_BLOCKED)
		bvci = &bfp->bvci;

	tx = bssgp2_enc_status(cause, bvci, rx, bfp->max_pdu_len);

	if (msgb_bvci(rx) == 0)
		fi_tx_sig(fi, tx);
	else
		fi_tx_ptp(fi, tx);
}

/* Update the features by bit-wise AND of advertised + received features */
static void update_negotiated_features(struct osmo_fsm_inst *fi, const struct tlv_parsed *tp)
{
	struct bvc_fsm_priv *bfp = fi->priv;

	OSMO_ASSERT(fi->fsm == &igpp_nse_fsm);

	bfp->features.received = 0;

	if (TLVP_PRES_LEN(tp, BSSGP_IE_FEATURE_BITMAP, 1))
		bfp->features.received |= *TLVP_VAL(tp, BSSGP_IE_FEATURE_BITMAP);

	if (TLVP_PRES_LEN(tp, BSSGP_IE_EXT_FEATURE_BITMAP, 1))
		bfp->features.received |= (*TLVP_VAL(tp, BSSGP_IE_EXT_FEATURE_BITMAP) << 8);

	bfp->features.negotiated = bfp->features.advertised & bfp->features.received;

	LOGPFSML(fi, LOGL_NOTICE, "Updating features: Advertised 0x%04x, Received 0x%04x, Negotiated 0x%04x\n",
		 bfp->features.advertised, bfp->features.received, bfp->features.negotiated);
}

static void igpp_nse_fsm_blocked_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	/* signaling BVC can never be blocked */
	OSMO_ASSERT(bfp->bvci != 0);
	_onenter_tail(fi, prev_state);
}

static void igpp_nse_fsm_blocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	struct msgb *rx = NULL, *tx;
	const struct tlv_parsed *tp = NULL;
	uint8_t cause;

	switch (event) {
	case BSSGP_BVCFSM_E_RX_BLOCK_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* If a BVC-BLOCK-ACK PDU is received by a BSS for the signalling BVC, the PDU is ignored. */
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-BLOCK-ACK on BVCI=0 is illegal\n");
			if (!bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		/* stop T1 timer */
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, 0, 0);
		break;
	case BSSGP_BVCFSM_E_RX_BLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		cause = *TLVP_VAL(tp, BSSGP_IE_CAUSE);
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-BLOCK (cause=%s)\n", bssgp_cause_str(cause));
		/* If a BVC-BLOCK PDU is received by an SGSN for a blocked BVC, a BVC-BLOCK-ACK
		 * PDU shall be returned. */
		if (bfp->role_sgsn) {
			/* If a BVC-BLOCK PDU is received by an SGSN for
			 * the signalling BVC, the PDU is ignored */
			if (bfp->bvci == 0)
				break;
			tx = bssgp2_enc_bvc_block_ack(bfp->bvci);
			fi_tx_sig(fi, tx);
		}
		break;
	case BSSGP_BVCFSM_E_RX_UNBLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-UNBLOCK\n");
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-UNBLOCK on BVCI=0 is illegal\n");
			/* If BVC-UNBLOCK PDU is received by an SGSN for the signalling BVC, the PDU is ignored.*/
			if (bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		if (!bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-UNBLOCK on BSS is illegal\n");
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		tx = bssgp2_enc_bvc_unblock_ack(bfp->bvci);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, T1_SECS, T1);
		break;
	case BSSGP_BVCFSM_E_REQ_UNBLOCK:
		if (bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "SGSN side cannot initiate BVC unblock\n");
			break;
		}
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "BVCI 0 cannot be unblocked\n");
			break;
		}
		bfp->locally_blocked = false;
		tx = bssgp2_enc_bvc_unblock(bfp->bvci);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		break;
	}
}

/* Waiting for RESET-ACK: Receive PDUs but don't transmit */
static void igpp_nse_fsm_wait_reset_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bvc_fsm_priv *bfp = fi->priv;
	const struct tlv_parsed *tp = NULL;
	struct msgb *rx = NULL, *tx;

	switch (event) {
	case BSSGP_BVCFSM_E_RX_RESET:
		/* 48.018 Section 8.4.3: If the BSS (or SGSN) has sent a BVC-RESET PDU for a BVCI to
		 * the SGSN (or BSS) and is awaiting a BVC-RESET-ACK PDU in response, but instead
		 * receives a BVC-RESET PDU indicating the same BVCI, then this shall be interpreted
		 * as a BVC-RESET ACK PDU and the T2 timer shall be stopped. */
		/* fall-through */
	case BSSGP_BVCFSM_E_RX_RESET_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		if (bfp->bvci == 0)
			update_negotiated_features(fi, tp);
		if (bfp->role_sgsn && bfp->bvci != 0)
			bfp->cell_id = bssgp_parse_cell_id(&bfp->ra_id, TLVP_VAL(tp, BSSGP_IE_CELL_ID));
		if (!bfp->role_sgsn && bfp->bvci != 0 && bfp->locally_blocked) {
			/* initiate the blocking procedure */
			/* transmit BVC-BLOCK, transition to BLOCKED state and start re-transmit timer */
			tx = bssgp2_enc_bvc_block(bfp->bvci, bfp->block_cause);
			fi_tx_sig(fi, tx);
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, T1_SECS, T1);
		} else
			osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		break;
	}
}

static void igpp_nse_fsm_unblocked(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bssgp2_flow_ctrl rx_fc, *tx_fc;
	struct bvc_fsm_priv *bfp = fi->priv;
	const struct tlv_parsed *tp = NULL;
	struct msgb *rx = NULL, *tx;
	int rc;

	switch (event) {
	case BSSGP_BVCFSM_E_RX_UNBLOCK_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* If BVC-UNBLOCK-ACK PDU is received by an BSS for the signalling BVC, the PDU is ignored. */
		LOGPFSML(fi, LOGL_ERROR, "Rx BVC-UNBLOCK-ACK on BVCI=0 is illegal\n");
		if (bfp->bvci == 0) {
			if (!bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		/* stop T1 timer */
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_UNBLOCKED, 0, 0);
		break;
	case BSSGP_BVCFSM_E_RX_UNBLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* If a BVC-UNBLOCK PDU is received by an SGSN for a blocked BVC, a BVC-UNBLOCK-ACK
		 * PDU shall be returned. */
		if (bfp->role_sgsn) {
			/* If a BVC-UNBLOCK PDU is received by an SGSN for
			 * the signalling BVC, the PDU is ignored */
			if (bfp->bvci == 0)
				break;
			bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_UNBLOCK_ACK, bfp->nsei, bfp->bvci, 0);
		}
		break;
	case BSSGP_BVCFSM_E_RX_BLOCK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		LOGPFSML(fi, LOGL_NOTICE, "Rx BVC-BLOCK (cause=%s)\n",
			 bssgp_cause_str(*TLVP_VAL(tp, BSSGP_IE_CAUSE)));
		/* If a BVC-BLOCK PDU is received by an SGSN for the signalling BVC, the PDU is ignored */
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-BLOCK on BVCI=0 is illegal\n");
			if (bfp->role_sgsn)
				break;
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		if (!bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "Rx BVC-BLOCK on BSS is illegal\n");
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		/* transmit BVC-BLOCK-ACK, transition to BLOCKED state */
		tx = bssgp2_enc_bvc_block_ack(bfp->bvci);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, 0, 0);
		break;
	case BSSGP_BVCFSM_E_REQ_BLOCK:
		if (bfp->role_sgsn) {
			LOGPFSML(fi, LOGL_ERROR, "SGSN may not initiate BVC-BLOCK\n");
			break;
		}
		if (bfp->bvci == 0) {
			LOGPFSML(fi, LOGL_ERROR, "BVCI 0 cannot be blocked\n");
			break;
		}
		bfp->locally_blocked = true;
		bfp->block_cause = *(uint8_t *)data;
		/* transmit BVC-BLOCK, transition to BLOCKED state and start re-transmit timer */
		tx = bssgp2_enc_bvc_block(bfp->bvci, bfp->block_cause);
		fi_tx_sig(fi, tx);
		osmo_fsm_inst_state_chg(fi, BSSGP_BVCFSM_S_BLOCKED, T1_SECS, T1);
		break;
	case BSSGP_BVCFSM_E_RX_FC_BVC:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* we assume osmo_tlv_prot_* has been used before calling here to ensure this */
		OSMO_ASSERT(bfp->role_sgsn);
		rc = bssgp2_dec_fc_bvc(&rx_fc, tp);
		if (rc < 0) {
			_tx_status(fi, BSSGP_CAUSE_SEM_INCORR_PDU, rx);
			break;
		}
		if (bfp->ops->rx_fc_bvc)
			bfp->ops->rx_fc_bvc(bfp->nsei, bfp->bvci, &rx_fc, bfp->ops_priv);
		tx = bssgp2_enc_fc_bvc_ack(rx_fc.tag);
		fi_tx_ptp(fi, tx);
		break;
	case BSSGP_BVCFSM_E_RX_FC_BVC_ACK:
		rx = data;
		tp = (const struct tlv_parsed *) msgb_bcid(rx);
		/* we assume osmo_tlv_prot_* has been used before calling here to ensure this */
		OSMO_ASSERT(!bfp->role_sgsn);
		break;
	case BSSGP_BVCFSM_E_REQ_FC_BVC:
		tx_fc = data;
		tx = bssgp2_enc_fc_bvc(tx_fc, bfp->features.negotiated & (BSSGP_XFEAT_GBIT << 8) ?
					&bfp->features.fc_granularity : NULL);
		fi_tx_ptp(fi, tx);
		break;
	}
}
#endif
/* XXX XXX =================================*/

/* "tail" of each onenter() handler: Calling the state change notification call-back */
static void _onenter_tail(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct igpp_nse_fsm_priv *ifp = fi->priv;

	if (prev_state == fi->state)
		return;

	if (ifp->ops && ifp->ops->state_chg_notification)
		ifp->ops->state_chg_notification(ifp->nsei, prev_state, fi->state, ifp->ops_priv);
}

static void igpp_nse_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_nse_fsm_recovering(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_nse_fsm_primary(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_nse_fsm_secondary(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_nse_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct igpp_fsm_priv *ifp = fi->priv;

	switch (event) {
	default:
		break;
	}
}

static int igpp_nse_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct igpp_fsm_priv *ifp = fi->priv;
	struct msgb *tx;

	switch (fi->T) {
	default:
		OSMO_ASSERT(0);
		break;
	}
	return 0;
}

static const struct osmo_fsm_state igpp_nse_fsm_states[] = {
	[IGPP_NSE_FSM_S_INIT] = {
		/* initial state */
		.name = "INIT",
		.in_event_mask = S(IGPP_NSE_FSM_E_RX_RESET_ACK),
		.out_state_mask = S(IGPP_NSE_FSM_S_PRIMARY) |
				  S(IGPP_NSE_FSM_S_RECOVERING),
		.action = igpp_nse_fsm_init,
		.onenter = _onenter_tail,
	},
	[IGPP_NSE_FSM_S_RECOVERING] = {
		.name = "RECOVERING",
		.in_event_mask = S(IGPP_NSE_FSM_E_RX_PROMOTE) |
				 S(IGPP_NSE_FSM_E_RX_DEMOTE) |
				 S(IGPP_NSE_FSM_E_RX_CREATE_BVC),
		.out_state_mask = S(IGPP_NSE_FSM_S_SECONDARY) |
				  S(IGPP_NSE_FSM_S_PRIMARY) |
				  S(IGPP_NSE_FSM_S_INIT),
		.action = igpp_nse_fsm_recovering,
		.onenter = _onenter_tail,
	},
	[IGPP_NSE_FSM_S_PRIMARY] = {
		.name = "PRIMARY",
		.in_event_mask = S(IGPP_NSE_FSM_E_RX_DEMOTE) |
				 S(IGPP_NSE_FSM_E_RX_CREATE_BVC_ACK),

		.out_state_mask = S(IGPP_NSE_FSM_S_SECONDARY) |
				  S(IGPP_NSE_FSM_S_INIT),
		.action = igpp_nse_fsm_primary,
		.onenter = _onenter_tail,
	},
	[IGPP_NSE_FSM_S_SECONDARY] = {
		.name = "SECONDARY",
		.in_event_mask = S(IGPP_NSE_FSM_E_RX_PROMOTE) |
				 S(IGPP_NSE_FSM_E_RX_CREATE_BVC),
		.out_state_mask = S(IGPP_NSE_FSM_S_PRIMARY),
		.action = igpp_nse_fsm_secondary,
		.onenter = _onenter_tail,
	},
};

static struct osmo_fsm igpp_nse_fsm = {
	.name = "IGPP-NSE",
	.states = igpp_nse_fsm_states,
	.num_states = ARRAY_SIZE(igpp_nse_fsm_states),
	.allstate_event_mask = S(IGPP_NSE_FSM_E_RX_PING) |
			       S(IGPP_NSE_FSM_E_RX_PONG) |
			       S(IGPP_NSE_FSM_E_RX_RESET),
	.allstate_action = igpp_nse_fsm_allstate,
	.timer_cb = igpp_nse_fsm_timer_cb,
	.log_subsys = DIGPP,
	.event_names = igpp_nse_event_names,
};

/* FIXME: Do we need NSE role? pass it along then */
static struct osmo_fsm_inst *
_igpp_nse_fsm_alloc(void *ctx, uint16_t nsei, enum igpp_role role)
{
	struct osmo_fsm_inst *fi;
	struct igpp_nse_fsm_priv *ifp;
	char idbuf[64];

	/* TODO: encode our role in the id string? */
	snprintf(idbuf, sizeof(idbuf), "IGPP-NSE%05u", nsei);

	fi = osmo_fsm_inst_alloc(&igpp_nse_fsm, ctx, NULL, LOGL_INFO, idbuf);
	if (!fi)
		return NULL;

	ifp = talloc_zero(fi, struct igpp_nse_fsm_priv);
	if (!ifp) {
		osmo_fsm_inst_free(fi);
		return NULL;
	}
	fi->priv = ifp;

	ifp->nsei = nsei;
	ifp->initial_role = role;

	return fi;
}

/*! Allocate an IGPP FSM for an NSE
 *  \param[in] ctx talloc context from which to allocate
 *  \param[in] nsei NS Entity Identifier
 *  \returns newly-allocated FSM Instance; NULL in case of error */
struct osmo_fsm_inst *
igpp_nse_fsm_alloc(void *ctx, uint16_t nsei, enum igpp_role role)
{
	struct osmo_fsm_inst *fi;

	fi = _igpp_nse_fsm_alloc(ctx, nsei, role);
	if (!fi)
		return NULL;

	return fi;
}

/*! Set the 'operations' callbacks + private data.
 *  \param[in] fi FSM instance for which the data shall be set
 *  \param[in] ops IGPP NSE FSM operations (call-back functions) to register
 *  \param[in] ops_priv opaque/private data pointer passed through to call-backs */
void igpp_nse_fsm_set_ops(struct osmo_fsm_inst *fi, const struct igpp_nse_fsm_ops *ops, void *ops_priv)
{
	struct igpp_nse_fsm_priv *ifp = fi->priv;

	OSMO_ASSERT(fi->fsm == &igpp_nse_fsm);

	ifp->ops = ops;
	ifp->ops_priv = ops_priv;
}

static __attribute__((constructor)) void on_dso_load_igpp_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&igpp_nse_fsm) == 0);
}
