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
		.default_val = 1000,
		.min_val = 500,
		.max_val = 5000,
		.unit = OSMO_TDEF_MS,
		.desc = "Guards the RESET procedure",
	}, {
		.T = 2,
		.default_val = 1000,
		.min_val = 100,
		.max_val = 3000,
		.unit = OSMO_TDEF_MS,
		.desc = "Guards the PING/PONG procedure",
	},
	{}
};

#define T1	1
#define T2	2

/* We cannot use osmo_tdef_fsm_* as it makes hard-coded assumptions that
 * each new/target state will always use the same timer and timeout - or
 * a timeout at all */
#define T1_SECS	osmo_tdef_get(igpp_fsm_tdefs, T1, OSMO_TDEF_MS, 1000)
#define T2_SECS	osmo_tdef_get(igpp_fsm_tdefs, T2, OSMO_TDEF_MS, 1000)

/* forward declaration */
static struct osmo_fsm igpp_fsm;

/* FIXME: Incomplete */
static const struct value_string igpp_event_names[] = {
	{ IGPP_FSM_E_RX_RESET, "RX-RESET" },
	{ IGPP_FSM_E_RX_RESET_ACK, "RX-RESET-ACK" },

	{ IGPP_FSM_E_RX_PING, "RX-PING" },
	{ IGPP_FSM_E_RX_PONG, "RX-PONG" },

	{ 0, NULL }
};

struct igpp_fsm_priv {
	/* Pointer to the IGPP config stuct */
	struct igpp_config *igpp;
	/* Are we by default primary or secondary for this NSE */
	enum igpp_role initial_role;

	/* call-backs provided by the user */
	const struct igpp_fsm_ops *ops;
	/* private data pointer passed to each call-back invocation */
	void *ops_priv;
};

/* "tail" of each onenter() handler: Calling the state change notification call-back */
static void _onenter_tail(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct igpp_fsm_priv *ifp = fi->priv;

	if (prev_state == fi->state)
		return;

	if (ifp->ops && ifp->ops->state_chg_notification)
		ifp->ops->state_chg_notification(prev_state, fi->state, ifp->ops_priv);
}

static void igpp_fsm_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_fsm_init_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct igpp_fsm_priv *ifp = fi->priv;
	struct msgb *msg;

	msg = igpp_enc_ping();
	igpp_send(ifp->igpp, msg);
	osmo_fsm_inst_state_chg(fi, IGPP_FSM_S_WAIT_RESET_ACK, T1_SECS, T1);

	_onenter_tail(fi, prev_state);
}

static void igpp_fsm_wait_reset_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_fsm_wait_reset_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct igpp_fsm_priv *ifp = fi->priv;
	struct msgb *msg;

	msg = igpp_enc_ping();
	igpp_send(ifp->igpp, msg);
	osmo_fsm_inst_state_chg(fi, IGPP_FSM_S_WAIT_RESET_ACK, T1_SECS, T1);

	_onenter_tail(fi, prev_state);
}

static void igpp_fsm_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_fsm_disconnected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: Send reset, wait for sync or timeout */
	/* we don't really expect anything in this state; all handled via allstate */
	OSMO_ASSERT(0);
}

static void igpp_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct igpp_fsm_priv *ifp = fi->priv;
	struct msgb *msg;

	switch (event) {
	case IGPP_FSM_E_RX_RESET:
		break;
	case IGPP_FSM_E_RX_PING:
		msg = igpp_enc_pong();
		igpp_send(ifp->igpp, msg);
		break;
	case IGPP_FSM_E_RX_PONG:
		break;
	default:
		break;
	}
}

static int igpp_fsm_timer_cb(struct osmo_fsm_inst *fi)
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

static const struct osmo_fsm_state igpp_fsm_states[] = {
	[IGPP_FSM_S_INIT] = {
		/* initial state */
		.name = "INIT",
		.in_event_mask = 0,
		.out_state_mask = S(IGPP_FSM_S_INIT) |
				  S(IGPP_FSM_S_WAIT_RESET_ACK),
		.action = igpp_fsm_init,
		.onenter = igpp_fsm_init_onenter,
	},
	[IGPP_FSM_S_WAIT_RESET_ACK] = {
		/* initial state */
		.name = "WAIT_RESET_ACK",
		.in_event_mask = S(IGPP_FSM_E_RX_RESET_ACK),
		.out_state_mask = S(IGPP_FSM_S_WAIT_RESET_ACK) |
				  S(IGPP_FSM_S_CONNECTED) |
				  S(IGPP_FSM_S_DISCONNECTED),
		.action = igpp_fsm_wait_reset_ack,
		.onenter = igpp_fsm_wait_reset_ack_onenter,
	},
	[IGPP_FSM_S_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = 0,
		.out_state_mask = S(IGPP_FSM_S_DISCONNECTED) |
				  S(IGPP_FSM_S_INIT),
		.action = igpp_fsm_connected,
		.onenter = _onenter_tail,
	},
	[IGPP_FSM_S_DISCONNECTED] = {
		.name = "DISCONNECTED",
		.in_event_mask = 0,
		.out_state_mask = S(IGPP_FSM_S_CONNECTED) |
				  S(IGPP_FSM_S_INIT),
		.action = igpp_fsm_disconnected,
		.onenter = _onenter_tail,
	},
};

static struct osmo_fsm igpp_fsm = {
	.name = "IGPP",
	.states = igpp_fsm_states,
	.num_states = ARRAY_SIZE(igpp_fsm_states),
	.allstate_event_mask = S(IGPP_FSM_E_RX_PING) |
			       S(IGPP_FSM_E_RX_PONG) |
			       S(IGPP_FSM_E_RX_RESET),
	.allstate_action = igpp_fsm_allstate,
	.timer_cb = igpp_fsm_timer_cb,
	.log_subsys = DIGPP,
	.event_names = igpp_event_names,
};

/* FIXME: Do we need NSE role? pass it along then */
static struct osmo_fsm_inst *
_igpp_fsm_alloc(void *ctx, struct igpp_config *igpp)
{
	struct osmo_fsm_inst *fi;
	struct igpp_fsm_priv *ifp;
	char idbuf[64];

	/* TODO: encode our role in the id string? */
	snprintf(idbuf, sizeof(idbuf), "IGPP");

	fi = osmo_fsm_inst_alloc(&igpp_fsm, ctx, NULL, LOGL_INFO, idbuf);
	if (!fi)
		return NULL;

	ifp = talloc_zero(fi, struct igpp_fsm_priv);
	if (!ifp) {
		osmo_fsm_inst_free(fi);
		return NULL;
	}
	fi->priv = ifp;

	ifp->igpp = igpp;

	return fi;
}

/*! Allocate an IGPP FSM for an NSE
 *  \param[in] ctx talloc context from which to allocate
 *  \returns newly-allocated FSM Instance; NULL in case of error */
struct osmo_fsm_inst *igpp_fsm_alloc(void *ctx, struct igpp_config *igpp)
{
	struct osmo_fsm_inst *fi;

	fi = _igpp_fsm_alloc(ctx, igpp);
	if (!fi)
		return NULL;

	return fi;
}

/*! Set the 'operations' callbacks + private data.
 *  \param[in] fi FSM instance for which the data shall be set
 *  \param[in] ops IGPP FSM operations (call-back functions) to register
 *  \param[in] ops_priv opaque/private data pointer passed through to call-backs */
void igpp_fsm_set_ops(struct osmo_fsm_inst *fi, const struct igpp_fsm_ops *ops, void *ops_priv)
{
	struct igpp_fsm_priv *ifp = fi->priv;

	OSMO_ASSERT(fi->fsm == &igpp_fsm);

	ifp->ops = ops;
	ifp->ops_priv = ops_priv;
}

static __attribute__((constructor)) void on_dso_load_igpp_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&igpp_fsm) == 0);
}
