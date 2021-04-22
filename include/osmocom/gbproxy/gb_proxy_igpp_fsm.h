#pragma once

#include <stdint.h>
#include <osmocom/gbproxy/gb_proxy_igpp.h>

struct osmo_fsm_inst;
struct gprs_ra_id;

enum igpp_fsm_state {
	IGPP_FSM_S_INIT,
	IGPP_FSM_S_WAIT_RESET_ACK,
	IGPP_FSM_S_CONNECTED,
	IGPP_FSM_S_DISCONNECTED,
};

enum igpp_fsm_event {
	/* Rx of IGPP PDUs from the remote side; 'data' is 'struct tlv_parsed', and
	 * the assumption is that the caller has already validated all mandatory IEs
	 * are present and of sufficient length */
	IGPP_FSM_E_RX_RESET,
	IGPP_FSM_E_RX_RESET_ACK,

	IGPP_FSM_E_RX_PING,
	IGPP_FSM_E_RX_PONG,
};

// FIXME: Do we need ops?
struct igpp_fsm_ops {
	/* call-back notifying the user of a state change */
	void (*state_chg_notification)(int old_state, int new_state,
					void *priv);
};

struct osmo_fsm_inst *igpp_fsm_alloc(void *ctx, struct igpp_config *igpp);

void igpp_fsm_set_ops(struct osmo_fsm_inst *fi, const struct igpp_fsm_ops *ops, void *ops_priv);
