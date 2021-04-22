#pragma once

#include <stdint.h>
#include <osmocom/gbproxy/gb_proxy_igpp.h>

struct osmo_fsm_inst;
struct gprs_ra_id;

enum igpp_nse_fsm_state {
	IGPP_NSE_FSM_S_INIT,
	IGPP_NSE_FSM_S_RECOVERING,
	IGPP_NSE_FSM_S_PRIMARY,
	IGPP_NSE_FSM_S_SECONDARY,
};

enum igpp_nse_fsm_event {
	/* Rx of IGPP PDUs from the remote side; 'data' is 'struct tlv_parsed', and
	 * the assumption is that the caller has already validated all mandatory IEs
	 * are present and of sufficient length */
	IGPP_NSE_FSM_E_RX_PING,
	IGPP_NSE_FSM_E_RX_PONG,

	IGPP_NSE_FSM_E_RX_RESET,
	IGPP_NSE_FSM_E_RX_RESET_ACK,

	IGPP_NSE_FSM_E_RX_PROMOTE,
	IGPP_NSE_FSM_E_RX_PROMOTE_ACK,
	IGPP_NSE_FSM_E_RX_DEMOTE,
	IGPP_NSE_FSM_E_RX_DEMOTE_ACK,

	IGPP_NSE_FSM_E_RX_CREATE_BVC,
	IGPP_NSE_FSM_E_RX_CREATE_BVC_ACK,
	IGPP_NSE_FSM_E_RX_DELETE_BVC,
	IGPP_NSE_FSM_E_RX_DELETE_BVC_ACK,

	IGPP_NSE_FSM_E_RX_BLOCK_BVC,
	IGPP_NSE_FSM_E_RX_BLOCK_BVC_ACK,

	IGPP_NSE_FSM_E_RX_UNBLOCK_BVC,
	IGPP_NSE_FSM_E_RX_UNBLOCK_BVC_ACK,

	IGPP_NSE_FSM_E_RX_FORWARD,
	IGPP_NSE_FSM_E_RX_FORWARD_ACK,

	IGPP_NSE_FSM_E_RX_ADD_IPSNS_EP,
	IGPP_NSE_FSM_E_RX_ADD_IPSNS_EP_ACK,
	IGPP_NSE_FSM_E_RX_DEL_IPSNS_EP,
	IGPP_NSE_FSM_E_RX_DEL_IPSNS_EP_ACK,
	IGPP_NSE_FSM_E_RX_CHG_IPSNS_EP,
	IGPP_NSE_FSM_E_RX_CHG_IPSNS_EP_ACK,

//	/* Requests of the local user */
//	IGPP_NSE_FSM_E_REQ_BLOCK,	/* data: uint8_t *cause */
//	IGPP_NSE_FSM_E_REQ_UNBLOCK,
//	IGPP_NSE_FSM_E_REQ_RESET,	/* data: uint8_t *cause */
//	IGPP_NSE_FSM_E_REQ_FC_BVC,	/* data: struct bssgp2_flow_ctrl */
};

// FIXME: Do we need ops?
struct igpp_nse_fsm_ops {
	/* call-back notifying the user of a state change */
	void (*state_chg_notification)(uint16_t nsei, int old_state, int new_state,
					void *priv);
};

struct osmo_fsm_inst *igpp_nse_fsm_alloc(void *ctx, uint16_t nsei, enum igpp_role role);

void igpp_nse_fsm_set_ops(struct osmo_fsm_inst *fi, const struct igpp_nse_fsm_ops *ops, void *ops_priv);
