#pragma once

#include <osmocom/core/hashtable.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>

#include <osmocom/netif/stream.h>

#include <stdint.h>

#define IGPP_DEFAULT_PORT 1234

enum igpp_pdu_type {
	IGPP_PDUT_PING,
	IGPP_PDUT_PONG,

	IGPP_PDUT_RESET,
	IGPP_PDUT_RESET_ACK,

	IGPP_PDUT_PROMOTE,
	IGPP_PDUT_PROMOTE_ACK,
	IGPP_PDUT_DEMOTE,
	IGPP_PDUT_DEMOTE_ACK,

	IGPP_PDUT_CREATE_BVC,
	IGPP_PDUT_CREATE_BVC_ACK,
	IGPP_PDUT_DELETE_BVC,
	IGPP_PDUT_DELETE_BVC_ACK,

	IGPP_PDUT_BLOCK_BVC,
	IGPP_PDUT_BLOCK_BVC_ACK,

	IGPP_PDUT_UNBLOCK_BVC,
	IGPP_PDUT_UNBLOCK_BVC_ACK,

	IGPP_PDUT_FORWARD,
	IGPP_PDUT_FORWARD_ACK,

	IGPP_PDUT_ADD_IPSNS_EP,
	IGPP_PDUT_ADD_IPSNS_EP_ACK,
	IGPP_PDUT_DEL_IPSNS_EP,
	IGPP_PDUT_DEL_IPSNS_EP_ACK,
	IGPP_PDUT_CHG_IPSNS_EP,
	IGPP_PDUT_CHG_IPSNS_EP_ACK,
};

struct igpp_hdr {
	uint8_t pdu_type;
	uint8_t data[0];
};

enum igpp_iei_type {
	// FIXME: Do we need this?
	IGPP_IE_TRANS_NO,
	IGPP_IE_ROLE,
	IGPP_IE_ROLE_NSE,
	IGPP_IE_NSEI,
	IGPP_IE_BVCI,
	IGPP_IE_CELL_ID,
	IGPP_IE_PDU,
	IGPP_IE_SNS_IP4,
	IGPP_IE_SNS_IP6,
	IGPP_IE_SNS_PORT,
	IGPP_IE_SNS_SIG_WEIGHT,
	IGPP_IE_SNS_DATA_WEIGHT,
	// TODO: BSSGP Features and Ext Features
};

/* TODO: Per NSE or per Server? */
enum igpp_role {
	IGPP_ROLE_NONE = 0x00,
	IGPP_ROLE_PRIMARY = 0x01,
	IGPP_ROLE_SECONDARY = 0x02,
};

enum igpp_role_nse {
	IGPP_ROLE_NSE_SGSN = 0x01,
	IGPP_ROLE_NSE_BSS = 0x02,
};

extern const struct osmo_tlv_prot_def osmo_pdef_igpp;

/*! the data structure stored in msgb->cb for libgb apps */
struct igpp_msgb_cb {
	struct igpp_hdr *igpph;
} __attribute__((packed, may_alias));

#define IGPP_MSGB_CB(__msgb)	((struct igpp_msgb_cb *)&((__msgb)->cb[0]))
#define msgb_igpph(__x)		IGPP_MSGB_CB(__x)->igpph
#define msgb_igpp_len(__x)	((__x)->tail - (uint8_t *)msgb_igpph(__x))



/* Config structs */

struct igpp_config {
	/* Pointer back to the gbproxy config */
	struct gbproxy_config * cfg;

	/* default role */
	enum igpp_role default_role;

	/* Remote peer info IP/port */
	struct {
		const char *host;
		uint16_t port;
	} peer;

	/* SCTP connection to the peer. default_role determines if it's
	 * client or server */
	struct {
		struct osmo_stream_srv_link *srv;
		struct osmo_stream_srv *sconn;
		struct osmo_stream_cli *cconn;
	} link;

	/* Global IGPP FSM */
	struct osmo_fsm_inst *fi;

	/* hash table of all IGPP NSEs */
	DECLARE_HASHTABLE(igpp_nses, 8);

	/* IGPP client/server connection (depending on the default_role) */
	struct osmo_stream_srv *srv_conn;
	struct osmo_stream_cli *cli_conn;
};

struct igpp_nse {
	struct igpp_config *igpp;
	uint16_t nsei;
	struct osmo_fsm_inst *fi;
};

int igpp_init_config(struct gbproxy_config *cfg);
int igpp_init_socket(void *ctx, struct igpp_config *igpp);

bool igpp_send(struct igpp_config *igpp, struct msgb *msg);

struct msgb *igpp_enc_reset();
struct msgb *igpp_enc_reset_ack();
struct msgb *igpp_enc_ping();
struct msgb *igpp_enc_pong();