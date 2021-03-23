#pragma once

#include <stdint.h>

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

#define IGPP_ROLE_SGSN	0x01
#define IGPP_ROLE_BSS	0x02

extern const struct osmo_tlv_prot_def osmo_pdef_igpp;

/*! the data structure stored in msgb->cb for libgb apps */
struct igpp_msgb_cb {
	unsigned char *igpph;
	unsigned char *bssgph;
} __attribute__((packed, may_alias));

#define IGPP_MSGB_CB(__msgb)	((struct igpp_msgb_cb *)&((__msgb)->cb[0]))
#define msgb_igpph(__x)	IGPP_MSGB_CB(__x)->igpph
#define msgb_bssgph(__x)	IGPP_MSGB_CB(__x)->bssgph
#define msgb_bssgp_len(__x)	((__x)->tail - (uint8_t *)msgb_bssgph(__x))