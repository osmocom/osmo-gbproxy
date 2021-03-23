#include "osmocom/core/byteswap.h"
#include <osmocom/gbproxy/gb_proxy_igpp.h>
#include <osmocom/gbproxy/gb_proxy.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/tlv.h>

static const uint8_t ping_ies[] = {};
static const uint8_t pong_ies[] = {};
static const uint8_t reset_ies[] = {};
static const uint8_t reset_ack_ies[] = {};
static const uint8_t promote_ies[] = { IGPP_IE_NSEI };
static const uint8_t promote_ack_ies[] = { IGPP_IE_NSEI };
static const uint8_t demote_ies[] = { IGPP_IE_NSEI };
static const uint8_t demote_ack_ies[] = { IGPP_IE_NSEI };
static const uint8_t create_bvc_ies[] = { IGPP_IE_ROLE, IGPP_IE_NSEI, IGPP_IE_BVCI, IGPP_IE_CELL_ID};
static const uint8_t create_bvc_ack_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t delete_bvc_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t delete_bvc_ack_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t block_bvc_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t block_bvc_ack_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t unblock_bvc_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t unblock_bvc_ack_ies[] = { IGPP_IE_NSEI, IGPP_IE_BVCI };
static const uint8_t forward_ies[] = { IGPP_IE_NSEI, IGPP_IE_PDU };
static const uint8_t forward_ack_ies[] = { IGPP_IE_NSEI };
static const uint8_t ipsns_ep_ies[] = { IGPP_IE_SNS_IP4, IGPP_IE_SNS_PORT, IGPP_IE_SNS_SIG_WEIGHT,
					IGPP_IE_SNS_DATA_WEIGHT };
static const uint8_t ipsns_ep_ack_ies[] = {};

const struct osmo_tlv_prot_def osmo_pdef_igpp = {
	.name = "IGPP",
	.tlv_def = &tvlv_att_def,
	.msg_def = {
		[IGPP_PDUT_PING] = MSG_DEF("PING", ping_ies, 0),
		[IGPP_PDUT_PONG] = MSG_DEF("PONG", pong_ies, 0),

		[IGPP_PDUT_RESET] = MSG_DEF("RESET", reset_ies, 0),
		[IGPP_PDUT_RESET_ACK] = MSG_DEF("RESET-ACK", reset_ack_ies, 0),

		[IGPP_PDUT_PROMOTE] = MSG_DEF("PROMOTE", promote_ies, 0),
		[IGPP_PDUT_PROMOTE_ACK] = MSG_DEF("PROMOTE-ACK", promote_ack_ies, 0),
		[IGPP_PDUT_DEMOTE] = MSG_DEF("DEMOTE", demote_ies, 0),
		[IGPP_PDUT_DEMOTE_ACK] = MSG_DEF("DEMOTE-ACK", demote_ack_ies, 0),

		[IGPP_PDUT_CREATE_BVC] = MSG_DEF("CREATE-BVC", create_bvc_ies, 0),
		[IGPP_PDUT_CREATE_BVC_ACK] = MSG_DEF("CREATE-BVC-ACK", create_bvc_ack_ies, 0),
		[IGPP_PDUT_DELETE_BVC] = MSG_DEF("DELETE-BVC", delete_bvc_ies, 0),
		[IGPP_PDUT_DELETE_BVC_ACK] = MSG_DEF("DELETE-BVC-ACK", delete_bvc_ack_ies, 0),

		[IGPP_PDUT_BLOCK_BVC] = MSG_DEF("BLOCK", block_bvc_ies, 0),
		[IGPP_PDUT_BLOCK_BVC_ACK] = MSG_DEF("BLOCK-ACK", block_bvc_ack_ies, 0),

		[IGPP_PDUT_UNBLOCK_BVC] = MSG_DEF("UNBLOCK", unblock_bvc_ies, 0),
		[IGPP_PDUT_UNBLOCK_BVC_ACK] = MSG_DEF("UNBLOCK-ACK", unblock_bvc_ack_ies, 0),

		/* Forwarding of BSSGP-signalling data to primary */
		[IGPP_PDUT_FORWARD] = MSG_DEF("FORWARD", forward_ies, 0),
		[IGPP_PDUT_FORWARD_ACK] = MSG_DEF("FORWARD-ACK",forward_ack_ies, 0),

		/* IP-SNS state */
		[IGPP_PDUT_ADD_IPSNS_EP] = MSG_DEF("ADD_IPSNS_EP", ipsns_ep_ies, 0),
		[IGPP_PDUT_ADD_IPSNS_EP_ACK] = MSG_DEF("ADD_IPSNS_EP_ACK", ipsns_ep_ack_ies, 0),
		[IGPP_PDUT_DEL_IPSNS_EP] = MSG_DEF("DEL_IPSNS_EP", ipsns_ep_ies, 0),
		[IGPP_PDUT_DEL_IPSNS_EP_ACK] = MSG_DEF("DEL_IPSNS_EP_ACK", ipsns_ep_ack_ies, 0),
		[IGPP_PDUT_CHG_IPSNS_EP] = MSG_DEF("CHG_IPSNS_EP", ipsns_ep_ies, 0),
		[IGPP_PDUT_CHG_IPSNS_EP_ACK] = MSG_DEF("CHG_IPSNS_EP_ACK", ipsns_ep_ack_ies, 0),
	},
	.ie_def = {
		[IGPP_IE_TRANS_NO] = { 2, "Transaction no." },
		[IGPP_IE_ROLE] = { 1, "Role" },
		[IGPP_IE_NSEI] = { 2, "NSEI" },
		[IGPP_IE_BVCI] = { 2, "BVCI" },
		[IGPP_IE_CELL_ID] = { 8, "Cell Identifier" },
		[IGPP_IE_PDU] = { 0, "BSSGP PDU" },
		[IGPP_IE_SNS_IP4] = { 0, "SNS IPv4" },
		[IGPP_IE_SNS_IP6] = { 0, "SNS IPv6" },
		[IGPP_IE_SNS_PORT] = { 0, "SNS Port" },
		[IGPP_IE_SNS_SIG_WEIGHT] = { 0, "SNS Signalling Weight" },
		[IGPP_IE_SNS_DATA_WEIGHT] = { 0, "SNS Data Weight" },
	}
};

struct msgb *igpp_msgb_alloc()
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "IGPP");

	OSMO_ASSERT(msg != NULL);

	msgb_igpph(msg) = msg->data;
	return msg;
}

inline struct msgb *igpp_msgb_enc_simple(enum igpp_pdu_type pdut)
{
	struct msgb *msg = igpp_msgb_alloc();
	struct igpp_hdr *igpph;

	if (!msg)
		return NULL;

	igpph = (struct igpp_hdr *)msgb_put(msg, sizeof(*igpph));
	igpph->pdu_type = pdut;

	return msg;
}

static inline struct msgb *igpp_enc_nsei_bvci_type(enum igpp_pdu_type pdut, uint16_t nsei, uint16_t bvci)
{
	uint16_t _nsei = osmo_htons(nsei);
	uint16_t _bvci = osmo_htons(bvci);

	struct msgb *msg = igpp_msgb_enc_simple(pdut);
	if (!msg)
		return NULL;

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *)&_nsei);
	msgb_tvlv_put(msg, IGPP_IE_BVCI, 2, (uint8_t *)&_bvci);

	return msg;
}

struct msgb *igpp_enc_ping()
{
	return igpp_msgb_enc_simple(IGPP_PDUT_PING);
}

struct msgb *igpp_enc_pong()
{
	return igpp_msgb_enc_simple(IGPP_PDUT_PONG);
}

struct msgb *igpp_enc_reset()
{
	return igpp_msgb_enc_simple(IGPP_PDUT_RESET);
}

struct msgb *igpp_enc_reset_ack()
{
	return igpp_msgb_enc_simple(IGPP_PDUT_RESET_ACK);
}

struct msgb *igpp_enc_promote(uint16_t nsei)
{
	uint16_t _nsei = osmo_htons(nsei);
	struct msgb *msg = igpp_msgb_enc_simple(IGPP_PDUT_PROMOTE);
	if (!msg)
		return NULL;

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *) &_nsei);

	return msg;
}

struct msgb *igpp_enc_promote_ack(uint16_t nsei)
{
	uint16_t _nsei = osmo_htons(nsei);
	struct msgb *msg = igpp_msgb_enc_simple(IGPP_PDUT_PROMOTE_ACK);
	if (!msg)
		return NULL;

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *) &_nsei);

	return msg;
}

struct msgb *igpp_enc_demote(uint16_t nsei)
{
	uint16_t _nsei = osmo_htons(nsei);
	struct msgb *msg = igpp_msgb_enc_simple(IGPP_PDUT_DEMOTE);
	if (!msg)
		return NULL;

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *) &_nsei);

	return msg;
}

struct msgb *igpp_enc_demote_ack(uint16_t nsei)
{
	uint16_t _nsei = osmo_htons(nsei);
	struct msgb *msg = igpp_msgb_enc_simple(IGPP_PDUT_DEMOTE_ACK);
	if (!msg)
		return NULL;

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *) &_nsei);

	return msg;
}

/** Encode a CREATE-BVC message
  * \param[in] nsei
  * \param[in] role
  * \param[in] bvci
  * \param[in] ra_id
  * \param[in] cell_id
  * \returns The encoded message or NULL on error
  */
struct msgb *igpp_enc_create_bvc(uint16_t nsei, uint8_t role, uint16_t bvci,
				 const struct gprs_ra_id *ra_id, uint16_t cell_id)
{
	OSMO_ASSERT(ra_id);

	uint16_t _nsei = osmo_htons(nsei);
	uint16_t _bvci = osmo_htons(bvci);
	uint8_t bssgp_cid[8];

	struct msgb *msg = igpp_msgb_enc_simple(IGPP_PDUT_CREATE_BVC);
	if (!msg)
		return NULL;

	bssgp_create_cell_id(bssgp_cid, ra_id, cell_id);

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *) &_nsei);
	msgb_tvlv_put(msg, IGPP_IE_ROLE, 1, (uint8_t *) &role);
	msgb_tvlv_put(msg, IGPP_IE_BVCI, 2, (uint8_t *) &_bvci);
	msgb_tvlv_put(msg, IGPP_IE_CELL_ID, 8, (uint8_t *) &bssgp_cid);

	return msg;
}

struct msgb *igpp_enc_create_bvc_ack(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_CREATE_BVC_ACK, nsei, bvci);
}

/** Encode a DELETE-BVC message
  * \param[in] nsei
  * \param[in] role
  * \param[in] bvci
  * \param[in] ra_id
  * \param[in] cell_id
  * \returns The encoded message or NULL on error
  */
struct msgb *igpp_enc_delete_bvc(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_DELETE_BVC, nsei, bvci);
}

struct msgb *igpp_enc_delete_bvc_ack(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_DELETE_BVC_ACK, nsei, bvci);
}

struct msgb *igpp_enc_block_bvc(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_BLOCK_BVC, nsei, bvci);
}

struct msgb *igpp_enc_block_bvc_ack(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_BLOCK_BVC_ACK, nsei, bvci);
}

struct msgb *igpp_enc_unblock_bvc(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_UNBLOCK_BVC, nsei, bvci);
}

struct msgb *igpp_enc_unblock_bvc_ack(uint16_t nsei, uint16_t bvci)
{
	return igpp_enc_nsei_bvci_type(IGPP_PDUT_UNBLOCK_BVC_ACK, nsei, bvci);
}

struct msgb *igpp_enc_forward(uint16_t nsei, struct msgb *pdu)
{
	//TODO: msgb_copy
	return NULL;
}

struct msgb *igpp_enc_forward_ack(uint16_t nsei)
{
	uint16_t _nsei = osmo_htons(nsei);
	struct msgb *msg = igpp_msgb_enc_simple(IGPP_PDUT_FORWARD_ACK);
	if (!msg)
		return NULL;

	msgb_tvlv_put(msg, IGPP_IE_NSEI, 2, (uint8_t *) &_nsei);

	return msg;
}
