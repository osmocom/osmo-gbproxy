/* (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>

#include <stdlib.h>

static void handle_lu_request(struct gsm_subscriber_connection *conn,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_loc_upd_req *lu;
	struct gsm48_loc_area_id lai;
	struct gsm_network *net;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu)) {
		LOGP(DMSC, LOGL_ERROR, "LU too small to look at: %u\n", msgb_l3len(msg));
		return;
	}

	net = conn->bts->network;

	gh = msgb_l3(msg);
	lu = (struct gsm48_loc_upd_req *) gh->data;

	gsm48_generate_lai(&lai, net->country_code, net->network_code,
			   conn->bts->location_area_code);

	if (memcmp(&lai, &lu->lai, sizeof(lai)) != 0) {
		LOGP(DMSC, LOGL_DEBUG, "Marking con for welcome USSD.\n");
		conn->sccp_con->new_subscriber = 1;
	}
}

/* we will need to stop the paging request */
static int handle_page_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct gsm48_hdr *gh;
	struct gsm48_pag_resp *resp;
	struct gsm_subscriber *subscr;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*resp)) {
		LOGP(DMSC, LOGL_ERROR, "PagingResponse too small: %u\n", msgb_l3len(msg));
		return -1;
	}

	gh = msgb_l3(msg);
	resp = (struct gsm48_pag_resp *) &gh->data[0];

	gsm48_paging_extract_mi(resp, msgb_l3len(msg) - sizeof(*gh),
				mi_string, &mi_type);
	DEBUGP(DRR, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_active_by_tmsi(conn->bts->network,
					       tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_active_by_imsi(conn->bts->network, mi_string);
		break;
	}

	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Non active subscriber got paged.\n");
		return -1;
	}

	paging_request_stop(conn->bts, subscr, conn);
	subscr_put(subscr);
	return 0;
}

/**
 * This is used to scan a message for extra functionality of the BSC. This
 * includes scanning for location updating requests/acceptd and then send
 * a welcome USSD message to the subscriber.
 */
int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gh->proto_discr & 0x0f;
	uint8_t mtype = gh->msg_type & 0xbf;

	if (pdisc == GSM48_PDISC_MM) {
		if (mtype == GSM48_MT_MM_LOC_UPD_REQUEST)
			handle_lu_request(conn, msg);
	} else if (pdisc == GSM48_PDISC_RR) {
		if (mtype == GSM48_MT_RR_PAG_RESP)
			handle_page_resp(conn, msg);
	}

	return 0;
}

static void send_welcome_ussd(struct gsm_subscriber_connection *conn)
{
	struct gsm_network *net;
	net = conn->bts->network;

	if (!net->msc_data->ussd_welcome_txt)
		return;

	gsm0480_send_ussdNotify(conn, 1, net->msc_data->ussd_welcome_txt);
	gsm0480_send_releaseComplete(conn);
}

/**
 * Messages coming back from the MSC.
 */
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm_network *net;
	struct gsm48_loc_area_id *lai;
	struct gsm48_hdr *gh;
	uint8_t mtype;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	gh = (struct gsm48_hdr *) msgb_l3(msg);
	mtype = gh->msg_type & 0xbf;
	net = conn->bts->network;

	if (mtype == GSM48_MT_MM_LOC_UPD_ACCEPT) {
		if (net->msc_data->core_ncc != -1 ||
		    net->msc_data->core_mcc != -1) {
			if (msgb_l3len(msg) >= sizeof(*gh) + sizeof(*lai)) {
				lai = (struct gsm48_loc_area_id *) &gh->data[0];
				gsm48_generate_lai(lai, net->country_code,
						   net->network_code,
						   conn->bts->location_area_code);
			}
		}

		if (conn->sccp_con->new_subscriber)
			send_welcome_ussd(conn);
	}

	return 0;
}
