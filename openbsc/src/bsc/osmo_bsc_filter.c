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
#include <openbsc/debug.h>

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
	}

	return 0;
}
