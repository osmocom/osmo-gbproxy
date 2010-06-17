/* main MSC management code... */

/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On Waves
 *
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

#include <openbsc/bsc_api.h>
#include <openbsc/debug.h>

#include <openbsc/gsm_04_11.h>

static void msc_sapi_n_reject(struct gsm_subscriber_connection* conn, int dlci)
{
	int sapi = dlci & 0x7;

	if (sapi == UM_SAPI_SMS)
		gsm411_sapi_n_reject(conn);
}

static void msc_clear_request(struct gsm_subscriber_connection* conn, uint32_t cause)
{
	gsm0408_clear_request(conn, cause);
}

static int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	gsm0408_dispatch(conn, msg);

	/* TODO: do better */
	return BSC_API_CONN_POL_ACCEPT;
}

static void msc_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	gsm0408_dispatch(conn, msg);
}

static struct bsc_api msc_handler = {
	.sapi_n_reject = msc_sapi_n_reject,
	.clear_request = msc_clear_request,
	.compl_l3 = msc_compl_l3,
	.dtap  = msc_dtap,
};

struct bsc_api *msc_bsc_api() {
	return &msc_handler;
}
