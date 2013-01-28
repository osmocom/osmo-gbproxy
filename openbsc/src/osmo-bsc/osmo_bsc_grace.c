/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/osmo_bsc_grace.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>

int bsc_grace_allow_new_connection(struct gsm_network *network, struct gsm_bts *bts)
{
	if (!network->bsc_data->rf_ctrl)
		return 1;
	if (bts->excl_from_rf_lock)
		return 1;
	return network->bsc_data->rf_ctrl->policy == S_RF_ON;
}

/**
 * Try to not page if everything the cell is not on.
 */
int bsc_grace_paging_request(struct gsm_subscriber *subscr, int chan_needed,
				struct osmo_msc_data *msc)
{
	struct gsm_bts *bts = NULL;

	if (!subscr->net->bsc_data->rf_ctrl)
		goto page;
	if (subscr->net->bsc_data->rf_ctrl->policy == S_RF_ON)
		goto page;

	/*
	 * Check if there is any BTS that is on for the given lac. Start
	 * with NULL and iterate through all bts.
	 */
	do {
		bts = gsm_bts_by_lac(subscr->net, subscr->lac, bts);
		if (!bts)
			break;

		/*
		 * continue if the BTS is not excluded from the lock
		 */
		if (!bts->excl_from_rf_lock)
			continue;

		/*
		 * now page on this bts
		 */
		paging_request_bts(bts, subscr, chan_needed, NULL, msc);
	} while (1);

	/* All bts are either off or in the grace period */
	return 0;
page:
	return paging_request(subscr->net, subscr, chan_needed, NULL, msc);
}

static int handle_sub(struct gsm_lchan *lchan, const char *text)
{
	struct gsm_subscriber_connection *conn;

	/* only send it to TCH */
	if (lchan->type != GSM_LCHAN_TCH_H && lchan->type != GSM_LCHAN_TCH_F)
		return -1;

	/* only send on the primary channel */
	conn = lchan->conn;
	if (!conn)
		return -1;

	if (conn->lchan != lchan)
		return -1;

	/* only when active */
	if (lchan->state != LCHAN_S_ACTIVE)
		return -1;

	gsm0480_send_ussdNotify(conn, 0, text);
	gsm0480_send_releaseComplete(conn);

	return 0;
}

/*
 * The place to handle the grace mode. Right now we will send
 * USSD messages to the subscriber, in the future we might start
 * a timer to have different modes for the grace period.
 */
static int handle_grace(struct gsm_network *network)
{
	int ts_nr, lchan_nr;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;

	if (!network->bsc_data->mid_call_txt)
		return 0;

	llist_for_each_entry(bts, &network->bts_list, list) {
		llist_for_each_entry(trx, &bts->trx_list, list) {
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ++ts_nr) {
				struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
				for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN; ++lchan_nr) {
					handle_sub(&ts->lchan[lchan_nr],
						   network->bsc_data->mid_call_txt);
				}
			}
		}
	}
	return 0;
}

static int handle_rf_signal(unsigned int subsys, unsigned int signal,
			    void *handler_data, void *signal_data)
{
	struct rf_signal_data *sig;

	if (subsys != SS_RF)
		return -1;

	sig = signal_data;

	if (signal == S_RF_GRACE)
		handle_grace(sig->net);

	return 0;
}

static __attribute__((constructor)) void on_dso_load_grace(void)
{
	osmo_signal_register_handler(SS_RF, handle_rf_signal, NULL);
}
