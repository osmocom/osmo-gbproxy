/* Ericsson RBS-2xxx specific code */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <sys/types.h>

#include <osmocore/tlv.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/e1_input.h>
#include <openbsc/signal.h>


static struct gsm_bts_model model_rbs2k = {
	.type = GSM_BTS_TYPE_RBS2000,
};

static void bootstrap_om_rbs2k(struct gsm_bts *bts)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for BTS %u\n", bts->nr);
	/* FIXME */
}

static int shutdown_om(struct gsm_bts *bts)
{
	/* FIXME */
	return 0;
}

/* Callback function to be called every time we receive a signal from INPUT */
static int gbl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts *bts;

	if (subsys != SS_GLOBAL)
		return 0;

	switch (signal) {
	case S_GLOBAL_BTS_CLOSE_OM:
		bts = signal_data;
		if (bts->type == GSM_BTS_TYPE_RBS2000)
			shutdown_om(signal_data);
		break;
	}

	return 0;
}

static void sabm_timer_cb(void *_line);

/* FIXME: we need one per bts, not one global! */
struct timer_list sabm_timer = {
	.cb = &sabm_timer_cb,
};

static void sabm_timer_cb(void *_line)
{
	struct e1inp_ts *e1i_ts = _line;

	lapd_send_sabm(e1i_ts->driver.dahdi.lapd, 62, 62);

	bsc_schedule_timer(&sabm_timer, 0, 50);
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;

	if (subsys != SS_INPUT)
		return 0;

	switch (signal) {
	case S_INP_TEI_UP:
		bsc_del_timer(&sabm_timer);
		switch (isd->link_type) {
		case E1INP_SIGN_OML:
			if (isd->trx->bts->type == GSM_BTS_TYPE_BS11)
				bootstrap_om_rbs2k(isd->trx->bts);
			break;
		}
		break;
	case S_INP_LINE_INIT:
		/* Right now Ericsson RBS are only supported on DAHDI */
		if (strcasecmp(isd->line->driver->name, "DAHDI"))
			break;
		sabm_timer.data = &isd->line->ts[1-1];
		bsc_schedule_timer(&sabm_timer, 0, 50);
		break;
	}

	return 0;
}

int bts_model_rbs2k_init(void)
{
	model_rbs2k.features.data = &model_rbs2k._features_data[0];
	model_rbs2k.features.data_len = sizeof(model_rbs2k._features_data);

	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HSCSD);

	register_signal_handler(SS_INPUT, inp_sig_cb, NULL);
	register_signal_handler(SS_GLOBAL, gbl_sig_cb, NULL);

	return gsm_bts_model_register(&model_rbs2k);
}
