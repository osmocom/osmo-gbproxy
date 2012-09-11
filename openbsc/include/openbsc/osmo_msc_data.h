/*
 * Data for the true BSC
 *
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
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

#ifndef _OSMO_MSC_DATA_H
#define _OSMO_MSC_DATA_H

#include "bsc_msc.h"

#include <osmocom/core/timer.h>

struct osmo_bsc_rf;
struct gsm_network;

struct gsm_audio_support {
        uint8_t hr  : 1,
                ver : 7;
};

enum {
	MSC_CON_TYPE_NORMAL,
	MSC_CON_TYPE_LOCAL,
};

struct osmo_msc_data {
	struct llist_head entry;

	/* Back pointer */
	struct gsm_network *network;

	int allow_emerg;
	int type;

	/* Connection data */
	char *bsc_token;
	int ping_timeout;
	int pong_timeout;
	struct osmo_timer_list ping_timer;
	struct osmo_timer_list pong_timer;
	struct bsc_msc_connection *msc_con;
	int core_ncc;
	int core_mcc;
	int rtp_base;

	/* audio codecs */
	struct gsm_audio_support **audio_support;
	int audio_length;

	/* destinations */
	struct llist_head dests;

	/* ussd welcome text */
	char *ussd_welcome_txt;

	/* mgcp agent */
	struct osmo_wqueue mgcp_agent;

	int nr;
};

/*
 * Per BSC data.
 */
struct osmo_bsc_data {
	struct gsm_network *network;

	/* msc configuration */
	struct llist_head mscs;

	/* rf ctl related bits */
	char *mid_call_txt;
	int mid_call_timeout;
	char *rf_ctrl_name;
	struct osmo_bsc_rf *rf_ctrl;
};


int osmo_bsc_msc_init(struct osmo_msc_data *msc);
int osmo_bsc_sccp_init(struct gsm_network *gsmnet);
int msc_queue_write(struct bsc_msc_connection *conn, struct msgb *msg, int proto);

int osmo_bsc_audio_init(struct gsm_network *network);

struct osmo_msc_data *osmo_msc_data_find(struct gsm_network *, int);
struct osmo_msc_data *osmo_msc_data_alloc(struct gsm_network *, int);


#endif
