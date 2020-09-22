/* Control Interface Implementation for the Gb-proxy */
/*
 * (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Daniel Willmann
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

#include <osmocom/core/talloc.h>


#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns.h>

#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/sgsn/gb_proxy.h>
#include <osmocom/sgsn/debug.h>

extern vector ctrl_node_vec;

static int ctrl_nsvc_state_cb(struct gprs_ns2_vc *nsvc, void *ctx) {
/* FIXME: Can't get NSVC state in ns2
	struct ctrl_cmd *cmd = (struct ctrl_cmd *)ctx;

	cmd->reply = gprs_ns2_vc_state_append(cmd->reply, nsvc);
*/
	return 0;
}

static int get_nsvc_state(struct ctrl_cmd *cmd, void *data)
{
	struct gbproxy_config *cfg = data;
	struct gprs_ns2_inst *nsi = cfg->nsi;
	struct gprs_ns2_nse *nse;
	struct gbproxy_peer *peer;

	cmd->reply = talloc_strdup(cmd, "");

	/* NS-VCs for SGSN */
	nse = gprs_ns2_nse_by_nsei(nsi, cfg->nsip_sgsn_nsei);
	if (nse)
		gprs_ns2_nse_foreach_nsvc(nse, &ctrl_nsvc_state_cb, cmd);
	/* NS-VCs for SGSN2 */
	nse = gprs_ns2_nse_by_nsei(nsi, cfg->nsip_sgsn2_nsei);
	if (nse)
		gprs_ns2_nse_foreach_nsvc(nse, &ctrl_nsvc_state_cb, cmd);

	/* NS-VCs for BSS peers */
	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		nse = gprs_ns2_nse_by_nsei(nsi, peer->nsei);
		if (nse)
			gprs_ns2_nse_foreach_nsvc(nse, &ctrl_nsvc_state_cb, cmd);
	}
	cmd->reply = "Getting NSVC state not yet implemented for NS2";
	return CTRL_CMD_ERROR;
}

CTRL_CMD_DEFINE_RO(nsvc_state, "nsvc-state");

static int get_gbproxy_state(struct ctrl_cmd *cmd, void *data)
{
	struct gbproxy_config *cfg = data;
	struct gbproxy_peer *peer;

	cmd->reply = talloc_strdup(cmd, "");

	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		struct gprs_ra_id raid;
		gsm48_parse_ra(&raid, peer->ra);

		cmd->reply = talloc_asprintf_append(cmd->reply, "%u,%u,%u,%u,%u,%u,%s\n",
				peer->nsei, peer->bvci,
				raid.mcc, raid.mnc,
				raid.lac, raid.rac,
				peer->blocked ? "BLOCKED" : "UNBLOCKED");
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(gbproxy_state, "gbproxy-state");

static int get_num_peers(struct ctrl_cmd *cmd, void *data)
{
	struct gbproxy_config *cfg = data;

	cmd->reply = talloc_strdup(cmd, "");
	cmd->reply = talloc_asprintf_append(cmd->reply, "%u", llist_count(&cfg->bts_peers));

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(num_peers, "number-of-peers");

int gb_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_nsvc_state);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_gbproxy_state);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_num_peers);

	return rc;
}
