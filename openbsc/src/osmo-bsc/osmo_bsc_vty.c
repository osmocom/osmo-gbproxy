/* Osmo BSC VTY Configuration */
/* (C) 2009-2011 by Holger Hans Peter Freyther
 * (C) 2009-2011 by On-Waves
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

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/vty.h>

#include <osmocom/core/talloc.h>


#define IPA_STR "IP.ACCESS specific\n"

extern struct gsm_network *bsc_gsmnet;

static struct osmo_bsc_data *osmo_bsc_data(struct vty *vty)
{
	return bsc_gsmnet->bsc_data;
}

static struct osmo_msc_data *osmo_msc_data(struct vty *vty)
{
	return osmo_msc_data_find(bsc_gsmnet, (int) vty->index);
}

static struct cmd_node bsc_node = {
	BSC_NODE,
	"%s(bsc)#",
	1,
};

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

DEFUN(cfg_net_msc, cfg_net_msc_cmd,
      "msc [<0-1000>]", "Configure MSC details\n" "MSC connection to configure\n")
{
	int index = argc == 1 ? atoi(argv[0]) : 0;
	struct osmo_msc_data *msc;

	msc = osmo_msc_data_alloc(bsc_gsmnet, index);
	if (!msc) {
		vty_out(vty, "%%Failed to allocate MSC data.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = (void *) index;
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc, cfg_net_bsc_cmd,
      "bsc", "Configure BSC\n")
{
	vty->node = BSC_NODE;
	return CMD_SUCCESS;
}

static void write_msc(struct vty *vty, struct osmo_msc_data *msc)
{
	struct bsc_msc_dest *dest;

	vty_out(vty, "msc %d%s", msc->nr, VTY_NEWLINE);
	if (msc->bsc_token)
		vty_out(vty, " token %s%s", msc->bsc_token, VTY_NEWLINE);
	if (msc->core_ncc != -1)
		vty_out(vty, " core-mobile-network-code %d%s",
			msc->core_ncc, VTY_NEWLINE);
	if (msc->core_mcc != -1)
		vty_out(vty, " core-mobile-country-code %d%s",
			msc->core_mcc, VTY_NEWLINE);
	vty_out(vty, " ip.access rtp-base %d%s", msc->rtp_base, VTY_NEWLINE);
	vty_out(vty, " timeout-ping %d%s", msc->ping_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout-pong %d%s", msc->pong_timeout, VTY_NEWLINE);
	if (msc->ussd_welcome_txt)
		vty_out(vty, " bsc-welcome-text %s%s", msc->ussd_welcome_txt, VTY_NEWLINE);

	if (msc->audio_length != 0) {
		int i;

		vty_out(vty, " codec-list ");
		for (i = 0; i < msc->audio_length; ++i) {
			if (i != 0)
				vty_out(vty, ", ");

			if (msc->audio_support[i]->hr)
				vty_out(vty, "hr%.1u", msc->audio_support[i]->ver);
			else
				vty_out(vty, "fr%.1u", msc->audio_support[i]->ver);
		}
		vty_out(vty, "%s", VTY_NEWLINE);

	}

	llist_for_each_entry(dest, &msc->dests, list)
		vty_out(vty, " dest %s %d %d%s", dest->ip, dest->port,
			dest->dscp, VTY_NEWLINE);

	vty_out(vty, " type %s%s", msc->type == MSC_CON_TYPE_NORMAL ?
					"normal" : "local", VTY_NEWLINE);
	vty_out(vty, " allow-emergency %s%s", msc->allow_emerg ?
					"allow" : "deny", VTY_NEWLINE);
}

static int config_write_msc(struct vty *vty)
{
	struct osmo_msc_data *msc;
	struct osmo_bsc_data *bsc = osmo_bsc_data(vty);

	llist_for_each_entry(msc, &bsc->mscs, entry)
		write_msc(vty, msc);

	return CMD_SUCCESS;
}

static int config_write_bsc(struct vty *vty)
{
	struct osmo_bsc_data *bsc = osmo_bsc_data(vty);

	vty_out(vty, "bsc%s", VTY_NEWLINE);
	if (bsc->mid_call_txt)
		vty_out(vty, " mid-call-text %s%s", bsc->mid_call_txt, VTY_NEWLINE);
	vty_out(vty, " mid-call-timeout %d%s", bsc->mid_call_timeout, VTY_NEWLINE);
	if (bsc->rf_ctrl_name)
		vty_out(vty, " bsc-rf-socket %s%s",
			bsc->rf_ctrl_name, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_token,
      cfg_net_bsc_token_cmd,
      "token TOKEN",
      "A token for the BSC to be sent to the MSC")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	bsc_replace_string(osmo_bsc_data(vty), &data->bsc_token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_ncc,
      cfg_net_bsc_ncc_cmd,
      "core-mobile-network-code <1-999>",
      "Use this network code for the backbone\n" "NCC value\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->core_ncc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mcc,
      cfg_net_bsc_mcc_cmd,
      "core-mobile-country-code <1-999>",
      "Use this country code for the backbone\n" "MCC value\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->core_mcc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_rtp_base,
      cfg_net_bsc_rtp_base_cmd,
      "ip.access rtp-base <1-65000>",
      IPA_STR
      "Set the rtp-base port for the RTP stream\n"
      "Port number\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->rtp_base = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_codec_list,
      cfg_net_bsc_codec_list_cmd,
      "codec-list .LIST",
      "Set the allowed audio codecs\n"
      "List of audio codecs\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	int saw_fr, saw_hr;
	int i;

	saw_fr = saw_hr = 0;

	/* free the old list... if it exists */
	if (data->audio_support) {
		talloc_free(data->audio_support);
		data->audio_support = NULL;
		data->audio_length = 0;
	}

	/* create a new array */
	data->audio_support =
		talloc_zero_array(osmo_bsc_data(vty), struct gsm_audio_support *, argc);
	data->audio_length = argc;

	for (i = 0; i < argc; ++i) {
		/* check for hrX or frX */
		if (strlen(argv[i]) != 3
				|| argv[i][1] != 'r'
				|| (argv[i][0] != 'h' && argv[i][0] != 'f')
				|| argv[i][2] < 0x30
				|| argv[i][2] > 0x39)
			goto error;

		data->audio_support[i] = talloc_zero(data->audio_support,
				struct gsm_audio_support);
		data->audio_support[i]->ver = atoi(argv[i] + 2);

		if (strncmp("hr", argv[i], 2) == 0) {
			data->audio_support[i]->hr = 1;
			saw_hr = 1;
		} else if (strncmp("fr", argv[i], 2) == 0) {
			data->audio_support[i]->hr = 0;
			saw_fr = 1;
		}

		if (saw_hr && saw_fr) {
			vty_out(vty, "Can not have full-rate and half-rate codec.%s",
					VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	return CMD_SUCCESS;

error:
	vty_out(vty, "Codec name must be hrX or frX. Was '%s'%s",
			argv[i], VTY_NEWLINE);
	return CMD_ERR_INCOMPLETE;
}

DEFUN(cfg_net_msc_dest,
      cfg_net_msc_dest_cmd,
      "dest A.B.C.D <1-65000> <0-255>",
      "Add a destination to a MUX/MSC\n"
      "IP Address\n" "Port\n" "DSCP\n")
{
	struct bsc_msc_dest *dest;
	struct osmo_msc_data *data = osmo_msc_data(vty);

	dest = talloc_zero(osmo_bsc_data(vty), struct bsc_msc_dest);
	if (!dest) {
		vty_out(vty, "%%Failed to create structure.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	dest->ip = talloc_strdup(dest, argv[0]);
	if (!dest->ip) {
		vty_out(vty, "%%Failed to copy dest ip.%s", VTY_NEWLINE);
		talloc_free(dest);
		return CMD_WARNING;
	}

	dest->port = atoi(argv[1]);
	dest->dscp = atoi(argv[2]);
	llist_add_tail(&dest->list, &data->dests);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_no_dest,
      cfg_net_msc_no_dest_cmd,
      "no dest A.B.C.D <1-65000> <0-255>",
      NO_STR "Remove a destination to a MUX/MSC\n"
      "IP Address\n" "Port\n" "DSCP\n")
{
	struct bsc_msc_dest *dest, *tmp;
	struct osmo_msc_data *data = osmo_msc_data(vty);

	int port = atoi(argv[1]);
	int dscp = atoi(argv[2]);

	llist_for_each_entry_safe(dest, tmp, &data->dests, list) {
		if (port != dest->port || dscp != dest->dscp
		    || strcmp(dest->ip, argv[0]) != 0)
			continue;

		llist_del(&dest->list);
		talloc_free(dest);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_ping_time,
      cfg_net_msc_ping_time_cmd,
      "timeout-ping NR",
      "Set the PING interval, negative for not sending PING")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->ping_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_pong_time,
      cfg_net_msc_pong_time_cmd,
      "timeout-pong NR",
      "Set the time to wait for a PONG.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->pong_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_welcome_ussd,
      cfg_net_msc_welcome_ussd_cmd,
      "bsc-welcome-text .TEXT",
      "Set the USSD notification to be sent.\n" "Text to be sent\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	char *str = argv_concat(argv, argc, 0);
	if (!str)
		return CMD_WARNING;

	bsc_replace_string(osmo_bsc_data(vty), &data->ussd_welcome_txt, str);
	talloc_free(str);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_type,
      cfg_net_msc_type_cmd,
      "type (normal|local)",
      "Select the MSC type\n"
      "Plain GSM MSC\n" "Special MSC for local call routing\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	if (strcmp(argv[0], "normal") == 0)
		data->type = MSC_CON_TYPE_NORMAL;
	else if (strcmp(argv[0], "local") == 0)
		data->type = MSC_CON_TYPE_LOCAL;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_emerg,
      cfg_net_msc_emerg_cmd,
      "allow-emergency (allow|deny)",
      "Allow CM ServiceRequests with type emergency\n"
      "Allow\n" "Deny\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->allow_emerg = strcmp("allow", argv[0]) == 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mid_call_text,
      cfg_net_bsc_mid_call_text_cmd,
      "mid-call-text .TEXT",
      "Set the USSD notifcation to be send.\n" "Text to be sent\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	bsc_replace_string(data, &data->mid_call_txt, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mid_call_timeout,
      cfg_net_bsc_mid_call_timeout_cmd,
      "mid-call-timeout NR",
      "Switch from Grace to Off in NR seconds.\n" "Timeout in seconds\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	data->mid_call_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_rf_socket,
      cfg_net_rf_socket_cmd,
      "bsc-rf-socket PATH",
      "Set the filename for the RF control interface.\n" "RF Control path\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);

	bsc_replace_string(data, &data->rf_ctrl_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(show_statistics,
      show_statistics_cmd,
      "show statistics",
      SHOW_STR "Statistics about the BSC\n")
{
	openbsc_vty_print_statistics(vty, bsc_gsmnet);
	return CMD_SUCCESS;
}

DEFUN(show_mscs,
      show_mscs_cmd,
      "show mscs",
      SHOW_STR "MSC Connections and State\n")
{
	struct osmo_msc_data *msc;
	llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry) {
		vty_out(vty, "MSC Nr: %d is connected: %d auth: %d.%s",
			msc->nr,
			msc->msc_con ? msc->msc_con->is_connected : -1,
			msc->msc_con ? msc->msc_con->is_authenticated : -1,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

int bsc_vty_init_extra(void)
{
	install_element(CONFIG_NODE, &cfg_net_msc_cmd);
	install_element(CONFIG_NODE, &cfg_net_bsc_cmd);

	install_node(&bsc_node, config_write_bsc);
	install_default(BSC_NODE);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_text_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_timeout_cmd);
	install_element(BSC_NODE, &cfg_net_rf_socket_cmd);



	install_node(&msc_node, config_write_msc);
	install_default(MSC_NODE);
	install_element(MSC_NODE, &cfg_net_bsc_token_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_ncc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_mcc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_rtp_base_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_codec_list_cmd);
	install_element(MSC_NODE, &cfg_net_msc_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_pong_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_type_cmd);
	install_element(MSC_NODE, &cfg_net_msc_emerg_cmd);

	install_element_ve(&show_statistics_cmd);
	install_element_ve(&show_mscs_cmd);

	return 0;
}
