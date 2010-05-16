/* OpenBSC logging helper for the VTY */
/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther
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

#include <stdlib.h>
#include <string.h>

#include <osmocore/talloc.h>

#include <openbsc/vty.h>
#include <openbsc/telnet_interface.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

static void _vty_output(struct log_target *tgt, const char *line)
{
	struct vty *vty = tgt->tgt_vty.vty;
	vty_out(vty, "%s", line);
	/* This is an ugly hack, but there is no easy way... */
	if (strchr(line, '\n'))
		vty_out(vty, "\r");
}

struct log_target *log_target_create_vty(struct vty *vty)
{
	struct log_target *target;

	target = log_target_create();
	if (!target)
		return NULL;

	target->tgt_vty.vty = vty;
	target->output = _vty_output;
	return target;
}

/* Down vty node level. */
gDEFUN(ournode_exit,
       ournode_exit_cmd, "exit", "Exit current mode and down to previous mode\n")
{
	switch (vty->node) {
	case GSMNET_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case BTS_NODE:
		vty->node = GSMNET_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts *bts = vty->index;
			vty->index = bts->network;
			vty->index_sub = NULL;
		}
		break;
	case TRX_NODE:
		vty->node = BTS_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx *trx = vty->index;
			vty->index = trx->bts;
			vty->index_sub = &trx->bts->description;
		}
		break;
	case TS_NODE:
		vty->node = TRX_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx_ts *ts = vty->index;
			vty->index = ts->trx;
			vty->index_sub = &ts->trx->description;
		}
		break;
	case MGCP_NODE:
	case GBPROXY_NODE:
	case SGSN_NODE:
	case NS_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	default:
		break;
	}
	return CMD_SUCCESS;
}

/* End of configuration. */
gDEFUN(ournode_end,
       ournode_end_cmd, "end", "End current mode and change to enable mode.")
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	case CONFIG_NODE:
	case GSMNET_NODE:
	case BTS_NODE:
	case TRX_NODE:
	case TS_NODE:
	case MGCP_NODE:
	case GBPROXY_NODE:
	case SGSN_NODE:
	case NS_NODE:
	case VTY_NODE:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	default:
		break;
	}
	return CMD_SUCCESS;
}

DEFUN(enable_logging,
      enable_logging_cmd,
      "logging enable",
	LOGGING_STR
      "Enables logging to this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (conn->dbg) {
		vty_out(vty, "Logging already enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn->dbg = log_target_create_vty(vty);
	if (!conn->dbg)
		return CMD_WARNING;

	log_add_target(conn->dbg);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_imsi_filter(conn->dbg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_all,
      logging_fltr_all_cmd,
      "logging filter all (0|1)",
	LOGGING_STR FILTER_STR
	"Do you want to log all messages?\n"
	"Only print messages matched by other filters\n"
	"Bypass filter and print all messages\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_all_filter(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(logging_use_clr,
      logging_use_clr_cmd,
      "logging color (0|1)",
	LOGGING_STR "Configure color-printing for log messages\n"
      "Don't use color for printing messages\n"
      "Use color for printing messages\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_use_color(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(logging_prnt_timestamp,
      logging_prnt_timestamp_cmd,
      "logging timestamp (0|1)",
	LOGGING_STR "Configure log message timestamping\n"
	"Don't prefix each log message\n"
	"Prefix each log message with current timestamp\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_print_timestamp(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

/* FIXME: those have to be kept in sync with the log levels and categories */
#define VTY_DEBUG_CATEGORIES "(rll|cc|mm|rr|rsl|nm|sms|pag|mncc|inp|mi|mib|mux|meas|sccp|msc|mgcp|ho|db|ref|gprs|ns|bssgp|llc|sndcp|all)"
#define CATEGORIES_HELP	\
	"A-bis Radio Link Layer (RLL)\n"			\
	"Layer3 Call Control (CC)\n"				\
	"Layer3 Mobility Management (MM)\n"			\
	"Layer3 Radio Resource (RR)\n"				\
	"A-bis Radio Signalling Link (RSL)\n"			\
	"A-bis Network Management / O&M (NM/OML)\n"		\
	"Layer3 Short Messagaging Service (SMS)\n"		\
	"Paging Subsystem\n"					\
	"MNCC API for Call Control application\n"		\
	"A-bis Input Subsystem\n"				\
	"A-bis Input Driver for Signalling\n"			\
	"A-bis Input Driver for B-Channel (voice data)\n"	\
	"A-bis B-Channel / Sub-channel Multiplexer\n"		\
	"Radio Measurements\n"					\
	"SCCP\n"						\
	"Mobile Switching Center\n"				\
	"Media Gateway Control Protocol\n"			\
	"Hand-over\n"						\
	"Database Layer\n"					\
	"Reference Counting\n"					\
	"GPRS Core\n"						\
	"GPRS Network Service (NS)\n"				\
	"GPRS BSS Gateway Protocol (BSSGP)\n"			\
	"GPRS Logical Link Control Protocol (LLC)\n"		\
	"GPRS Sub-Network Dependent Control Protocol (SNDCP)\n"	\
	"Global setting for all subsytems\n"

#define VTY_DEBUG_LEVELS "(everything|debug|info|notice|error|fatal)"
#define LEVELS_HELP	\
	"Log simply everything\n"				\
	"Log debug messages and higher levels\n"		\
	"Log informational messages and higher levels\n"	\
	"Log noticable messages and higher levels\n"		\
	"Log error messages and higher levels\n"		\
	"Log only fatal messages\n"
DEFUN(logging_level,
      logging_level_cmd,
      "logging level " VTY_DEBUG_CATEGORIES " " VTY_DEBUG_LEVELS,
      LOGGING_STR
      "Set the log level for a specified category\n"
      CATEGORIES_HELP
      LEVELS_HELP)
{
	struct telnet_connection *conn;
	int category = log_parse_category(argv[0]);
	int level = log_parse_level(argv[1]);

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (level < 0) {
		vty_out(vty, "Invalid level `%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Check for special case where we want to set global log level */
	if (!strcmp(argv[0], "all")) {
		log_set_log_level(conn->dbg, level);
		return CMD_SUCCESS;
	}

	if (category < 0) {
		vty_out(vty, "Invalid category `%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn->dbg->categories[category].enabled = 1;
	conn->dbg->categories[category].loglevel = level;

	return CMD_SUCCESS;
}

DEFUN(logging_set_category_mask,
      logging_set_category_mask_cmd,
      "logging set log mask MASK",
	LOGGING_STR
      "Decide which categories to output.\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_parse_category_mask(conn->dbg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(diable_logging,
      disable_logging_cmd,
      "logging disable",
	LOGGING_STR
      "Disables logging to this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_del_target(conn->dbg);
	talloc_free(conn->dbg);
	conn->dbg = NULL;
	return CMD_SUCCESS;
}

static void vty_print_logtarget(struct vty *vty, const struct log_info *info,
				const struct log_target *tgt)
{
	unsigned int i;

	vty_out(vty, " Global Loglevel: %s%s",
		log_level_str(tgt->loglevel), VTY_NEWLINE);
	vty_out(vty, " Use color: %s, Print Timestamp: %s%s",
		tgt->use_color ? "On" : "Off",
		tgt->print_timestamp ? "On" : "Off", VTY_NEWLINE);

	vty_out(vty, " Log Level specific information:%s", VTY_NEWLINE);

	for (i = 0; i < info->num_cat; i++) {
		const struct log_category *cat = &tgt->categories[i];
		vty_out(vty, "  %-10s %-10s %-8s %s%s",
			info->cat[i].name+1, log_level_str(cat->loglevel),
			cat->enabled ? "Enabled" : "Disabled",
 			info->cat[i].description,
			VTY_NEWLINE);
	}
}

#define SHOW_LOG_STR "Show current logging configuration\n"

DEFUN(show_logging_vty,
      show_logging_vty_cmd,
      "show logging vty",
	SHOW_STR SHOW_LOG_STR
	"Show current logging configuration for this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_print_logtarget(vty, &log_info, conn->dbg);

	return CMD_SUCCESS;
}

gDEFUN(cfg_description, cfg_description_cmd,
	"description .TEXT",
	"Save human-readable decription of the object\n")
{
	char **dptr = vty->index_sub;

	if (!dptr) {
		vty_out(vty, "vty->index_sub == NULL%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	*dptr = argv_concat(argv, argc, 0);
	if (!dptr)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

gDEFUN(cfg_no_description, cfg_no_description_cmd,
	"no description",
	NO_STR
	"Remove description of the object\n")
{
	char **dptr = vty->index_sub;

	if (!dptr) {
		vty_out(vty, "vty->index_sub == NULL%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (*dptr) {
		talloc_free(*dptr);
		*dptr = NULL;
	}

	return CMD_SUCCESS;
}

void openbsc_vty_add_cmds()
{
	install_element_ve(&enable_logging_cmd);
	install_element_ve(&disable_logging_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);
	install_element_ve(&logging_fltr_all_cmd);
	install_element_ve(&logging_use_clr_cmd);
	install_element_ve(&logging_prnt_timestamp_cmd);
	install_element_ve(&logging_set_category_mask_cmd);
	install_element_ve(&logging_level_cmd);
	install_element_ve(&show_logging_vty_cmd);
}
