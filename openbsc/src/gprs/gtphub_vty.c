/* (C) 2015 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <string.h>

#include <ares.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>

#include <openbsc/vty.h>
#include <openbsc/gtphub.h>

/* TODO split GRX ares from sgsn into a separate struct and allow use without
 * globals. */
#include <openbsc/sgsn.h>
extern struct sgsn_instance *sgsn;

static struct gtphub *g_hub = 0;
static struct gtphub_cfg *g_cfg = 0;

static struct cmd_node gtphub_node = {
	GTPHUB_NODE,
	"%s(config-gtphub)# ",
	1,
};

#define GTPH_DEFAULT_CONTROL_PORT 2123
#define GTPH_DEFAULT_USER_PORT 2152

static void write_addrs(struct vty *vty, const char *name,
			struct gtphub_cfg_addr *c, struct gtphub_cfg_addr *u)
{
	if ((c->port == GTPH_DEFAULT_CONTROL_PORT)
	    && (u->port == GTPH_DEFAULT_USER_PORT)
	    && (strcmp(c->addr_str, u->addr_str) == 0)) {
		/* Default port numbers and same IP address: write "short"
		 * variant. */
		vty_out(vty, " %s %s%s",
			name,
			c->addr_str,
			VTY_NEWLINE);
		return;
	}

	vty_out(vty, " %s ctrl %s %d user %s %d%s",
		name,
		c->addr_str, (int)c->port,
		u->addr_str, (int)u->port,
		VTY_NEWLINE);

	struct ares_addr_node *server;
	for (server = sgsn->ares_servers; server; server = server->next)
		vty_out(vty, " grx-dns-add %s%s", inet_ntoa(server->addr.addr4), VTY_NEWLINE);
}

static int config_write_gtphub(struct vty *vty)
{
	vty_out(vty, "gtphub%s", VTY_NEWLINE);

	write_addrs(vty, "bind-to-sgsns",
		    &g_cfg->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].bind,
		    &g_cfg->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_USER].bind);

	write_addrs(vty, "bind-to-ggsns",
		    &g_cfg->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].bind,
		    &g_cfg->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_USER].bind);

	if (g_cfg->sgsn_use_sender) {
		vty_out(vty, "sgsn-use-sender%s", VTY_NEWLINE);
	}

	if (g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].addr_str) {
		write_addrs(vty, "sgsn-proxy",
			    &g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL],
			    &g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_USER]);
	}

	if (g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].addr_str) {
		write_addrs(vty, "ggsn-proxy",
			    &g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL],
			    &g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_USER]);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub, cfg_gtphub_cmd,
      "gtphub",
      "Configure the GTP hub")
{
	vty->node = GTPHUB_NODE;
	return CMD_SUCCESS;
}

#define BIND_ARGS  "ctrl ADDR <0-65535> user ADDR <0-65535>"
#define BIND_DOCS  \
	"Set GTP-C bind\n" \
	"GTP-C local IP address (v4 or v6)\n" \
	"GTP-C local port\n" \
	"Set GTP-U bind\n" \
	"GTP-U local IP address (v4 or v6)\n" \
	"GTP-U local port\n"


DEFUN(cfg_gtphub_bind_to_sgsns_short, cfg_gtphub_bind_to_sgsns_short_cmd,
	"bind-to-sgsns ADDR",
	"GTP Hub Parameters\n"
	"Set the local bind address to listen for SGSNs, for both GTP-C and GTP-U\n"
	"Local IP address (v4 or v6)\n"
	)
{
	int i;
	for_each_plane(i)
		g_cfg->to_gsns[GTPH_SIDE_SGSN][i].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].bind.port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_USER].bind.port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_bind_to_ggsns_short, cfg_gtphub_bind_to_ggsns_short_cmd,
	"bind-to-ggsns ADDR",
	"GTP Hub Parameters\n"
	"Set the local bind address to listen for GGSNs, for both GTP-C and GTP-U\n"
	"Local IP address (v4 or v6)\n"
	)
{
	int i;
	for_each_plane(i)
		g_cfg->to_gsns[GTPH_SIDE_GGSN][i].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].bind.port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_USER].bind.port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}


static int handle_binds(struct gtphub_cfg_bind *b, const char **argv)
{
	b[GTPH_PLANE_CTRL].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	b[GTPH_PLANE_CTRL].bind.port = atoi(argv[1]);
	b[GTPH_PLANE_USER].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	b[GTPH_PLANE_USER].bind.port = atoi(argv[3]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_bind_to_sgsns, cfg_gtphub_bind_to_sgsns_cmd,
	"bind-to-sgsns " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Set the local bind addresses and ports to listen for SGSNs\n"
	BIND_DOCS
	)
{
	return handle_binds(g_cfg->to_gsns[GTPH_SIDE_SGSN], argv);
}

DEFUN(cfg_gtphub_bind_to_ggsns, cfg_gtphub_bind_to_ggsns_cmd,
	"bind-to-ggsns " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Set the local bind addresses and ports to listen for GGSNs\n"
	BIND_DOCS
	)
{
	return handle_binds(g_cfg->to_gsns[GTPH_SIDE_GGSN], argv);
}

DEFUN(cfg_gtphub_ggsn_proxy_short, cfg_gtphub_ggsn_proxy_short_cmd,
	"ggsn-proxy ADDR",
	"GTP Hub Parameters\n"
	"Redirect all GGSN bound traffic to default ports on this address (another gtphub)\n"
	"Remote IP address (v4 or v6)\n"
	)
{
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_USER].port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_ggsn_proxy, cfg_gtphub_ggsn_proxy_cmd,
	"ggsn-proxy " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Redirect all GGSN bound traffic to these addresses and ports (another gtphub)\n"
	BIND_DOCS
	)
{
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].port = atoi(argv[1]);
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	g_cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_USER].port = atoi(argv[3]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_sgsn_proxy_short, cfg_gtphub_sgsn_proxy_short_cmd,
	"sgsn-proxy ADDR",
	"GTP Hub Parameters\n"
	"Redirect all SGSN bound traffic to default ports on this address (another gtphub)\n"
	"Remote IP address (v4 or v6)\n"
	)
{
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_USER].port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_sgsn_proxy, cfg_gtphub_sgsn_proxy_cmd,
	"sgsn-proxy " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Redirect all SGSN bound traffic to these addresses and ports (another gtphub)\n"
	BIND_DOCS
	)
{
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].port = atoi(argv[1]);
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	g_cfg->proxy[GTPH_SIDE_SGSN][GTPH_PLANE_USER].port = atoi(argv[3]);
	return CMD_SUCCESS;
}


#define SGSN_USE_SENDER_STR \
	"Ignore SGSN's Address IEs, use sender address and port (useful over NAT)\n"

DEFUN(cfg_gtphub_sgsn_use_sender,
      cfg_gtphub_sgsn_use_sender_cmd,
      "sgsn-use-sender",
      SGSN_USE_SENDER_STR)
{
	g_cfg->sgsn_use_sender = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_no_sgsn_use_sender,
      cfg_gtphub_no_sgsn_use_sender_cmd,
      "no sgsn-use-sender",
      NO_STR SGSN_USE_SENDER_STR)
{
	g_cfg->sgsn_use_sender = 0;
	return CMD_SUCCESS;
}


/* Copied from sgsn_vty.h */
DEFUN(cfg_grx_ggsn, cfg_grx_ggsn_cmd,
	"grx-dns-add A.B.C.D",
	"Add DNS server\nIPv4 address\n")
{
	struct ares_addr_node *node = talloc_zero(tall_bsc_ctx, struct ares_addr_node);
	node->family = AF_INET;
	inet_aton(argv[0], &node->addr.addr4);

	node->next = sgsn->ares_servers;
	sgsn->ares_servers = node;
	return CMD_SUCCESS;
}


/*
(show gtphub all, show gtphub stats, show gtphub teidmap,
 show gtphub peers, ...)
*/

static void show_bind_stats_all(struct vty *vty)
{
	int plane_idx;
	for_each_plane(plane_idx) {
		vty_out(vty, "- %s Plane:%s",
			gtphub_plane_idx_names[plane_idx], VTY_NEWLINE);

		struct gtphub_bind *b = &g_hub->to_gsns[GTPH_SIDE_GGSN][plane_idx];
		vty_out(vty, "  - to/from GGSNs: %s port %d%s",
			gsn_addr_to_str(&b->local_addr), (int)b->local_port,
			VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, "    ", b->counters_io);

		b = &g_hub->to_gsns[GTPH_SIDE_SGSN][plane_idx];
		vty_out(vty, "  - to/from SGSNs: %s port %d%s",
			gsn_addr_to_str(&b->local_addr), (int)b->local_port,
			VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, "    ", b->counters_io);
	}
}

/*
static void show_peers_summary(struct vty *vty)
{
	int c
	int plane_idx;
}
*/

static void show_tunnels_summary(struct vty *vty)
{
	time_t now = gtphub_now();

	const int w = 36;
	int max_expiry = g_hub->expire_slowly.expiry_in_seconds;
	float seconds_per_step = ((float)max_expiry) / w;

	/* Print TEI mapping expiry in an ASCII histogram, like:
	     TEI map summary
	       Legend:  '_'=0  '.'<=1%  ':'<=2%  '|'<=10%  '#'>10%  (10.0 m/step)
	       CTRL: 30 mappings, valid for 360m[#  :.    |   .    :  .              ]1m
	       USER: 30 mappings, valid for 360m[#  :.    |   .    :  .              ]1m
	       4 TEI mappings in total, last expiry in 359.4 min
	 */
	vty_out(vty,
		"Tunnels summary%s"
		"  Legend:  ' '=0  '.'<=1%%  ':'<=2%%  '|'<=10%%  '#'>10%%  (%.1f m/step)%s",
		VTY_NEWLINE,
		seconds_per_step / 60.,
		VTY_NEWLINE);

	int last_expiry = 0;

	unsigned int count = 0;

	int histogram[w];
	memset(histogram, 0, sizeof(histogram));

	struct gtphub_tunnel *t;
	llist_for_each_entry(t, &g_hub->tunnels, entry) {
		count ++;
		int expiry = t->expiry_entry.expiry - now;
		last_expiry = (last_expiry > expiry) ? last_expiry : expiry;

		int hi = ((float)expiry) / seconds_per_step;
		if (hi < 0)
			hi = 0;
		if (hi > (w - 1))
			hi = w - 1;
		histogram[hi] ++;
	}

	vty_out(vty,
		"  %u tunnels, valid for %dm[",
		count, max_expiry / 60);

	int i;
	for (i = w - 1; i >= 0; i--) {
		char c;
		int val = histogram[i];
		int percent = 100. * val / count;
		if (!val)
			c = ' ';
		else if (percent <= 1)
			c = '.';
		else if (percent <= 2)
			c = ':';
		else if (percent <= 10)
			c = '|';
		else c = '#';
		vty_out(vty, "%c", c);
	}
	vty_out(vty, "]1m%s", VTY_NEWLINE);

	vty_out(vty, "  last expiry in %.1f min%s",
		((float)last_expiry) / 60.,
		VTY_NEWLINE);
}

static void show_tunnels_all(struct vty *vty)
{
	time_t now = gtphub_now();

	vty_out(vty, "All tunnels:%s"
		"Legend: SGSN <-> GGSN, with each:%s"
		"        <IP-Ctrl>[/<IP-User>] (<TEI-Ctrl>=<mapped>/<TEI-User>=<mapped>)%s",
		VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	unsigned int count = 0;
	unsigned int incomplete = 0;
	struct gtphub_tunnel *t;
	llist_for_each_entry(t, &g_hub->tunnels, entry) {
		vty_out(vty,
			"(%4dm) %s%s",
			-(int)((t->expiry_entry.expiry - now) / 60),
			gtphub_tunnel_str(t),
			VTY_NEWLINE);
		count ++;
		if (!gtphub_tunnel_complete(t))
			incomplete ++;
	}
	vty_out(vty, "Total: %u tunnels%s", count, VTY_NEWLINE);
}

DEFUN(show_gtphub_tunnels_summary, show_gtphub_tunnels_summary_cmd, "show gtphub tunnels summary",
      SHOW_STR "Summary of all tunnels")
{
	show_tunnels_summary(vty);
	return CMD_SUCCESS;
}

DEFUN(show_gtphub_tunnels_list, show_gtphub_tunnels_list_cmd, "show gtphub tunnels list",
      SHOW_STR "List all tunnels")
{
	show_tunnels_all(vty);
	return CMD_SUCCESS;
}

DEFUN(show_gtphub, show_gtphub_cmd, "show gtphub all",
      SHOW_STR "Display information about the GTP hub")
{
	show_bind_stats_all(vty);
	show_tunnels_summary(vty);
	return CMD_SUCCESS;
}


int gtphub_vty_init(struct gtphub *global_hub, struct gtphub_cfg *global_cfg)
{
	g_hub = global_hub;
	g_cfg = global_cfg;

	install_element_ve(&show_gtphub_cmd);
	install_element_ve(&show_gtphub_tunnels_summary_cmd);
	install_element_ve(&show_gtphub_tunnels_list_cmd);

	install_element(CONFIG_NODE, &cfg_gtphub_cmd);
	install_node(&gtphub_node, config_write_gtphub);
	vty_install_default(GTPHUB_NODE);

	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_sgsns_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_sgsns_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_ggsns_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_ggsns_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_ggsn_proxy_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_ggsn_proxy_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_sgsn_proxy_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_sgsn_proxy_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_sgsn_use_sender_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_no_sgsn_use_sender_cmd);
	install_element(GTPHUB_NODE, &cfg_grx_ggsn_cmd);

	return 0;
}

int gtphub_cfg_read(struct gtphub_cfg *cfg, const char *config_file)
{
	int rc;

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}
