#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

struct gbproxy_config {
	/* parsed from config file */
	uint16_t nsip_sgsn_nsei;

	/* misc */
	struct gprs_ns_inst *nsi;
};

extern struct gbproxy_config gbcfg;
extern struct cmd_element show_gbproxy_cmd;
extern struct cmd_element delete_gb_bvci_cmd;
extern struct cmd_element delete_gb_nsei_cmd;

/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);


/* gb_proxy.c */

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, uint16_t nsei, uint16_t ns_bvci, uint16_t nsvci);

int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data);

/* Reset all persistent NS-VC's */
int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi);

int gbprox_dump_global(FILE *stream, int indent);
int gbprox_dump_peers(FILE *stream, int indent);
void gbprox_reset();
#endif
