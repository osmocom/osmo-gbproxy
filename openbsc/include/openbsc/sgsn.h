#ifndef _SGSN_H
#define _SGSN_H

#include <sys/types.h>

#include <osmocore/msgb.h>

#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_sgsn.h>

struct sgsn_config {
	/* parsed from config file */

	char *gtp_statedir;
	struct sockaddr_in gtp_listenaddr;

	/* misc */
	struct gprs_ns_inst *nsi;
};

struct sgsn_instance {
	char *config_file;
	struct sgsn_config cfg;
	/* File descriptor wrappers for LibGTP */
	struct bsc_fd gtp_fd0;
	struct bsc_fd gtp_fd1c;
	struct bsc_fd gtp_fd1u;
	/* Timer for libGTP */
	struct timer_list gtp_timer;
	/* GSN instance for libgtp */
	struct gsn_t *gsn;
};

extern struct sgsn_instance *sgsn;

/* sgsn_vty.c */

int sgsn_vty_init(void);
int sgsn_parse_config(const char *config_file, struct sgsn_config *cfg);

/* sgsn.c */

/* Main input function for Gb proxy */
int sgsn_rcvmsg(struct msgb *msg, struct gprs_nsvc *nsvc, uint16_t ns_bvci);


struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp);
int sgsn_delete_pdp_ctx(struct sgsn_pdp_ctx *pctx);

/* gprs_sndcp.c */

/* Entry point for the SNSM-ACTIVATE.indication */
int sndcp_sm_activate_ind(struct gprs_llc_lle *lle, uint8_t nsapi);
/* Called by SNDCP when it has received/re-assembled a N-PDU */
int sgsn_rx_sndcp_ud_ind(uint32_t tlli, uint8_t nsapi, struct msgb *msg,
			 uint32_t npdu_len, uint8_t *npdu);

#endif
