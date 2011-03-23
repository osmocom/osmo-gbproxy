#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/gsm0480.h>

struct gsm_subscriber_connection;

int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const struct msgb *in_msg, const char* response_text, 
			       const struct ussd_request *req);
int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     const struct msgb *msg, 
			     const struct ussd_request *request);

int gsm0480_send_ussdNotify(struct gsm_subscriber_connection *conn, int level, const char *text);
int gsm0480_send_releaseComplete(struct gsm_subscriber_connection *conn);

#endif
