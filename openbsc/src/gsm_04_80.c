/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009, 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
 *
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/bsc_api.h>

#include <osmocore/gsm0480.h>
#include <osmocore/gsm_utils.h>
#include <osmocore/msgb.h>
#include <osmocore/tlv.h>

static inline unsigned char *msgb_wrap_with_TL(struct msgb *msgb, u_int8_t tag)
{
	uint8_t *data = msgb_push(msgb, 2);

	data[0] = tag;
	data[1] = msgb->len - 2;
	return data;
}

static inline unsigned char *msgb_push_TLV1(struct msgb *msgb, u_int8_t tag,
					    u_int8_t value)
{
	uint8_t *data = msgb_push(msgb, 3);

	data[0] = tag;
	data[1] = 1;
	data[2] = value;
	return data;
}


/* Send response to a mobile-originated ProcessUnstructuredSS-Request */
int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const struct msgb *in_msg, const char *response_text,
			       const struct ussd_request *req)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	u_int8_t *ptr8;
	int response_len;

	/* First put the payload text into the message */
	ptr8 = msgb_put(msg, 0);
	response_len = gsm_7bit_encode(ptr8, response_text);
	msgb_put(msg, response_len);

	/* Then wrap it as an Octet String */
	msgb_wrap_with_TL(msg, ASN1_OCTET_STRING_TAG);

	/* Pre-pend the DCS octet string */
	msgb_push_TLV1(msg, ASN1_OCTET_STRING_TAG, 0x0F);

	/* Then wrap these as a Sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the operation code */
	msgb_push_TLV1(msg, GSM0480_OPERATION_CODE,
			GSM0480_OP_CODE_PROCESS_USS_REQ);

	/* Wrap the operation code and IA5 string as a sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);

	/* Wrap this up as a Return Result component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_RETURN_RESULT);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS | req->transaction_id
					| (1<<7);  /* TI direction = 1 */
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     const struct msgb *in_msg,
			     const struct ussd_request *req)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	/* First insert the problem code */
	msgb_push_TLV1(msg, GSM_0480_PROBLEM_CODE_TAG_GENERAL,
			GSM_0480_GEN_PROB_CODE_UNRECOGNISED);

	/* Before it insert the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);

	/* Wrap this up as a Reject component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_REJECT);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS;
	gh->proto_discr |= req->transaction_id | (1<<7);  /* TI direction = 1 */
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

int gsm0480_send_ussdNotify(struct gsm_subscriber_connection *conn, int level, const char *text)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm0480_create_unstructuredSS_Notify(level, text);
	if (!msg)
		return -1;

	gsm0480_wrap_invoke(msg, GSM0480_OP_CODE_USS_NOTIFY, 0);
	gsm0480_wrap_facility(msg);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS;
	gh->msg_type = GSM0480_MTYPE_REGISTER;

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

int gsm0480_send_releaseComplete(struct gsm_subscriber_connection *conn)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm48_msgb_alloc();
	if (!msg)
		return -1;

	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS;
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}
