/*
 * (C) 2011-2012 by Holger Hans Peter Freyther
 * (C) 2011-2012 by On-Waves
 * (C) 2011 by Daniel Willmann
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

#include <osmocom/core/talloc.h>

#include <openbsc/control_cmd.h>
#include <openbsc/control_if.h>

#include <openbsc/bsc_nat.h>

#include <unistd.h>


#define NAT_MAX_CTRL_ID 65535

static struct bsc_nat *g_nat;

static int bsc_id_unused(int id, struct bsc_connection *bsc)
{
	struct bsc_cmd_list *pending;

	llist_for_each_entry(pending, &bsc->cmd_pending, list_entry) {
		if (pending->nat_id == id)
			return 0;
	}
	return 1;
}

static int get_next_free_bsc_id(struct bsc_connection *bsc)
{
	int new_id, overflow = 0;

	new_id = bsc->last_id;

	do {
		new_id++;
		if (new_id == NAT_MAX_CTRL_ID) {
			new_id = 1;
			overflow++;
		}

		if (bsc_id_unused(new_id, bsc)) {
			bsc->last_id = new_id;
			return new_id;
		}
	} while (overflow != 2);

	return -1;
}

void bsc_nat_ctrl_del_pending(struct bsc_cmd_list *pending)
{
	llist_del(&pending->list_entry);
	osmo_timer_del(&pending->timeout);
	talloc_free(pending->cmd);
	talloc_free(pending);
}

static struct bsc_cmd_list *bsc_get_pending(struct bsc_connection *bsc, char *id_str)
{
	struct bsc_cmd_list *cmd_entry;
	int id = atoi(id_str);
	if (id == 0)
		return NULL;

	llist_for_each_entry(cmd_entry, &bsc->cmd_pending, list_entry) {
		if (cmd_entry->nat_id == id) {
			return cmd_entry;
		}
	}
	return NULL;
}

int bsc_nat_handle_ctrlif_msg(struct bsc_connection *bsc, struct msgb *msg)
{
	struct ctrl_cmd *cmd;
	struct bsc_cmd_list *pending;
	char *var, *id;

	cmd = ctrl_cmd_parse(bsc, msg);
	msgb_free(msg);

	if (!cmd) {
		cmd = talloc_zero(bsc, struct ctrl_cmd);
		if (!cmd) {
			LOGP(DNAT, LOGL_ERROR, "OOM!\n");
			return -ENOMEM;
		}
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Failed to parse command.";
		goto err;
	}

	if (bsc->cfg && !llist_empty(&bsc->cfg->lac_list)) {
		if (cmd->variable) {
			var = talloc_asprintf(cmd, "net.0.bsc.%i.%s", bsc->cfg->nr,
					   cmd->variable);
			if (!var) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "OOM";
				goto err;
			}
			talloc_free(cmd->variable);
			cmd->variable = var;
		}

		/* We have to handle TRAPs before matching pending */
		if (cmd->type == CTRL_TYPE_TRAP) {
			ctrl_cmd_send_to_all(bsc->nat->ctrl, cmd);
			talloc_free(cmd);
			return 0;
		}

		/* Find the pending command */
		pending = bsc_get_pending(bsc, cmd->id);
		if (pending) {
			id = talloc_strdup(cmd, pending->cmd->id);
			if (!id) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "OOM";
				goto err;
			}
			cmd->id = id;
			ctrl_cmd_send(&pending->ccon->write_queue, cmd);
			bsc_nat_ctrl_del_pending(pending);
		} else {
			/* We need to handle TRAPS here */
			if ((cmd->type != CTRL_TYPE_ERROR) &&
			    (cmd->type != CTRL_TYPE_TRAP)) {
				LOGP(DNAT, LOGL_NOTICE, "Got control message "
					"from BSC without pending entry\n");
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "No request outstanding";
				goto err;
			}
		}
	}
	talloc_free(cmd);
	return 0;
err:
	ctrl_cmd_send(&bsc->write_queue, cmd);
	talloc_free(cmd);
	return 0;
}

static void pending_timeout_cb(void *data)
{
	struct bsc_cmd_list *pending = data;
	LOGP(DNAT, LOGL_ERROR, "Command timed out\n");
	pending->cmd->type = CTRL_TYPE_ERROR;
	pending->cmd->reply = "Command timed out";
	ctrl_cmd_send(&pending->ccon->write_queue, pending->cmd);

	bsc_nat_ctrl_del_pending(pending);
}

static void ctrl_conn_closed_cb(struct ctrl_connection *connection)
{
	struct bsc_connection *bsc;
	struct bsc_cmd_list *pending, *tmp;

	llist_for_each_entry(bsc, &g_nat->bsc_connections, list_entry) {
		llist_for_each_entry_safe(pending, tmp, &bsc->cmd_pending, list_entry) {
			if (pending->ccon == connection)
				bsc_nat_ctrl_del_pending(pending);
		}
	}
}

static int forward_to_bsc(struct ctrl_cmd *cmd)
{
	int ret = CTRL_CMD_HANDLED;
	struct ctrl_cmd *bsc_cmd = NULL;
	struct bsc_connection *bsc;
	struct bsc_cmd_list *pending;
	unsigned int nr;
	char *nr_str, *tmp, *saveptr;

	/* Skip over the beginning (bsc.) */
	tmp = strtok_r(cmd->variable, ".", &saveptr);
	tmp = strtok_r(NULL, ".", &saveptr);
	tmp = strtok_r(NULL, ".", &saveptr);
	nr_str = strtok_r(NULL, ".", &saveptr);
	if (!nr_str) {
		cmd->reply = "command incomplete";
		goto err;
	}
	nr = atoi(nr_str);

	tmp = strtok_r(NULL, "\0", &saveptr);
	if (!tmp) {
		cmd->reply = "command incomplete";
		goto err;
	}

	llist_for_each_entry(bsc, &g_nat->bsc_connections, list_entry) {
		if (!bsc->cfg)
			continue;
		if (!bsc->authenticated)
			continue;
		if (bsc->cfg->nr == nr) {
			/* Add pending command to list */
			pending = talloc_zero(bsc, struct bsc_cmd_list);
			if (!pending) {
				cmd->reply = "OOM";
				goto err;
			}

			pending->nat_id = get_next_free_bsc_id(bsc);
			if (pending->nat_id < 0) {
				cmd->reply = "No free ID found";
				goto err;
			}

			bsc_cmd = ctrl_cmd_cpy(bsc, cmd);
			if (!bsc_cmd) {
				cmd->reply = "Could not forward command";
				goto err;
			}

			talloc_free(bsc_cmd->id);
			bsc_cmd->id = talloc_asprintf(bsc_cmd, "%i", pending->nat_id);
			if (!bsc_cmd->id) {
				cmd->reply = "OOM";
				goto err;
			}

			talloc_free(bsc_cmd->variable);
			bsc_cmd->variable = talloc_strdup(bsc_cmd, tmp);
			if (!bsc_cmd->variable) {
				cmd->reply = "OOM";
				goto err;
			}

			if (ctrl_cmd_send(&bsc->write_queue, bsc_cmd)) {
				cmd->reply = "Sending failed";
				goto err;
			}
			pending->ccon = cmd->ccon;
			pending->ccon->closed_cb = ctrl_conn_closed_cb;
			pending->cmd = cmd;

			/* Setup the timeout */
			pending->timeout.data = pending;
			pending->timeout.cb = pending_timeout_cb;
			/* TODO: Make timeout configurable */
			osmo_timer_schedule(&pending->timeout, 10, 0);
			llist_add_tail(&pending->list_entry, &bsc->cmd_pending);

			goto done;
		}
	}
	/* We end up here if there's no bsc to handle our LAC */
	cmd->reply = "no BSC with this nr";
err:
	ret = CTRL_CMD_ERROR;
done:
	if (bsc_cmd)
		talloc_free(bsc_cmd);
	return ret;

}


CTRL_CMD_DEFINE(fwd_cmd, "net 0 bsc *");
static int get_fwd_cmd(struct ctrl_cmd *cmd, void *data)
{
	return forward_to_bsc(cmd);
}

static int set_fwd_cmd(struct ctrl_cmd *cmd, void *data)
{
	return forward_to_bsc(cmd);
}

static int verify_fwd_cmd(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

struct ctrl_handle *bsc_nat_controlif_setup(struct bsc_nat *nat, int port)
{
	struct ctrl_handle *ctrl;
	int rc;


	ctrl = controlif_setup(NULL, 4250);
	if (!ctrl) {
		fprintf(stderr, "Failed to initialize the control interface. Exiting.\n");
		return NULL;
	}

	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_fwd_cmd);
	if (rc) {
		fprintf(stderr, "Failed to install the control command. Exiting.\n");
		osmo_fd_unregister(&ctrl->listen_fd);
		close(ctrl->listen_fd.fd);
		talloc_free(ctrl);
		return NULL;
	}

	g_nat = nat;
	return ctrl;
}

