/*
   Copyright (C) Andrzej Hajda 2009
   Contact: andrzej.hajda@wp.pl
   License: GNU General Public License version 3
*/

#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/termios.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <tevent.h>
#include <popt.h>
#include <util/memory.h>
#include <credentials.h>
#include <util/time.h>
#include <util/debug.h>
#include <smb_cliraw.h>
#include <smb_cli.h>
#include <dcerpc.h>
#include <param.h>
#define TEVENT_CONTEXT_INIT tevent_context_init

#include "async.h"
#include "svcinstall.h"
#include "winexesvc.h"

#define SERVICE_FILENAME SERVICE_NAME ".exe"

static struct loadparm_context *cmdline_lp_ctx;

/* winexesvc32_exe.c */
extern unsigned int winexesvc32_exe_len;
extern unsigned char winexesvc32_exe[];

/* winexesvc64_exe.c */
extern unsigned int winexesvc64_exe_len;
extern unsigned char winexesvc64_exe[];

static const char version_message_fmt[] = "winexe version %d.%02d\nThis program may be freely redistributed under the terms of the GNU GPLv3\n";

static struct tevent_context *ev_ctx;

struct program_options {
	char *hostname;
	char *cmd;
	struct cli_credentials *credentials;
	char *runas;
	char *runas_file;
	int flags;
};

static int abort_requested = 0;

static void parse_args(int argc, char *argv[], struct program_options *options)
{
	poptContext pc;
	int opt, i;

	int argc_new;
	char **argv_new;
	
	memset(options, 0, sizeof(struct program_options));
	int flag_interactive = 0;
	int flag_ostype = 2;
	int flag_reinstall = 0;
	int flag_uninstall = 0;
	int flag_system = 0;
	char *opt_user = NULL;
	char *opt_kerberos = NULL;
	char *opt_auth_file = NULL;
	char *opt_debuglevel = NULL;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "user", 'U', POPT_ARG_STRING, &opt_user, 0, "Set the network username", "[DOMAIN/]USERNAME[%PASSWORD]" },
		{ "authentication-file", 'A', POPT_ARG_STRING, &opt_auth_file, 0, "Get the credentials from a file", "FILE" },
		{ "kerberos", 'k', POPT_ARG_STRING, &opt_kerberos, 0, "Use Kerberos, -k [yes|no]" },
		{ "debuglevel", 'd', POPT_ARG_STRING, &opt_debuglevel, 0, "Set debug level", "DEBUGLEVEL" },
		{ "uninstall", 0, POPT_ARG_NONE, &flag_uninstall, 0,
		  "Uninstall winexe service after remote execution", NULL},
		{ "reinstall", 0, POPT_ARG_NONE, &flag_reinstall, 0,
		  "Reinstall winexe service before remote execution", NULL},
		{ "system", 0, POPT_ARG_NONE, &flag_system, 0,
		  "Use SYSTEM account" , NULL},
		{ "runas", 0, POPT_ARG_STRING, &options->runas, 0,
		  "Run as user (BEWARE: password is sent in cleartext over net)" , "[DOMAIN\\]USERNAME%PASSWORD"},
		{ "runas-file", 0, POPT_ARG_STRING, &options->runas_file, 0,
		  "Run as user options defined in a file", "FILE"},
		{ "interactive", 0, POPT_ARG_INT, &flag_interactive, 0,
		  "Desktop interaction: 0 - disallow, 1 - allow. If you allow use also --system switch (Win requirement). Vista do not support this option.", "0|1"},
		{ "ostype", 0, POPT_ARG_INT, &flag_ostype, 0,
		  "OS type: 0 - 32bit, 1 - 64bit, 2 - winexe will decide. Determines which version (32bit/64bit) of service will be installed.", "0|1|2"},
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "//host command");

	if ((opt = poptGetNextOpt(pc)) != -1) {
		DEBUG(0, (version_message_fmt, VERSION_MAJOR, VERSION_MINOR));
		poptPrintUsage(pc, stdout, 0);
		exit(1);
	}

	argv_new = discard_const_p(char *, poptGetArgs(pc));

	argc_new = argc;
	for (i = 0; i < argc - 1; i++) {
		if (!argv_new || argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (argc_new != 2 || argv_new[0][0] != '/'
	    || argv_new[0][1] != '/') {
		DEBUG(0, (version_message_fmt, VERSION_MAJOR, VERSION_MINOR));
		poptPrintUsage(pc, stdout, 0);
		exit(1);
	}

	if (opt_debuglevel)
		lpcfg_set_cmdline(cmdline_lp_ctx, "log level", opt_debuglevel);

	options->credentials = cli_credentials_init(talloc_autofree_context());
	if (opt_user)
		cli_credentials_parse_string(options->credentials, opt_user, CRED_SPECIFIED);
	else if (opt_auth_file)
		cli_credentials_parse_file(options->credentials, opt_auth_file, CRED_SPECIFIED);
	cli_credentials_guess(options->credentials, cmdline_lp_ctx);

	if (opt_kerberos)
		cli_credentials_set_kerberos_state(options->credentials,
						strcmp(opt_kerberos, "yes")
						? CRED_MUST_USE_KERBEROS
						: CRED_DONT_USE_KERBEROS);


	if (options->runas == NULL && options->runas_file != NULL) {
		struct cli_credentials* cred = cli_credentials_init(talloc_autofree_context());
		cli_credentials_parse_file(cred, options->runas_file, CRED_SPECIFIED);
		if (cred->username != NULL && cred->password != NULL) {
			char buffer[1024];
			if (cred->domain != NULL) {
				snprintf(buffer, sizeof(buffer), "%s\\%s%%%s", cred->domain, cred->username, cred->password);
			} else {
				snprintf(buffer, sizeof(buffer), "%s%%%s", cred->username, cred->password);
			}
			buffer[sizeof(buffer)-1] = '\0';
			options->runas = strdup(buffer);
		}
	}

	options->hostname = argv_new[0] + 2;
	options->cmd = argv_new[1];
	
	options->flags = flag_interactive;
	if (flag_reinstall)
		options->flags |= SVC_FORCE_UPLOAD;
	if (flag_ostype == 1)
		options->flags |= SVC_OS64BIT;
	if (flag_ostype == 2)
		options->flags |= SVC_OSCHOOSE;
	if (flag_uninstall)
		options->flags |= SVC_UNINSTALL;
	if (flag_system)
		options->flags |= SVC_SYSTEM;
}

enum {STATE_OPENING, STATE_GETTING_VERSION, STATE_RUNNING, STATE_CLOSING, STATE_CLOSING_FOR_REINSTALL };

struct winexe_context {
	int state;
	struct program_options *args;
	struct smbcli_tree *tree;
	struct async_context *ac_ctrl;
	struct async_context *ac_in;
	struct async_context *ac_out;
	struct async_context *ac_err;
	int return_code;
};

static void exit_program(struct winexe_context *c);

static void on_ctrl_pipe_error(struct winexe_context *c, int func, NTSTATUS status)
{
	DEBUG(1, ("ERROR: on_ctrl_pipe_error - %s\n", nt_errstr(status)));
	static int activated = 0;
	if (!activated
	    && NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		status =
		    svc_install(ev_ctx, c->args->hostname,
				SERVICE_NAME, SERVICE_FILENAME,
				winexesvc32_exe, winexesvc32_exe_len,
				winexesvc64_exe, winexesvc64_exe_len,
				c->args->credentials, cmdline_lp_ctx, c->args->flags);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,
			      ("ERROR: Failed to install service winexesvc - %s\n",
			       nt_errstr(status)));
			c->return_code = 1;
			exit_program(c);
		}
		activated = 1;
		async_open(c->ac_ctrl, "\\pipe\\" PIPE_NAME, OPENX_MODE_ACCESS_RDWR);
	} else if (func == ASYNC_OPEN_RECV) {
		DEBUG(0,
		      ("ERROR: Cannot open control pipe - %s\n",
		       nt_errstr(status)));
		c->return_code = 1;
		exit_program(c);
	} else if (func == ASYNC_READ_RECV && c->state == STATE_OPENING) {
		;
	} else
		exit_program(c);
}

static void on_in_pipe_open(struct winexe_context *c);

static void on_out_pipe_read(struct winexe_context *c, const char *data, int len);
static void on_err_pipe_read(struct winexe_context *c, const char *data, int len);

static void on_in_pipe_error(struct winexe_context *c, int func, NTSTATUS status);
static void on_out_pipe_error(struct winexe_context *c, int func, NTSTATUS status);
static void on_err_pipe_error(struct winexe_context *c, int func, NTSTATUS status);

static const char *cmd_check(const char *data, const char *cmd, int len)
{
	int lcmd = strlen(cmd);
	if (lcmd >= len)
		return 0;
	if (!strncmp(data, cmd, lcmd)
	    && (data[lcmd] == ' ' || data[lcmd] == '\n')) {
		return data + lcmd + 1;
	}
	return 0;
}

static void catch_alarm(int sig)
{
	abort_requested = 1;
	signal(sig, SIG_DFL);
}

static void timer_handler(struct tevent_context *ev, struct tevent_timer *te, struct timeval current_time, void *private_data)
{
	struct winexe_context *c = talloc_get_type(private_data, struct winexe_context);
	if (abort_requested) {
		fprintf(stderr, "Aborting...\n");
		async_write(c->ac_ctrl, "abort\n", 6);
	} else
		tevent_add_timer(c->tree->session->transport->ev, c, timeval_current_ofs(0, 10000), (tevent_timer_handler_t)timer_handler, c);
}

static void on_ctrl_pipe_open(struct winexe_context *c)
{
	char *str = "get version\n";

	DEBUG(1, ("CTRL: Sending command: %s", str));
	c->state = STATE_GETTING_VERSION;
	async_write(c->ac_ctrl, str, strlen(str));
	signal(SIGINT, catch_alarm);
	signal(SIGTERM, catch_alarm);
	tevent_add_timer(c->tree->session->transport->ev, c, timeval_current_ofs(0, 10000), (tevent_timer_handler_t)timer_handler, c);
}

static void on_ctrl_pipe_read(struct winexe_context *c, const char *data, int len)
{
	const char *p;
	if ((p = cmd_check(data, CMD_STD_IO_ERR, len))) {
		DEBUG(1, ("CTRL: Recieved command: %.*s", len, data));
		unsigned int npipe = strtoul(p, 0, 16);
		char *fn;
		/* Open in */
		c->ac_in = talloc_zero(c, struct async_context);
		c->ac_in->tree = c->tree;
		c->ac_in->cb_ctx = c;
		c->ac_in->cb_open = (async_cb_open) on_in_pipe_open;
		c->ac_in->cb_error = (async_cb_error) on_in_pipe_error;
		fn = talloc_asprintf(c->ac_in, "\\pipe\\" PIPE_NAME_IN, npipe);
		async_open(c->ac_in, fn, OPENX_MODE_ACCESS_RDWR);
		/* Open out */
		c->ac_out = talloc_zero(c, struct async_context);
		c->ac_out->tree = c->tree;
		c->ac_out->cb_ctx = c;
		c->ac_out->cb_read = (async_cb_read) on_out_pipe_read;
		c->ac_out->cb_error = (async_cb_error) on_out_pipe_error;
		fn = talloc_asprintf(c->ac_out, "\\pipe\\" PIPE_NAME_OUT, npipe);
		async_open(c->ac_out, fn, OPENX_MODE_ACCESS_RDWR);
		/* Open err */
		c->ac_err = talloc_zero(c, struct async_context);
		c->ac_err->tree = c->tree;
		c->ac_err->cb_ctx = c;
		c->ac_err->cb_read = (async_cb_read) on_err_pipe_read;
		c->ac_err->cb_error = (async_cb_error) on_err_pipe_error;
		fn = talloc_asprintf(c->ac_err, "\\pipe\\" PIPE_NAME_ERR, npipe);
		async_open(c->ac_err, fn, OPENX_MODE_ACCESS_RDWR);
	} else if ((p = cmd_check(data, CMD_RETURN_CODE, len))) {
		c->return_code = strtoul(p, 0, 16);
	} else if ((p = cmd_check(data, "version", len))) {
		int ver = strtoul(p, 0, 0);
		if (ver/10 != VERSION/10) {
			DEBUG(1, ("CTRL: Bad version of service (is %d.%02d, expected %d.%02d), reinstalling.\n", ver/100, ver%100, VERSION/100, VERSION%100));
			async_close(c->ac_ctrl);
			c->state = STATE_CLOSING_FOR_REINSTALL;
		} else {
			char *str;
			if (c->args->runas)
				str = talloc_asprintf(c, "set runas %s\nrun %s\n", c->args->runas, c->args->cmd);
			else
				str = talloc_asprintf(c, "%srun %s\n", (c->args->flags & SVC_SYSTEM) ? "set system 1\n" : "" , c->args->cmd);
			DEBUG(1, ("CTRL: Sending command: %s", str));
			async_write(c->ac_ctrl, str, strlen(str));
			talloc_free(str);
			c->state = STATE_RUNNING;
		}
	} else if ((p = cmd_check(data, "error", len))) {
		DEBUG(0, ("Error: %.*s", len, data));
		if (c->state == STATE_GETTING_VERSION) {
			DEBUG(0, ("CTRL: Probably old version of service, reinstalling.\n"));
			async_close(c->ac_ctrl);
			c->state = STATE_CLOSING_FOR_REINSTALL;
		}
	} else {
		DEBUG(0, ("CTRL: Unknown command: %.*s", len, data));
	}
}

static void on_ctrl_pipe_close(struct winexe_context *c)
{
	if (c->state == STATE_CLOSING_FOR_REINSTALL) {
		DEBUG(1,("Reinstalling service\n"));
		svc_uninstall(ev_ctx, c->args->hostname,
			      SERVICE_NAME, SERVICE_FILENAME,
			      c->args->credentials,
			      cmdline_lp_ctx);
		svc_install(ev_ctx, c->args->hostname,
			    SERVICE_NAME, SERVICE_FILENAME,
			    winexesvc32_exe, winexesvc32_exe_len,
			    winexesvc64_exe, winexesvc64_exe_len,
			    c->args->credentials, cmdline_lp_ctx, c->args->flags);
		c->state = STATE_OPENING;
		async_open(c->ac_ctrl, "\\pipe\\" PIPE_NAME, OPENX_MODE_ACCESS_RDWR);
	}
}

static void on_stdin_read_event(struct tevent_context *ev,
			     struct tevent_fd *fde,
			     uint16_t flags,
			     struct winexe_context *c)
{
	char buf[256];
	int len;
	if ((len = read(0, &buf, sizeof(buf))) > 0) {
		async_write(c->ac_in, buf, len);
	} else {
		usleep(10);
	}
}

static void on_in_pipe_open(struct winexe_context *c)
{
	tevent_add_fd(c->tree->session->transport->ev,
		     c->tree, 0, TEVENT_FD_READ,
		     (tevent_fd_handler_t) on_stdin_read_event, c);
	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag &= ~ICANON;
	tcsetattr(0, TCSANOW, &term);
	setbuf(stdin, NULL);
}

static void on_out_pipe_read(struct winexe_context *c, const char *data, int len)
{
	write(1, data, len);
}

static void on_in_pipe_error(struct winexe_context *c, int func, NTSTATUS status)
{
	async_close(c->ac_in);
}

static void on_out_pipe_error(struct winexe_context *c, int func, NTSTATUS status)
{
	async_close(c->ac_out);
}

static void on_err_pipe_read(struct winexe_context *c, const char *data, int len)
{
	write(2, data, len);
}

static void on_err_pipe_error(struct winexe_context *c, int func, NTSTATUS status)
{
	async_close(c->ac_err);
}

static void exit_program(struct winexe_context *c)
{
	if (c->args->flags & SVC_UNINSTALL)
		svc_uninstall(ev_ctx, c->args->hostname,
			      SERVICE_NAME, SERVICE_FILENAME,
			      c->args->credentials,
			      cmdline_lp_ctx);
	exit(c->return_code);
}

int main(int argc, char *argv[])
{
	NTSTATUS status;
	struct smbcli_tree *cli_tree;
	struct program_options options;

	cmdline_lp_ctx = loadparm_init_global(false);
 
	parse_args(argc, argv, &options);
	DEBUG(1, (version_message_fmt, VERSION_MAJOR, VERSION_MINOR));
	ev_ctx = TEVENT_CONTEXT_INIT(talloc_autofree_context());
	lpcfg_set_option(cmdline_lp_ctx, "client ntlmv2 auth=no");

	if (options.flags & SVC_FORCE_UPLOAD)
		svc_uninstall(ev_ctx, options.hostname,
			      SERVICE_NAME, SERVICE_FILENAME,
			      options.credentials,
			      cmdline_lp_ctx);

	if (!(options.flags & SVC_IGNORE_INTERACTIVE)) {
		svc_install(ev_ctx, options.hostname,
			    SERVICE_NAME, SERVICE_FILENAME,
			    winexesvc32_exe, winexesvc32_exe_len,
			    winexesvc64_exe, winexesvc64_exe_len,
			    options.credentials, cmdline_lp_ctx, options.flags);
	}

	struct smbcli_options smb_options;
	struct smbcli_session_options session_options;

	lpcfg_smbcli_options(cmdline_lp_ctx, &smb_options);
	lpcfg_smbcli_session_options(cmdline_lp_ctx, &session_options);

	struct smbcli_state *cli_state;
	status = smbcli_full_connection(NULL, &cli_state, options.hostname, lpcfg_smb_ports(cmdline_lp_ctx), "IPC$",
	                            NULL, lpcfg_socket_options(cmdline_lp_ctx), options.credentials, lpcfg_resolve_context(cmdline_lp_ctx), ev_ctx,
	            		    &smb_options, &session_options, lpcfg_gensec_settings(NULL, cmdline_lp_ctx));
	if (cli_state)
		cli_tree = cli_state->tree;
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,
		      ("ERROR: Failed to open connection - %s\n",
		       nt_errstr(status)));
		return 1;
	}

	struct winexe_context *c =
	    talloc_zero(NULL, struct winexe_context);
	if (c == NULL) {
		DEBUG(0,
		      ("ERROR: Failed to allocate struct winexe_context\n"));
		return 1;
	}

	c->tree = cli_tree;
	c->ac_ctrl = talloc_zero(NULL, struct async_context);
	c->ac_ctrl->tree = cli_tree;
	c->ac_ctrl->cb_ctx = c;
	c->ac_ctrl->cb_open = (async_cb_open) on_ctrl_pipe_open;
	c->ac_ctrl->cb_read = (async_cb_read) on_ctrl_pipe_read;
	c->ac_ctrl->cb_error = (async_cb_error) on_ctrl_pipe_error;
	c->ac_ctrl->cb_close = (async_cb_close) on_ctrl_pipe_close;
	c->args = &options;
	c->return_code = 99;
	c->state = STATE_OPENING;
	async_open(c->ac_ctrl, "\\pipe\\" PIPE_NAME, OPENX_MODE_ACCESS_RDWR);

	tevent_loop_wait(cli_tree->session->transport->ev);
	return 0;
}
