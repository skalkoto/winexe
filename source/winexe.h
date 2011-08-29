/*
   Copyright (C) Andrzej Hajda 2009
   Contact: andrzej.hajda@wp.pl
   License: GNU General Public License version 3
*/

#define SVC_INTERACTIVE 1
#define SVC_IGNORE_INTERACTIVE 2
#define SVC_INTERACTIVE_MASK 3
#define SVC_FORCE_UPLOAD 4
#define SVC_OS64BIT 8
#define SVC_OSCHOOSE 16
#define SVC_UNINSTALL 32
#define SVC_SYSTEM 64

/* svcinstall.c */
NTSTATUS svc_install(const char *hostname,
		     struct cli_credentials *credentials, int flags);
NTSTATUS svc_uninstall(const char *hostname,
		       struct cli_credentials *credentials);

/* async.c */
enum { ASYNC_OPEN, ASYNC_OPEN_RECV, ASYNC_READ, ASYNC_READ_RECV,
	    ASYNC_WRITE, ASYNC_WRITE_RECV, ASYNC_CLOSE, ASYNC_CLOSE_RECV };
typedef void (*async_cb_open) (void *ctx);
typedef void (*async_cb_read) (void *ctx, const char *data, int len);
typedef void (*async_cb_close) (void *ctx);
typedef void (*async_cb_error) (void *ctx, int func, NTSTATUS status);

struct list_item {
	struct list_item *next;
	int size;
	char data[0];
};

struct list {
	struct list_item *begin;
	struct list_item *end;
};

struct async_context {
/* Public - must be initialized by client */
	struct smbcli_tree *tree;
	void *cb_ctx;
	async_cb_open cb_open;
	async_cb_read cb_read;
	async_cb_close cb_close;
	async_cb_error cb_error;
/* Private - internal usage, initialize to zeros */
	int fd;
	union smb_open *io_open;
	union smb_read *io_read;
	union smb_write *io_write;
	union smb_close *io_close;
	struct smbcli_request *rreq;
	struct smbcli_request *wreq;
	struct list wq;
	char buffer[256];
};

int async_open(struct async_context *c, const char *fn, int open_mode);
int async_read(struct async_context *c);
int async_write(struct async_context *c, const void *buf, int len);
int async_close(struct async_context *c);

extern struct tevent_context *ev_ctx;

/* winexesvc32_exe.c */
extern unsigned int winexesvc32_exe_len;
extern unsigned char winexesvc32_exe[];

/* winexesvc64_exe.c */
extern unsigned int winexesvc64_exe_len;
extern unsigned char winexesvc64_exe[];
