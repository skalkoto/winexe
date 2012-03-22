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

NTSTATUS svc_install(struct tevent_context *ev_ctx, 
                     const char *hostname,
		     const char *service_name, const char *service_filename,
		     unsigned char *svc32_exe, unsigned int svc32_exe_len,
		     unsigned char *svc64_exe, unsigned int svc64_exe_len,
		     struct cli_credentials *credentials,
		     struct loadparm_context *cllp_ctx,
		     int flags);
NTSTATUS svc_uninstall(struct tevent_context *ev_ctx,
		       const char *hostname,
		       const char *service_name, const char *service_filename,
		       struct cli_credentials * credentials,
		       struct loadparm_context *cllp_ctx);

#ifndef USE_SAMBA_TREE_HEADERS

# The following declarations are needed to compile against Samba 4 alpha18
# headers which are missing them. The missing declarations have reportedly
# been added to alpha19.

typedef struct composite_context *(*resolve_name_send_fn)(TALLOC_CTX *mem_ctx,
							  struct tevent_context *,
							  void *privdata,
							  uint32_t flags,
							  uint16_t port,
							  struct nbt_name *);

typedef NTSTATUS (*resolve_name_recv_fn)(struct composite_context *creq,
                                         TALLOC_CTX *mem_ctx,
                                         struct socket_address ***addrs,
                                         char ***names);

struct resolve_context {
	struct resolve_method {
		resolve_name_send_fn send_fn;
		resolve_name_recv_fn recv_fn;
		void *privdata;
		struct resolve_method *prev, *next;
	} *methods;
};

struct resolve_context *lpcfg_resolve_context(struct loadparm_context *lp_ctx);

#endif
