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
