/*
   Copyright (C) Andrzej Hajda 2009
   Contact: andrzej.hajda@wp.pl
   License: GNU General Public License version 3
*/

#include "build/winexe_build.h"

#ifdef USE_SAMBA_TREE_HEADERS
#include "includes.h"
#include "system/filesys.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "lib/events/events.h"
#include "lib/util/samba_util.h"
#include "libcli/libcli.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_svcctl_c.h"
#include "libcli/smb_composite/smb_composite.h"
#else
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <tevent.h>
#include <samba-4.0/core/ntstatus.h>
#include <samba-4.0/param.h>
#include <samba-4.0/gen_ndr/ndr_svcctl_c.h>
#include <samba-4.0/dcerpc.h>
#include <samba-4.0/smb_cliraw.h>
#include <samba-4.0/smb_cli.h>
#include <samba-4.0/samba_util.h>
// #includes still available only from Samba tree
#include "param/param_proto.h"
#include "lib/socket/socket.h"
#include "libcli/libcli.h"
#include "libcli/smb_composite/smb_composite.h"
#define DEBUG(x,y)
#define DEBUGLVL(x) 0
#endif

#include "svcinstall.h"

//#define SERVICE_ALL_ACCESS (0xF01FF)
#define SERVICE_NO_CHANGE (0xffffffff)
#define SERVICE_INTERACTIVE_PROCESS (0x00000100)

#define SERVICE_STATE_ACTIVE (0x01)
#define SERVICE_STATE_INACTIVE (0x02)
#define SERVICE_STATE_ALL (0x03)
#define SERVICE_WIN32_OWN_PROCESS (0x00000010)
#define SERVICE_DEMAND_START (0x00000003)
#define SERVICE_ERROR_NORMAL (0x00000001)
#define SERVICE_CONTROL_STOP (0x00000001)
#define NT_STATUS_SERVICE_DOES_NOT_EXIST NT_STATUS(0xc0000424)

#define NT_ERR(status, lvl, args...) if (!NT_STATUS_IS_OK(status)) { DEBUG(lvl,("ERROR: " args)); DEBUG(lvl,(". %s.\n", nt_errstr(status))); return status; }
#define NT_RES(status, werr) (NT_STATUS_IS_OK(status) ? werror_to_ntstatus(werr) : status)

static void svc_dcerpc_init_once()
{
	static int initialized = 0;

	if (!initialized) {
		dcerpc_init();
		initialized = 1;
	}
}

static NTSTATUS svc_pipe_connect(struct tevent_context *ev_ctx, 
                          struct dcerpc_pipe **psvc_pipe,
			  const char *hostname,
			  struct cli_credentials *credentials,
			  struct loadparm_context *cllp_ctx)
{
	NTSTATUS status;
	char *binding;

	asprintf(&binding, "ncacn_np:%s%s", hostname, DEBUGLVL(9)?"[print]":"");
	svc_dcerpc_init_once();
	status =
	    dcerpc_pipe_connect(NULL, psvc_pipe, binding,
				&ndr_table_svcctl, credentials, ev_ctx, cllp_ctx);
	free(binding);
	return status;
}

static NTSTATUS svc_OpenSCManager(struct dcerpc_binding_handle *binding_handle,
			   const char *hostname,
			   struct policy_handle * pscm_handle)
{
	NTSTATUS status;
	struct svcctl_OpenSCManagerW r;

	r.in.MachineName = hostname;
	r.in.DatabaseName = NULL;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = pscm_handle;
	status = dcerpc_svcctl_OpenSCManagerW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_OpenService(struct dcerpc_binding_handle *binding_handle,
			 struct policy_handle * pscm_handle,
			 const char *ServiceName,
			 struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_OpenServiceW r;

	r.in.scmanager_handle = pscm_handle;
	r.in.ServiceName = ServiceName;
	r.in.access_mask = SERVICE_ALL_ACCESS;
	r.out.handle = psvc_handle;
	status = dcerpc_svcctl_OpenServiceW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_CreateService(struct dcerpc_binding_handle *binding_handle,
			   struct policy_handle * pscm_handle,
			   const char *ServiceName,
			   uint32_t type,
			   const char *binary_path,
			   struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_CreateServiceW r;

	r.in.scmanager_handle = pscm_handle;
	r.in.ServiceName = ServiceName;
	r.in.DisplayName = NULL;
	r.in.desired_access = SERVICE_ALL_ACCESS;
	r.in.type = type;
	r.in.start_type = SERVICE_DEMAND_START;
	r.in.error_control = SERVICE_ERROR_NORMAL;
	r.in.binary_path = binary_path;
	r.in.LoadOrderGroupKey = NULL;
	r.in.TagId = NULL;
	r.in.dependencies = NULL;
	r.in.dependencies_size = 0;
	r.in.service_start_name = NULL;
	r.in.password = NULL;
	r.in.password_size = 0;
	r.out.handle = psvc_handle;
	r.out.TagId = NULL;
	status = dcerpc_svcctl_CreateServiceW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_ChangeServiceConfig(struct dcerpc_binding_handle *binding_handle,
                           struct policy_handle * psvc_handle,
			   uint32_t type,
                           const char *binary_path)
{
	NTSTATUS status;
	struct svcctl_ChangeServiceConfigW r;

	r.in.handle = psvc_handle;
	r.in.type = type;
	r.in.start_type = SERVICE_NO_CHANGE;
	r.in.error_control = SERVICE_NO_CHANGE;
	r.in.binary_path = binary_path;
	r.in.load_order_group = NULL;
	r.in.dependencies = NULL;
	r.in.service_start_name = NULL;
	r.in.password = NULL;
	r.in.display_name = NULL;
	r.out.tag_id = NULL;
	status = dcerpc_svcctl_ChangeServiceConfigW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_StartService(struct dcerpc_binding_handle *binding_handle,
			  struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_StartServiceW r;

	r.in.handle = psvc_handle;
	r.in.NumArgs = 0;
	r.in.Arguments = NULL;
	status = dcerpc_svcctl_StartServiceW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_ControlService(struct dcerpc_binding_handle *binding_handle,
			    struct policy_handle * psvc_handle,
			    int control, struct SERVICE_STATUS * sstatus)
{
	NTSTATUS status;
	struct svcctl_ControlService r;

	r.in.handle = psvc_handle;
	r.in.control = control;
	r.out.service_status = sstatus;
	status = dcerpc_svcctl_ControlService_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_QueryServiceStatus(struct dcerpc_binding_handle *binding_handle,
			    struct policy_handle * psvc_handle,
			    struct SERVICE_STATUS * sstatus)
{
	NTSTATUS status;
	struct svcctl_QueryServiceStatus r;

	r.in.handle = psvc_handle;
	r.out.service_status = sstatus;
	status = dcerpc_svcctl_QueryServiceStatus_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_DeleteService(struct dcerpc_binding_handle *binding_handle,
			   struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_DeleteService r;

	r.in.handle = psvc_handle;
	status = dcerpc_svcctl_DeleteService_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_CloseServiceHandle(struct dcerpc_binding_handle *binding_handle,
				struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_CloseServiceHandle r;

	r.in.handle = psvc_handle;
	r.out.handle = psvc_handle;
	status = dcerpc_svcctl_CloseServiceHandle_r(binding_handle, NULL, &r);
	return status;
}

static NTSTATUS svc_UploadService(struct tevent_context *ev_ctx, 
                           const char *hostname,
			   const char *service_filename,
			   unsigned char *svc32_exe, unsigned int svc32_exe_len,
			   unsigned char *svc64_exe, unsigned int svc64_exe_len,
			   struct cli_credentials *credentials,
			   struct loadparm_context *cllp_ctx,
		           int flags)
{
	struct smb_composite_savefile *io;
	struct smbcli_state *cli;
	NTSTATUS status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;

	lpcfg_smbcli_options(cllp_ctx, &options);
	lpcfg_smbcli_session_options(cllp_ctx, &session_options);

	status =
	    smbcli_full_connection(NULL, &cli, hostname, lpcfg_smb_ports(cllp_ctx), "ADMIN$", NULL,
				   lpcfg_socket_options(cllp_ctx), credentials, lpcfg_resolve_context(cllp_ctx), ev_ctx, &options, &session_options, lpcfg_gensec_settings(NULL, cllp_ctx));
	NT_ERR(status, 1, "Failed to open ADMIN$ share");
	if (flags & SVC_FORCE_UPLOAD) {
		smbcli_unlink(cli->tree, service_filename);
	} else {
		int fd = smbcli_open(cli->tree, service_filename, O_RDONLY, DENY_NONE);
		if (fd >= 0) {
			smbcli_close(cli->tree, fd);
			return status;
		}
	}
	io = talloc_zero(cli->tree, struct smb_composite_savefile);
	io->in.fname = service_filename;
	if (flags & SVC_OSCHOOSE) {
	    status = smbcli_chkpath(cli->tree, "SysWoW64");
	}
	if ((flags & SVC_OSCHOOSE && NT_STATUS_IS_OK(status)) || (flags & SVC_OS64BIT)) {
		DEBUG(1, ("svc_UploadService: Installing 64bit %s\n", service_filename));
		io->in.data = svc64_exe;
		io->in.size = svc64_exe_len;
	} else {
		DEBUG(1, ("svc_UploadService: Installing 32bit %s\n", service_filename));
		io->in.data = svc32_exe;
		io->in.size = svc32_exe_len;
	}
	status = smb_composite_savefile(cli->tree, io);
	NT_ERR(status, 1, "Failed to save ADMIN$/%s", io->in.fname);
	talloc_free(io);
	smbcli_tdis(cli);
	return status;
}

/* Start, Creates, Install service if necccesary */
NTSTATUS svc_install(struct tevent_context *ev_ctx, 
                     const char *hostname,
		     const char *service_name, const char *service_filename,
		     unsigned char *svc32_exe, unsigned int svc32_exe_len,
		     unsigned char *svc64_exe, unsigned int svc64_exe_len,
		     struct cli_credentials *credentials,
		     struct loadparm_context *cllp_ctx,
		     int flags)
{
	NTSTATUS status;
	struct dcerpc_binding_handle *binding_handle;
	struct dcerpc_pipe *svc_pipe;
	struct policy_handle scm_handle;
	struct policy_handle svc_handle;
	int need_start;

	status = svc_pipe_connect(ev_ctx, &svc_pipe, hostname, credentials, cllp_ctx);
	NT_ERR(status, 1, "Cannot connect to svcctl pipe");
	binding_handle = svc_pipe->binding_handle;
	status = svc_UploadService(ev_ctx, hostname, service_filename,
				   svc32_exe, svc32_exe_len,
				   svc64_exe, svc64_exe_len,
				   credentials, cllp_ctx, flags);
	NT_ERR(status, 1, "UploadService failed");
	status = svc_OpenSCManager(binding_handle, hostname, &scm_handle);
	NT_ERR(status, 1, "OpenSCManager failed");
	status = svc_OpenService(binding_handle, &scm_handle, service_name,
				 &svc_handle);
	if (NT_STATUS_EQUAL(status, NT_STATUS_SERVICE_DOES_NOT_EXIST)) {
		status =
		    svc_CreateService(binding_handle, &scm_handle, service_name,
			SERVICE_WIN32_OWN_PROCESS | 
			(flags & SVC_INTERACTIVE ? SERVICE_INTERACTIVE_PROCESS : 0),
			service_filename, &svc_handle);
		NT_ERR(status, 1, "CreateService failed");
		need_start = 1;
	} else if (NT_STATUS_IS_OK(status) && !(flags & SVC_IGNORE_INTERACTIVE)) {
		struct SERVICE_STATUS s;
		int what, want;
		status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
		NT_ERR(status, 1, "QueryServiceStatus failed");
		what = s.type & SERVICE_INTERACTIVE_PROCESS;
		want = flags & SVC_INTERACTIVE;
		if ((what && !want) || (!what && want)) {
			need_start = 1;
			if (s.state != SVCCTL_STOPPED) {
				status = svc_ControlService(binding_handle, &svc_handle,
                                       SERVICE_CONTROL_STOP, &s);
				NT_ERR(status, 1, "StopService failed");
			}
			status = svc_ChangeServiceConfig(binding_handle, &svc_handle, 
			    SERVICE_WIN32_OWN_PROCESS | 
			    (want ? SERVICE_INTERACTIVE_PROCESS : 0),
			    NULL);
			NT_ERR(status, 1, "ChangeServiceConfig failed");
			do {
			    smb_msleep(100);
			    status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
			    NT_ERR(status, 1, "QueryServiceStatus failed");
			} while (s.state == SVCCTL_STOP_PENDING);
		}
	} else {
		NT_ERR(status, 1, "OpenService failed");
	}
	if ((flags & SVC_IGNORE_INTERACTIVE) || need_start) {
	    status = svc_StartService(binding_handle, &svc_handle);
	    NT_ERR(status, 1, "StartService failed");
	}
	{
		struct SERVICE_STATUS s;
		do {
			smb_msleep(100);
			status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
			NT_ERR(status, 1, "QueryServiceStatus failed");
		} while (s.state == SVCCTL_START_PENDING);
		if (s.state != SVCCTL_RUNNING) {
			DEBUG(0, ("Service cannot start, status=0x%08X\n", s.state));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	svc_CloseServiceHandle(binding_handle, &svc_handle);
	svc_CloseServiceHandle(binding_handle, &scm_handle);
	talloc_free(svc_pipe);
	return status;
}

NTSTATUS svc_uninstall(struct tevent_context *ev_ctx,
		       const char *hostname,
		       const char *service_name, const char *service_filename,
		       struct cli_credentials *credentials,
		       struct loadparm_context *cllp_ctx)
{
	NTSTATUS status;
	struct dcerpc_binding_handle *binding_handle;
	struct dcerpc_pipe *svc_pipe;
	struct policy_handle scm_handle;
	struct policy_handle svc_handle;
	struct SERVICE_STATUS svc_status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;

	lpcfg_smbcli_options(cllp_ctx, &options);
	lpcfg_smbcli_session_options(cllp_ctx, &session_options);

	status = svc_pipe_connect(ev_ctx, &svc_pipe, hostname, credentials, cllp_ctx);
	NT_ERR(status, 1, "Cannot connect to svcctl pipe");
	binding_handle = svc_pipe->binding_handle;
	status = svc_OpenSCManager(binding_handle, hostname, &scm_handle);
	NT_ERR(status, 1, "OpenSCManager failed");
	status =
	    svc_OpenService(binding_handle, &scm_handle, service_name,
			    &svc_handle);
	NT_ERR(status, 1, "OpenService failed");
	DEBUG(1, ("OpenService - %s\n", nt_errstr(status)));
	if (NT_STATUS_IS_OK(status)) {
		status =
		    svc_ControlService(binding_handle, &svc_handle,
				       SERVICE_CONTROL_STOP, &svc_status);
		{
			struct SERVICE_STATUS s;
			do {
				smb_msleep(100);
				status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
				NT_ERR(status, 1, "QueryServiceStatus failed");
			} while (s.state == SVCCTL_STOP_PENDING);
			if (s.state != SVCCTL_STOPPED) {
				DEBUG(0, ("Service cannot stop, status=0x%08X\n", s.state));
				return NT_STATUS_UNSUCCESSFUL;
			}
		}
		DEBUG(1, ("StopService - %s\n", nt_errstr(status)));
		status = svc_DeleteService(binding_handle, &svc_handle);
		DEBUG(1, ("DeleteService - %s\n", nt_errstr(status)));
		status = svc_CloseServiceHandle(binding_handle, &svc_handle);
		DEBUG(1, ("CloseServiceHandle - %s\n", nt_errstr(status)));
	}
	svc_CloseServiceHandle(binding_handle, &scm_handle);
	DEBUG(1, ("CloseSCMHandle - %s\n", nt_errstr(status)));

	struct smbcli_state *cli;
	status =
	    smbcli_full_connection(NULL, &cli, hostname, lpcfg_smb_ports(cllp_ctx), "ADMIN$", NULL,
				   lpcfg_socket_options(cllp_ctx), credentials, lpcfg_resolve_context(cllp_ctx), ev_ctx, &options, &session_options, lpcfg_gensec_settings(NULL, cllp_ctx));
	NT_ERR(status, 1, "Failed to open ADMIN$ share");
	/* Give svc some time to exit */
	smb_msleep(300);
	status = smbcli_unlink(cli->tree, service_filename);
	DEBUG(1, ("Delete %s - %s\n", service_filename, nt_errstr(status)));
	status = smbcli_tdis(cli);
	DEBUG(1, ("Closing ADMIN$ - %s\n", nt_errstr(status)));
	talloc_free(svc_pipe);
	return status;
}
