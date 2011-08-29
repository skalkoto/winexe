/*
   Copyright (C) Andrzej Hajda 2009
   Contact: andrzej.hajda@wp.pl
   License: GNU General Public License version 3
*/

#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "shared.h"

#if 0
static void SvcDebugOut(const char *a, int b)
{
	FILE *f = fopen("C:\\" SERVICE_NAME ".log", "at");
	fprintf(f, a, b);
	fclose(f);
}
#else
#define SvcDebugOut(a,b) 0
#endif

extern DWORD WINAPI winexesvc_loop(LPVOID lpParameter);

static SERVICE_STATUS winexesvcStatus;
static SERVICE_STATUS_HANDLE winexesvcStatusHandle;

static VOID WINAPI winexesvcCtrlHandler(DWORD Opcode)
{
	DWORD status;

	switch (Opcode) {
	case SERVICE_CONTROL_PAUSE:
		SvcDebugOut(SERVICE_NAME ": winexesvcCtrlHandler: pause\n", 0);
		winexesvcStatus.dwCurrentState = SERVICE_PAUSED;
		break;

	case SERVICE_CONTROL_CONTINUE:
		SvcDebugOut(SERVICE_NAME ": winexesvcCtrlHandler: continue\n", 0);
		winexesvcStatus.dwCurrentState = SERVICE_RUNNING;
		break;

	case SERVICE_CONTROL_STOP:
		SvcDebugOut(SERVICE_NAME ": winexesvcCtrlHandler: stop\n", 0);
		winexesvcStatus.dwWin32ExitCode = 0;
		winexesvcStatus.dwCurrentState = SERVICE_STOPPED;
		winexesvcStatus.dwCheckPoint = 0;
		winexesvcStatus.dwWaitHint = 0;

		if (!SetServiceStatus
		    (winexesvcStatusHandle, &winexesvcStatus)) {
			status = GetLastError();
			SvcDebugOut(SERVICE_NAME
				    ": SetServiceStatus error %ld\n",
				    status);
		}

		SvcDebugOut(SERVICE_NAME ": Leaving winexesvc\n", 0);
		return;

	case SERVICE_CONTROL_INTERROGATE:
		SvcDebugOut(SERVICE_NAME ": winexesvcCtrlHandler: interrogate\n", 0);
		break;

	default:
		SvcDebugOut(SERVICE_NAME ": Unrecognized opcode %ld\n",
			    Opcode);
	}

	if (!SetServiceStatus(winexesvcStatusHandle, &winexesvcStatus)) {
		status = GetLastError();
		SvcDebugOut(SERVICE_NAME ": SetServiceStatus error 0x%08X\n",
			    status);
	}
	return;
}

static DWORD winexesvcInitialization(DWORD argc, LPTSTR * argv,
			      DWORD * specificError)
{
	HANDLE th = CreateThread(NULL, 0, winexesvc_loop, NULL, 0, NULL);
	if (th) {
		CloseHandle(th);
		return NO_ERROR;
	}
	return !NO_ERROR;
}

static void WINAPI winexesvcStart(DWORD argc, LPTSTR * argv)
{
	DWORD status;
	DWORD specificError;

	winexesvcStatus.dwServiceType = SERVICE_WIN32;
	winexesvcStatus.dwCurrentState = SERVICE_START_PENDING;
	winexesvcStatus.dwControlsAccepted =
	    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
	winexesvcStatus.dwWin32ExitCode = 0;
	winexesvcStatus.dwServiceSpecificExitCode = 0;
	winexesvcStatus.dwCheckPoint = 0;
	winexesvcStatus.dwWaitHint = 0;

	SvcDebugOut(SERVICE_NAME ": RegisterServiceCtrlHandler\n", 0);

	winexesvcStatusHandle =
	    RegisterServiceCtrlHandler(SERVICE_NAME, winexesvcCtrlHandler);

	if (winexesvcStatusHandle == (SERVICE_STATUS_HANDLE) 0) {
		SvcDebugOut(SERVICE_NAME
			    ": RegisterServiceCtrlHandler failed %d\n",
			    GetLastError());
		return;
	}
	status = winexesvcInitialization(argc, argv, &specificError);

	if (status != NO_ERROR) {
		winexesvcStatus.dwCurrentState = SERVICE_STOPPED;
		winexesvcStatus.dwCheckPoint = 0;
		winexesvcStatus.dwWaitHint = 0;
		winexesvcStatus.dwWin32ExitCode = status;
		winexesvcStatus.dwServiceSpecificExitCode = specificError;

		SetServiceStatus(winexesvcStatusHandle, &winexesvcStatus);
		return;
	}

	winexesvcStatus.dwCurrentState = SERVICE_RUNNING;
	winexesvcStatus.dwCheckPoint = 0;
	winexesvcStatus.dwWaitHint = 0;

	if (!SetServiceStatus(winexesvcStatusHandle, &winexesvcStatus)) {
		status = GetLastError();
		SvcDebugOut(SERVICE_NAME ": SetServiceStatus error %ld\n",
			    status);
	}

	SvcDebugOut(SERVICE_NAME ": Returning the Main Thread \n", 0);

	return;
}

int main(int argc, char *argv[])
{
	SERVICE_TABLE_ENTRY DispatchTable[] = {
		{SERVICE_NAME, winexesvcStart},
		{NULL, NULL}
	};

	SvcDebugOut(SERVICE_NAME ": StartServiceCtrlDispatcher %d\n",
		    GetLastError());
	if (!StartServiceCtrlDispatcher(DispatchTable)) {
		SvcDebugOut(SERVICE_NAME
			    ": StartServiceCtrlDispatcher (%d)\n",
			    GetLastError());
	}
	return 0;
}
