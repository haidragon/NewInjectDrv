
#pragma once
#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <ntddscsi.h>
#include <srb.h>
#include <ntimage.h>
#include "ntifs_48.h"
#include "zwfunc.h"
#include "windef.h"

typedef unsigned int UINT ;
typedef unsigned long DWORD ;
typedef unsigned long* PDWORD ;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned char* PBYTE;
typedef char CHAR;
//typedef BOOLEAN BOOL;

//#define DebugPrint KdPrint

#if DBG
#define DebugPrint(_x_) \
	;//DbgPrint _x_;

#else

#define DebugPrint(_x_)

#endif
#define VMProtectBegin \
	__asm _emit 0xEB \
	__asm _emit 0x10 \
	__asm _emit 0x56 \
	__asm _emit 0x4D \
	__asm _emit 0x50 \
	__asm _emit 0x72 \
	__asm _emit 0x6F \
	__asm _emit 0x74 \
	__asm _emit 0x65 \
	__asm _emit 0x63 \
	__asm _emit 0x74 \
	__asm _emit 0x20 \
	__asm _emit 0x62 \
	__asm _emit 0x65 \
	__asm _emit 0x67 \
	__asm _emit 0x69 \
	__asm _emit 0x6E \
	__asm _emit 0x00 \

#define VMProtectEnd \
	__asm _emit 0xEB \
	__asm _emit 0x0E \
	__asm _emit 0x56 \
	__asm _emit 0x4D \
	__asm _emit 0x50 \
	__asm _emit 0x72 \
	__asm _emit 0x6F \
	__asm _emit 0x74 \
	__asm _emit 0x65 \
	__asm _emit 0x63 \
	__asm _emit 0x74 \
	__asm _emit 0x20 \
	__asm _emit 0x65 \
	__asm _emit 0x6E \
	__asm _emit 0x64 \
	__asm _emit 0x00 \


#define STDCALL __stdcall
#pragma warning(disable:4047 4244 4311 4312 4244 4312 4133 4267)

//global var declare
#define NOT_SUPPORTED	0
#define WIN2K			1
#define WINXP			2
extern DWORD gKernelVersion;

#define AFD_BIND 0x12003

#define AFD_CONNECT 0x12007

#define AFD_SET_CONTEXT 0x12047

#define AFD_RECV 0x12017

#define AFD_SEND 0x1201f

#define AFD_SELECT 0x12024

#define AFD_UDP_SEND 0x12023

#define PROCESS_TERMINATE         (0x0001)  // winnt
#define PROCESS_CREATE_THREAD     (0x0002)  // winnt
#define PROCESS_SET_SESSIONID     (0x0004)  // winnt
#define PROCESS_VM_OPERATION      (0x0008)  // winnt
#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt
// begin_ntddk begin_wdm begin_ntifs
#define PROCESS_DUP_HANDLE        (0x0040)  // winnt
// end_ntddk end_wdm end_ntifs
#define PROCESS_CREATE_PROCESS    (0x0080)  // winnt
#define PROCESS_SET_QUOTA         (0x0100)  // winnt
#define PROCESS_SET_INFORMATION   (0x0200)  // winnt
#define PROCESS_QUERY_INFORMATION (0x0400)  // winnt
#define PROCESS_SET_PORT          (0x0800)
#define PROCESS_SUSPEND_RESUME    (0x0800)  // winnt



#define THREAD_TERMINATE               (0x0001)  // winnt
// end_ntddk end_wdm end_ntifs
#define THREAD_SUSPEND_RESUME          (0x0002)  // winnt
#define THREAD_ALERT                   (0x0004)
#define THREAD_GET_CONTEXT             (0x0008)  // winnt
#define THREAD_SET_CONTEXT             (0x0010)  // winnt
// begin_ntddk begin_wdm begin_ntifs
#define THREAD_SET_INFORMATION         (0x0020)  // winnt
// end_ntddk end_wdm end_ntifs
#define THREAD_QUERY_INFORMATION       (0x0040)  // winnt
// begin_winnt
#define THREAD_SET_THREAD_TOKEN        (0x0080)
#define THREAD_IMPERSONATE             (0x0100)
#define THREAD_DIRECT_IMPERSONATION    (0x0200)

#define MAX_SUSPEND_LIST 1024

#define BASEADDRLEN 10
#define NtBase 0x804d8000
#define EPROCESS_SIZE     1
#define PEB_OFFSET          2   
#define FILE_NAME_OFFSET        3   
#define PROCESS_LINK_OFFSET     4   
#define PROCESS_ID_OFFSET       5   
#define EXIT_TIME_OFFSET        6    

#define VA_OFFSET(object, offset) ((PCHAR)(object) + offset)

#define WP_STUFF
//#define  DBGMSG_FULL 0x911
//#define  DBGMSG 0x911

#include "tools.h"
#include "Debug.h"
#include "List.h"
#include "xde.h"
#include "hook.h"
#include "memory_type.h"
#include "ldasm.h"


