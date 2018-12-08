// NewInjectExe.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include "ntdll.h"

PVOID SymGetProcAddress(LPCWSTR szDllName,LPCWSTR szApiName);
PVOID getApcDispatchAddress();
#define CMD_STRING "GgTestDemo"
#define CMD_LENGTH (sizeof(CMD_STRING)-1)

typedef struct _CMD_CONTEXT_
{
	DWORD dwKey;
	DWORD dwLoadlibraryA;
	DWORD dwDispatchApc;
	CHAR  szDll[MAX_PATH];
}CMD_CONTEXT,*PCMD_CONTEXT;

typedef
	NTSTATUS
	(NTAPI *PZW_CREATE_FILE)(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer,
	IN ULONG EaLength
	);

typedef
	NTSTATUS
	(NTAPI *PRTL_INIT_UNICODE_STRING)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

#define	wczDosDevice	L"\\??\\gg134"

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;


BOOL SetInjectDLL(LPCSTR szDll)
{
	CHAR Buffer[sizeof(FILE_FULL_EA_INFORMATION) + CMD_LENGTH + sizeof(CMD_CONTEXT)] = {0};
	PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)&Buffer;
	PCMD_CONTEXT cmd;
	HMODULE hModule;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES ObjectAttributes; 
	UNICODE_STRING DeviceName;
	IO_STATUS_BLOCK IoStatus;
	PZW_CREATE_FILE ZwCreateFilePtr;
	PRTL_INIT_UNICODE_STRING RtlInitUnicodeStringPtr;
	BOOL bRet=FALSE;


	Ea->NextEntryOffset = 0;
	Ea->Flags = 0;
	Ea->EaNameLength = CMD_LENGTH;
	RtlCopyMemory(Ea->EaName, CMD_STRING, CMD_LENGTH);
	Ea->EaValueLength = sizeof(CMD_CONTEXT);	
	cmd = (PCMD_CONTEXT)&Ea->EaName[Ea->EaNameLength+1];
	
	cmd->dwKey = 0x11011;
	cmd->dwLoadlibraryA = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryA");
	cmd->dwDispatchApc = (DWORD)getApcDispatchAddress();
	strncpy(cmd->szDll,szDll,MAX_PATH);

	hModule = LoadLibrary( TEXT("ntdll.dll") );
	if ( hModule == NULL ){
		return bRet;
	}

	ZwCreateFilePtr = (PZW_CREATE_FILE)GetProcAddress(hModule,"ZwCreateFile");
	RtlInitUnicodeStringPtr = (PRTL_INIT_UNICODE_STRING)GetProcAddress(hModule,"RtlInitUnicodeString");
	if ( ZwCreateFilePtr ){
		RtlInitUnicodeStringPtr(&DeviceName, wczDosDevice);
		InitializeObjectAttributes(
			&ObjectAttributes, 
			&DeviceName, 
			OBJ_CASE_INSENSITIVE, 
			0, 0
			);

		ntStatus = 
			ZwCreateFilePtr(
			&hFile,
			READ_CONTROL,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN_IF,0, 
			Ea, sizeof(Buffer)
			);
		CloseHandle(hFile);
		bRet = TRUE;
		if ( ntStatus != STATUS_SUCCESS ){
			bRet = FALSE;
		}
	}
	FreeLibrary( hModule );
	return bRet;
}

PVOID getApcDispatchAddress()
{
	PVOID lpRet=NULL;
	if(GetModuleHandleA("kernelbase.dll"))
	{
		//高版本系统
		lpRet = SymGetProcAddress(L"ntdll.dll",L"RtlDispatchAPC");
	}
	else
	{
		lpRet = SymGetProcAddress(L"kernel32.dll",L"BaseDispatchAPC");
	}
	printf("%p",lpRet);
	return lpRet;
}
int _tmain(int argc, _TCHAR* argv[])
{
	SetInjectDLL("C:\\lilith.dll");
	getchar();
	return 0;
}

