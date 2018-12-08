#include "stdafx.h"

PVOID pfn_BaseDispatchApc = NULL;
PVOID pfn_LoadLibraryA = NULL;

CHAR szDllPath[MAX_PATH]={0};

DWORD ZwQueueApcThreadId = 0;

NTSTATUS NTAPI MyNtQueueApcThread(
	__in HANDLE     ThreadHandle,
	__in PVOID      ApcRoutine,
	__in_opt PVOID  ApcArgument1,
	__in_opt PVOID  ApcArgument2,
	__in_opt PVOID  ApcArgument3
	)
{
	NTSTATUS ns;
	__asm
	{
			push eax
			push ApcArgument3
			push ApcArgument2
			push ApcArgument1
			push ApcRoutine
			push ThreadHandle
			mov eax,ZwQueueApcThreadId
			mov edx,esp
			int 0x2e
			mov ns,eax
			pop eax
	}
	return ns;
}

VOID LoadImageNotifyRoutine (
	IN PUNICODE_STRING  FullImageName,
	IN HANDLE  ProcessId, // where image is mapped
	IN PIMAGE_INFO  ImageInfo
	)
{    
	if (!pfn_LoadLibraryA
		|| !pfn_BaseDispatchApc)
	{
		//没初始化地址！
		return ;
	}
	if (FullImageName
		&&FullImageName->Buffer)
	{
		UNICODE_STRING usString;
		RtlInitUnicodeString(&usString,L"*\\XXX.EXE");
		if (FsRtlIsNameInExpression(&usString,FullImageName,TRUE,NULL))
		{
			SIZE_T size = MAX_PATH;
			PVOID BaseAddress=0;
			NTSTATUS ns;
			ns = ZwAllocateVirtualMemory(NtCurrentProcess(),
				&BaseAddress,
				0,
				&size,
				MEM_COMMIT,
				PAGE_READWRITE
				);
			if (NT_SUCCESS(ns))
			{
				RtlCopyMemory(BaseAddress,szDllPath,MAX_PATH);
				MyNtQueueApcThread( ZwCurrentThread(),
					pfn_BaseDispatchApc,
					pfn_LoadLibraryA,
					BaseAddress,
					NULL );
			}
		}
	}
}

VOID SetAddress(DWORD dwLoadLibrary,DWORD dwApcDispatch,LPCSTR lpszDllName)
{
	strcpy(szDllPath,lpszDllName);
	pfn_LoadLibraryA = (PVOID)dwLoadLibrary;
	pfn_BaseDispatchApc = (PVOID)dwApcDispatch;
	return ;
}
VOID InitInjectApc()
{
	ZwQueueApcThreadId = GetSyscallNumber("NtQueueApcThread");
	PsSetLoadImageNotifyRoutine( LoadImageNotifyRoutine );
}