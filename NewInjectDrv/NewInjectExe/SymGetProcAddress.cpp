#include "stdafx.h"
#include <windows.h>
#include <Dbghelp.h>
#include <stdio.h>
#pragma comment(lib,"dbghelp.lib")

WCHAR symbolPath[0x2000] = { 0 };

ULONG_PTR GetFunctionAddressPDB(HMODULE hMod, const WCHAR * name)
{
	BYTE memory[0x2000];
	ZeroMemory(memory, sizeof(memory));
	SYMBOL_INFOW * info = (SYMBOL_INFOW *)memory;
	info->SizeOfStruct = sizeof(SYMBOL_INFOW);
	info->MaxNameLen = MAX_SYM_NAME;
	info->ModBase = (ULONG_PTR)hMod;

	if (!SymFromNameW(GetCurrentProcess(), name, info))
	{
		printf("SymFromName %ws returned error : %d\n", name, GetLastError());
		return 0;
	}

	return (ULONG_PTR)info->Address;
}
PVOID SymGetProcAddress(LPCWSTR szDllName,LPCWSTR szApiName)
{
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED);
	WCHAR path[MAX_PATH] = { 0 };

	GetModuleFileNameW(0, path, _countof(path));
	WCHAR * temp = wcsrchr(path, L'\\');
	*temp = 0;
	wcscat(symbolPath, L"SRV*");
	wcscat(symbolPath, path);
	wcscat(symbolPath, L"*http://msdl.microsoft.com/download/symbols");
	if (!SymInitializeW(GetCurrentProcess(), symbolPath, TRUE))
	{
		return NULL;
	}
	HMODULE hDll = GetModuleHandleW(szDllName);
	PVOID lpRet=NULL;
	lpRet = (PVOID)GetFunctionAddressPDB(hDll,szApiName);
	SymCleanup(GetCurrentProcess());

	return lpRet;
}

