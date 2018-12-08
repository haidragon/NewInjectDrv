#pragma once
#define XALIGN_DOWN(x, align)(x &~ (align - 1))
#define XALIGN_UP(x, align)((x & (align - 1))?XALIGN_DOWN(x, align) + align:x)

#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

#define M_ALLOC(_size_) ExAllocatePool(NonPagedPool, (_size_))
#define M_FREE(_addr_) ExFreePool((_addr_))

#define XLOWORD(_dw) ((USHORT)(((ULONG)(_dw)) & 0xffff))
#define XHIWORD(_dw) ((USHORT)((((ULONG)(_dw)) >> 16) & 0xffff))

#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)      \
	(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros)    \
	(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)     \
	(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)        \
	(((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"

#define IFMT32_W L"0x%.8x"
#define IFMT64_W L"0x%.16I64x"

#ifdef _X86_
#define IFMT IFMT32
#define IFMT_W IFMT32_W
#elif _AMD64_
#define IFMT IFMT64
#define IFMT_W IFMT64_W
#endif

BOOLEAN SetObjectSecurityWorld(HANDLE hObject, ACCESS_MASK AccessMask);
PVOID KernelGetModuleBase(char *ModuleName);
ULONG KernelGetExportAddress(PVOID Image, char *lpszFunctionName);
POBJECT_NAME_INFORMATION GetObjectName(PVOID pObject);
POBJECT_NAME_INFORMATION GetObjectNameByHandle(HANDLE hObject);
POBJECT_NAME_INFORMATION GetFullNtPath(PUNICODE_STRING Name);
BOOLEAN GetNormalizedModulePath(PANSI_STRING asPath, PANSI_STRING asNormalizedPath);
PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass);
BOOLEAN AllocUnicodeString(PUNICODE_STRING us, USHORT MaximumLength);
BOOLEAN AppendUnicodeToString(PUNICODE_STRING Dest, PCWSTR Source, USHORT Len);
ULONG GetFileSize(HANDLE hFile, PULONG FileSizeHigh);
BOOLEAN ReadFromFile(PUNICODE_STRING FileName, PVOID *Data, PULONG DataSize);
BOOLEAN DumpToFile(PUNICODE_STRING FileName, PVOID Data, ULONG DataSize);
BOOLEAN DeleteFile(PUNICODE_STRING usFileName);
BOOLEAN LoadImageAsDataFile(PUNICODE_STRING usName, PVOID *Image, PULONG MappedImageSize);
BOOLEAN QuerySymbolicLink(PUNICODE_STRING usName, PUNICODE_STRING usDestination);
void __stdcall ClearWp(PVOID Param);
void __stdcall SetWp(PVOID Param);
void ForEachProcessor(PKSTART_ROUTINE Routine, PVOID Param);
ULONG GetSyscallNumber(char *lpszName);
BOOLEAN RegQueryValueKey(HANDLE hKey, PWSTR lpwcName, ULONG Type, PVOID *Data, PULONG DataSize);
BOOLEAN RegSetValueKey(HANDLE hKey, PWSTR lpwcName, ULONG Type, PVOID Data, ULONG DataSize);
BOOLEAN GetProcessFullImagePath(PEPROCESS Process, PUNICODE_STRING ImagePath);


typedef struct _MAPPED_MDL
{
	PMDL Mdl;
	PVOID Buffer;
	PVOID MappedBuffer;

} MAPPED_MDL,
	*PMAPPED_MDL;

BOOLEAN AllocateUserMemory(ULONG Size, PMAPPED_MDL MdlInfo);
void FreeUserMemory(PMAPPED_MDL MdlInfo);
BOOLEAN AllocateKernelMemory(ULONG Size, PMAPPED_MDL MdlInfo);
void FreeKernelMemory(PMAPPED_MDL MdlInfo);
void CopyKernelMemory(PVOID Dst, PVOID Src, ULONG Size);
BOOLEAN SetPfnsForAddress(PVOID Address, ULONG PagesCount, PHYSICAL_ADDRESS *PhysicalAddr);
BOOLEAN IsWow64Process(PEPROCESS Process, BOOLEAN *bIsWow64);
ULONG __stdcall GetCR4(void);
ULONG __stdcall GetCR3(void);
PVOID __stdcall GetCALLByName(PCWSTR SourceString);
PVOID GetKeServiceDescriptorTableShadow(PVOID NewBase);
BOOLEAN ValidateUnicodeString(PUNICODE_STRING usStr);
typedef struct _RTL_PROCESS_MODULE_INFORMATION 
{
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[ 256 ];

} RTL_PROCESS_MODULE_INFORMATION, 
	*PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES 
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];

} RTL_PROCESS_MODULES, 
	*PRTL_PROCESS_MODULES;

typedef enum WIN_VER_DETAIL {
	WINDOWS_VERSION_NONE,       //  0
	WINDOWS_VERSION_2K,
	WINDOWS_VERSION_XP,
	WINDOWS_VERSION_2K3,
	WINDOWS_VERSION_2K3_SP1_SP2,
	WINDOWS_VERSION_VISTA_2008,
	WINDOWS_VERSION_7
} WIN_VER_DETAIL;

typedef NTSTATUS (NTAPI * PFN_RtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);

WIN_VER_DETAIL GetWindowsVersion();
ULONG HookSSDT(ULONG Id,ULONG Addr);
