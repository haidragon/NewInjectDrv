
#ifndef ZWFUNC_H
#define ZWFUNC_H

#include <ntddk.h>
#include "ntifs_48.h"
#include "windef.h"
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *MmSectionObjectType;
//
//typedef struct _KINTERRUPT 
//{
//    CSHORT Type;
//    CSHORT Size;
//    LIST_ENTRY InterruptListEntry;
//    PKSERVICE_ROUTINE ServiceRoutine;
//    PVOID ServiceContext;
//    KSPIN_LOCK SpinLock;
//    ULONG Spare1;
//    PKSPIN_LOCK ActualLock;
//    PKINTERRUPT_ROUTINE DispatchAddress;
//    ULONG Vector;
//    KIRQL Irql;
//    KIRQL SynchronizeIrql;
//    BOOLEAN FloatingSave;
//    BOOLEAN Connected;
//    CCHAR Number;
//    BOOLEAN ShareVector;
//    KINTERRUPT_MODE Mode;
//    ULONG ServiceCount;
//    ULONG Spare3;
//    ULONG DispatchCode[DISPATCH_LENGTH];
//} KINTERRUPT;
//typedef struct _KINTERRUPT *PKINTERRUPT, *RESTRICTED_POINTER PRKINTERRUPT; 
//

typedef struct _KE_DEVOBJ_EXTENSION 
{

    CSHORT          Type;
    USHORT          Size;

    //
    // Public part of the DeviceObjectExtension structure
    //

    PDEVICE_OBJECT  DeviceObject;               // owning device object

// end_ntddk end_nthal end_ntifs end_wdm

    //
    // Universal Power Data - all device objects must have this
    //

    ULONG           PowerFlags;             // see ntos\po\pop.h
                                            // WARNING: Access via PO macros
                                            // and with PO locking rules ONLY.

    //
    // Pointer to the non-universal power data
    //  Power data that only some device objects need is stored in the
    //  device object power extension -> DOPE
    //  see po.h
    //

    struct          _DEVICE_OBJECT_POWER_EXTENSION  *Dope;

    //
    // power state information
    //

    //
    // Device object extension flags.  Protected by the IopDatabaseLock.
    //

    ULONG ExtensionFlags;

    //
    // PnP manager fields
    //

    PVOID           DeviceNode;

    //
    // AttachedTo is a pointer to the device object that this device
    // object is attached to.  The attachment chain is now doubly
    // linked: this pointer and DeviceObject->AttachedDevice provide the
    // linkage.
    //

    PDEVICE_OBJECT  AttachedTo;

    //
    // Doubly-linked list of file objects
    //

    LIST_ENTRY      FileObjectList;

} KE_DEVOBJ_EXTENSION, *PKE_DEVOBJ_EXTENSION;


typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	PVOID Handle;
}CURDIR, *PCURDIR;


typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
    STRING DosPath;
}RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores;
}RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//typedef struct _INITIAL_TEB {
//  PVOID                StackBase;
//  PVOID                StackLimit;
//  PVOID                StackCommit;
//  PVOID                StackCommitMax;
//  PVOID                StackReserved;
//} INITIAL_TEB, *PINITIAL_TEB;

typedef struct tagMSG {
    HWND        hwnd;
    UINT        message;
    WPARAM      wParam;
    LPARAM      lParam;
    DWORD       time;
    POINT       pt;
#ifdef _MAC
    DWORD       lPrivate;
#endif
} MSG, *PMSG, NEAR *NPMSG, FAR *LPMSG;


//// 加载模块链
//typedef struct _LDR_DATA_TABLE_ENTRY
//{
//	LIST_ENTRY		InLoadOrderLinks;
//	LIST_ENTRY		InMemoryOrderLinks;
//	LIST_ENTRY		InInitializationOrderLinks;
//	PVOID			DllBase;
//	PVOID			EntryPoint;
//	DWORD			SizeOfImage;
//	UNICODE_STRING	FullDllName;
//	UNICODE_STRING	BaseDllName;
//}LDR_DATA_TABLE_ENTRY;
//typedef LDR_DATA_TABLE_ENTRY*	PLDR_DATA_TABLE_ENTRY;
//typedef LDR_DATA_TABLE_ENTRY**	PPLDR_DATA_TABLE_ENTRY;

/*
 * Raw Input request APIs
 */
typedef struct tagRAWINPUTDEVICE {
    USHORT usUsagePage; // Toplevel collection UsagePage
    USHORT usUsage;     // Toplevel collection Usage
    DWORD dwFlags;
    HWND hwndTarget;    // Target hwnd. NULL = follows keyboard focus
} RAWINPUTDEVICE, *PRAWINPUTDEVICE, *LPRAWINPUTDEVICE;

typedef CONST RAWINPUTDEVICE* PCRAWINPUTDEVICE;

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,				// Result is OBJECT_BASIC_INFORMATION structure
    ObjectNameInformation,				// Result is OBJECT_NAME_INFORMATION structure
    ObjectTypeInformation,				// Result is OBJECT_TYPE_INFORMATION structure
    ObjectAllInformation,				// Result is OBJECT_ALL_INFORMATION structure
    ObjectDataInformation				// Result is OBJECT_DATA_INFORMATION structure

} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

//typedef enum _OBJECT_INFORMATION_CLASS {
//	ObjectBasicInformation,
//	ObjectNameInformation,
//	ObjectTypeInformation,
//	ObjectTypesInformation,
//	ObjectHandleFlagInformation,
//	ObjectSessionInformation,
//	MaxObjectInfoClass  // MaxObjectInfoClass should always be the last enum
//} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION {

  UNICODE_STRING          TypeName;
  ULONG                   TotalNumberOfHandles;
  ULONG                   TotalNumberOfObjects;
  WCHAR                   Unused1[8];
  ULONG                   HighWaterNumberOfHandles;
  ULONG                   HighWaterNumberOfObjects;
  WCHAR                   Unused2[8];
  ACCESS_MASK             InvalidAttributes;
  GENERIC_MAPPING         GenericMapping;
  ACCESS_MASK             ValidAttributes;
  BOOLEAN                 SecurityRequired;
  BOOLEAN                 MaintainHandleCount;
  USHORT                  MaintainTypeList;
  POOL_TYPE               PoolType;
  ULONG                   DefaultPagedPoolCharge;
  ULONG                   DefaultNonPagedPoolCharge;

} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


//// SystemModuleInformation
//typedef struct _SYSTEM_MODULE_INFORMATION {
//    ULONG   Reserved[2];
//    PVOID   Base;
//    ULONG   Size;
//    ULONG   Flags;
//    USHORT  Index;
//    USHORT  Unknown;
//    USHORT  LoadCount;
//    USHORT  ModuleNameOffset;
//    CHAR    ImageName[256];
//} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
//

//////////////////////////////////////////////////////////////////////////

//typedef struct _CONTROL_AREA
//{
//	PVOID			Segment;
//	LIST_ENTRY		DereferenceList;
//	DWORD			NumberOfSectionReferences;
//	DWORD			NumberOfPfnReferences;
//	DWORD			NumberOfMappedViews;
//	WORD			NumberOfSubsections;
//	WORD			FlushInProgressCount;
//	DWORD			NumberOfUserReferences;
//	DWORD			u;
//	PFILE_OBJECT	FilePointer;
//	PVOID			WaitingForDeletion;
//	WORD			ModifiedWriteCount;
//	WORD			NumberOfSystemCacheViews;
//}CONTROL_AREA,
// *PCONTROL_AREA;


//typedef struct _SEGMENT_OBJECT
//{
//	PVOID			BaseAddress;
//	DWORD			TotalNumberOfPtes;
//	LARGE_INTEGER	SizeOfSegment;
//	DWORD			NonExtendedPtes;
//	DWORD			ImageCommitment;
//	PCONTROL_AREA	ControlArea;
//	PVOID			Subsection;
//	PVOID			LargeControlArea;
//	PVOID			MmSectionFlags;
//	PVOID			MmSubSectionFlags;
//}SEGMENT_OBJECT,
// *PSEGMENT_OBJECT;


//typedef struct _SECTION_OBJECT
//{
//	PVOID			StartingVa;
//	PVOID			EndingVa;
//	PVOID			Parent;
//	PVOID			LeftChild;
//	PVOID			RightChild;
//	PSEGMENT_OBJECT	Segment;
//}SECTION_OBJECT,
// *PSECTION_OBJECT;

typedef struct{
    ULONG Length;
    ULONG Unknown1;
    ULONG Unknown2;
    PWSTR pwsImageFileName;
    ULONG Unknown4;
    ULONG Unknown5;
    ULONG Unknown6;
    PCLIENT_ID pcidClient;
    ULONG Unknown8;
    ULONG Unknown9;
    ULONG Unknown10;
    ULONG Unknown11;
    ULONG Unknown12;
    ULONG Unknown13;
    ULONG Unknown14;
    ULONG Unknown15;
    ULONG Unknown16;
}PROCESS_UNKNOWN, *PPROCESS_UNKNOWN;


typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
}OBJECT_DIRECTORY_INFORMATION,
 *POBJECT_DIRECTORY_INFORMATION;

#pragma pack()

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
						IN PUNICODE_STRING ObjectPath,
						IN ULONG Attributes,
						IN PACCESS_STATE PassedAccessState OPTIONAL,
						IN ACCESS_MASK DesiredAccess OPTIONAL,
						IN POBJECT_TYPE ObjectType,
						IN KPROCESSOR_MODE AccessMode,
						IN OUT PVOID ParseContext OPTIONAL,
						OUT PVOID *ObjectPtr
						);  
NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByName (
					IN POBJECT_ATTRIBUTES ObjectAttributes,
					IN POBJECT_TYPE ObjectType OPTIONAL,
					IN KPROCESSOR_MODE AccessMode,
					IN OUT PACCESS_STATE AccessState OPTIONAL,
					IN ACCESS_MASK DesiredAccess OPTIONAL,
					IN OUT PVOID ParseContext OPTIONAL,
					OUT PHANDLE Handle
					);
/*
 * Exported and documented Zw class functions. These typedefs are based
 * on the prototypes found in NTDDK.H from Windows 2000 SP1 DDK.
 *
 * NTSYSAPI and NTAPI macros have been removed because they cannot be used
 * in a typedef.
 */


typedef
NTSTATUS
(NTAPI *NTCLOSE)(
				 IN HANDLE hHandle
				 );
typedef
NTSTATUS
(NTAPI *NTSUSPENDTHREAD)(			
									IN HANDLE ThreadHandle,
									OUT PULONG PreviousSuspendCount/* OPTIONAL*/
									); 
typedef NTSTATUS (NTAPI*NTSETCONTEXTTHREAD)(			
									   IN HANDLE ThreadHandle,
									   IN PCONTEXT Context
									   ); 

typedef NTSTATUS (NTAPI*NTPROTECTVIRTUALMEMORY) (
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG ProtectSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
	);	
typedef NTSTATUS (*T_ZwDeleteFile)(
	IN POBJECT_ATTRIBUTES  ObjectAttributes
);

typedef NTSTATUS (*T_ZwCreateFile) (
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
);

typedef NTSTATUS (*T_ZwOpenFile) (
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
);

typedef NTSTATUS (*T_ZwQueryInformationFile) (
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (*T_ZwSetInformationFile) (
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (*T_ZwReadFile) (
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
);

typedef NTSTATUS (*T_ZwWriteFile) (
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL
);

typedef NTSTATUS (*T_ZwClose) (
	IN HANDLE Handle
);

typedef NTSTATUS (*T_NtSuspendProcess) (
	IN HANDLE ProcessHandle
);

typedef NTSTATUS (*T_NtResumeProcess) (
	IN HANDLE ProcessHandle
	);

typedef NTSTATUS (*T_ZwCreateDirectoryObject) (
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (*T_ZwMakeTemporaryObject) (
	IN HANDLE Handle
);

typedef NTSTATUS (*T_ZwOpenSection) (
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);



typedef NTSTATUS (*T_ZwMapViewOfSection) (
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN ULONG ZeroBits,
	IN ULONG CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Protect
);

typedef NTSTATUS (*T_ZwUnmapViewOfSection) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress
);

typedef NTSTATUS (*T_ZwSetInformationThread) (
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength
);

typedef NTSTATUS (*T_ZwCreateKey) (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL
);

typedef NTSTATUS (*T_ZwOpenKey) (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (*T_ZwDeleteKey) (
	IN HANDLE KeyHandle
);

typedef NTSTATUS (*T_ZwEnumerateKey) (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);

typedef NTSTATUS (*T_ZwEnumerateValueKey) (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);

typedef NTSTATUS (*T_ZwFlushKey) (
	IN HANDLE KeyHandle
);

typedef NTSTATUS (*T_ZwQueryKey) (
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);

typedef NTSTATUS (*T_ZwQueryValueKey) (
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);

typedef NTSTATUS (*T_ZwSetValueKey) (
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID Data,
	IN ULONG DataSize
);

typedef NTSTATUS (*T_ZwOpenSymbolicLinkObject) (
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (*T_ZwQuerySymbolicLinkObject) (
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL
);

typedef NTSTATUS (*T_ZwCreateTimer) (
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType
);

typedef NTSTATUS (*T_ZwOpenTimer) (
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (*T_ZwCancelTimer) (
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL
);

typedef NTSTATUS (*T_ZwSetTimer) (
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN WakeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL
);

/* Undocumented, see comment in blocknt.h */
typedef NTSTATUS (*T_ZwQueryDirectoryFile) (
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
);

/* Undocumented, see comment in blocknt.h */
typedef NTSTATUS (*T_ZwQuerySystemInformation) (
	IN SYSTEM_INFORMATION_CLASS SystemInfoClass,
	OUT PVOID SystemInfoBuffer,
	IN ULONG SystemInfoBufferSize,
	OUT PULONG BytesReturned OPTIONAL
);

typedef NTSTATUS (*IOPCONTROLFILE)(
 IN HANDLE FileHandle,
 IN HANDLE Event OPTIONAL,
 IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
 IN PVOID ApcContext OPTIONAL,
 OUT PIO_STATUS_BLOCK IoStatusBlock,
 IN ULONG IoControlCode,
 IN PVOID InputBuffer OPTIONAL,
 IN ULONG InputBufferLength,
 OUT PVOID OutputBuffer OPTIONAL,
 IN ULONG OutputBufferLength,
 IN BOOLEAN DeviceIoControl);

// NtCreateThread
typedef
NTSTATUS
(NTAPI *NTCREATETHREAD)(
						OUT	PHANDLE              ThreadHandle,
						IN	ACCESS_MASK          DesiredAccess,
						IN	POBJECT_ATTRIBUTES   ObjectAttributes /*OPTIONAL*/,
						IN	HANDLE               ProcessHandle,
						OUT	PCLIENT_ID           ClientId,
						IN	PCONTEXT             ThreadContext,
						IN	PINITIAL_TEB         InitialTeb,
						IN	BOOLEAN              CreateSuspended
						);

typedef
NTSTATUS
(NTAPI *NTWRITEVIRTUALMEMORY)(
							  IN	HANDLE				ProcessHandle,
							  OUT	PVOID				BaseAddress,
							  IN	PVOID				Buffer,
							  IN	ULONG				BufferSize,
							  OUT	PULONG				NumberOfBytesWritten /*OPTIONAL*/
							  );

typedef
NTSTATUS
(NTAPI *NTREADVIRTUALMEMORY)(
							 IN	HANDLE				ProcessHandle,
							 IN	PVOID				BaseAddress,
							 OUT	PVOID				Buffer,
							 IN	ULONG				NumberOfBytesToRead,
							 OUT	PULONG				NumberOfBytesReaded/* OPTIONAL */
							 );

typedef
HHOOK 
(NTAPI *NTUSERSETWINDOWSHOOKEX)(
								IN	HANDLE				hmod,
								IN	PUNICODE_STRING		pstrLib,
								IN	DWORD				idThread,
								IN	INT					nFilterType,
								IN	PROC				pfnFilterProc,
								IN	DWORD				dwFlags
								);


typedef 
BOOL 
(NTAPI *NTUSERREGISTERRAWINPUTDEVICES)(
									   /*PCRAWINPUTDEVICE pRawInputDevices,*/
									   ULONG					pRawInputDevices,
									   UINT					uiNumDevices,
									   UINT					cbSize
									   );


typedef 
BOOL 
(NTAPI *NTUSERGETKEYBOARDSTATE)(
								PBYTE					lpKeyState
								);


typedef
BOOL 
(NTAPI *NTUSERGETMESSAGE)(
						  OUT	LPMSG				pmsg,
						  IN	HWND				hwnd,
						  IN	UINT				wMsgFilterMin,
						  IN	UINT				wMsgFilterMax
						  );

typedef
NTSTATUS
(NTAPI *NTOPENTHREAD)(
					  OUT PHANDLE				ThreadHandle,
					  IN ACCESS_MASK			DesiredAccess,
					  IN POBJECT_ATTRIBUTES	ObjectAttributes,
					  IN PCLIENT_ID			ClientId
					  );

typedef
NTSTATUS
(NTAPI *NTOPENPROCESS)(
					   PHANDLE					ProcessHandle,
					   ACCESS_MASK				DesiredAccess,
					   POBJECT_ATTRIBUTES		ObjectAttributes,
					   PCLIENT_ID				ClientId
					   );

// NtCreateProcess
typedef
NTSTATUS
(NTAPI *NTCREATEPROCESS)(
						 PHANDLE ProcessHandle,
						 ACCESS_MASK DesiredAccess,
						 POBJECT_ATTRIBUTES ObjectAttributes,
						 HANDLE ParentProcess,
						 BOOLEAN InheritObjectTable,
						 HANDLE SectionHandle,
						 HANDLE DebugPort,
						 HANDLE ExceptionPort
						 );

// NtCreateProcessEx
typedef
NTSTATUS
(NTAPI *NTCREATEPROCESSEX)(
						   PHANDLE ProcessHandle,
						   ACCESS_MASK DesiredAccess,
						   POBJECT_ATTRIBUTES ObjectAttributes,
						   HANDLE ParentProcess,
						   BOOLEAN InheritObjectTable,
						   HANDLE SectionHandle OPTIONAL,
						   HANDLE DebugPort OPTIONAL,
						   HANDLE ExceptionPort OPTIONAL,
						   HANDLE Unknown
						   );

// NtOpenKey
typedef
NTSTATUS
(NTAPI *NTOPENKEY)(
				   PHANDLE				KeyHandle,
				   ACCESS_MASK			DesiredAccess,
				   POBJECT_ATTRIBUTES	ObjectAttributes
				   );

typedef
NTSTATUS 
(NTAPI *NTQUERYVALUEKEY)(
						 IN HANDLE  KeyHandle,
						 IN PUNICODE_STRING  ValueName,
						 IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
						 OUT PVOID  KeyValueInformation,
						 IN ULONG  Length,
						 OUT PULONG  ResultLength
						 );

typedef
NTSTATUS 
(NTAPI *NTENUMERATEKEY)(
						IN HANDLE  KeyHandle,
						IN ULONG  Index,
						IN KEY_INFORMATION_CLASS  KeyInformationClass,
						OUT PVOID  KeyInformation,
						IN ULONG  Length,
						OUT PULONG  ResultLength
						);


// NtCreateSection
typedef
NTSTATUS
(NTAPI *NTCREATESECTION)(
						 PHANDLE SectionHandle,
						 ACCESS_MASK DesiredAccess,
						 POBJECT_ATTRIBUTES ObjectAttributes,
						 PLARGE_INTEGER SectionSize,
						 ULONG Protect,
						 ULONG Attributes,
						 HANDLE FileHandle
						 );


typedef
NTSTATUS
(NTAPI *NTRESUMETHREAD)(
						IN	HANDLE		ThreadHandle,
						OUT	PULONG		PreviousSuspendCount OPTIONAL
						);

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
	ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX，参见MSDN中UpdateProcThreadAttribute的说明
	SIZE_T Size;        // Value的大小
	ULONG_PTR Value;    // 保存4字节数据（比如一个Handle）或数据指针
	ULONG Unknown;      // 总是0，可能是用来返回数据给调用者
} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
	ULONG Length;       // 结构总大小
	PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;


typedef
NTSTATUS
(NTAPI *NTCREATEUSERPROCESS)(
							 OUT PHANDLE ProcessHandle,
							 OUT PHANDLE ThreadHandle,
							 IN ACCESS_MASK ProcessDesiredAccess,
							 IN ACCESS_MASK ThreadDesiredAccess,
							 IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
							 IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
							 IN ULONG CreateProcessFlags,
							 IN ULONG CreateThreadFlags,
							 IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
							 IN PVOID Parameter9,
							 IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
							 );


typedef NTSTATUS (NTAPI *NTUSERBUILDHWNDLIST) ( IN ULONG hDesktop OPTIONAL, IN ULONG hParentWnd, IN ULONG HwndListType, IN ULONG ThreadId, OUT ULONG ARG_5, OUT HWND* pWnd, OUT ULONG* nBufSize); 
typedef INT      (NTAPI *NTUSERINTERNALGETWINDOWTEXT)(HWND hWnd, LPWSTR lpString, INT nMaxCount);
typedef HWND     (NTAPI *NTUSERFINDWINDOWEX)(HWND hwndParent, HWND hwndChildAfter, PUNICODE_STRING ucClassName, PUNICODE_STRING ucWindowName, ULONG ARG5); 
typedef DWORD    (NTAPI *NTUSERQUERYWINDOW)(HWND hWnd, DWORD Index);
typedef HDC		 (NTAPI *NTUSERGETDC)(IN HWND WindowHandle);
typedef ULONG    (NTAPI *NTUSERGETFOREGROUNDWINDOW)(VOID);
typedef HHOOK (NTAPI *NtUserSetWindowsHookEx_t)(IN HANDLE hmod, IN PUNICODE_STRING pstrLib OPTIONAL, IN DWORD idThread,
												IN int nFilterType, IN PROC pfnFilterProc, IN DWORD dwFlags);

typedef ULONG (NTAPI *NTGDIGETPIXEL)(HDC hDC,int XPos,int YPos);
typedef ULONG (NTAPI *NTUSERCALLONEPARAM)(DWORD param,DWORD RoutineType);

typedef VOID (NTAPI *KeInitializeSpinLock_ptr)(IN PKSPIN_LOCK  SpinLock);

typedef NTSTATUS (*NTGETCONTEXTTHREAD) (
										IN HANDLE ThreadHandle,
										OUT PCONTEXT Context
										);	
typedef NTSTATUS (*NTSETINFORMATIONTHREAD)(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength
	);
typedef NTSTATUS (NTAPI *T_ZwQueryInformationProcess)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS (NTAPI *T_ZwSetInformationProcess)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
	);

typedef NTSTATUS (NTAPI *T_ZwQueryInformationThread)(
	__in HANDLE ThreadHandle,
	__in THREADINFOCLASS ThreadInformationClass,
	__out_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS (NTAPI *NTRAISEHARDERROR) (
					NTSTATUS ErrorStatus,
					ULONG NumberOfParameters,
					ULONG UnicodeStringParameterMask,
					PULONG Parameters,
					ULONG ValidResponseOptions,
					PULONG Response
					);

typedef NTSTATUS (NTAPI *T_ZwQueryObject) (
     HANDLE Handle,
     OBJECT_INFORMATION_CLASS ObjectInformationClass,
     PVOID ObjectInformation,
     ULONG ObjectInformationLength,
     PULONG ReturnLength
    );
//////////////////////////////////////////////////////////////////////////
typedef NTSTATUS (*PSSUSPENDTHREAD)(IN PETHREAD Thread, OUT PULONG PreviousCount);
typedef NTSTATUS (*PSRESUMETHREAD)(IN PETHREAD Thread,  OUT PULONG PreviousCount);
typedef NTSTATUS (*PSSUSPENDPROCESS)(IN PEPROCESS ProcessHandle);
typedef PETHREAD (*PSGETNEXTPROCESSTHREAD)(IN PEPROCESS Process, IN PETHREAD Thread OPTIONAL);
typedef NTSTATUS (*PSRESUMEPROCESS)(IN PEPROCESS ProcessHandle);

typedef NTSTATUS (NTAPI *T_ZwCreateThread)(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientId,
	__in PCONTEXT ThreadContext,
	__in PINITIAL_TEB InitialTeb,
	__in BOOLEAN CreateSuspended
	);

VOID mySpinlockX(PKSPIN_LOCK SpinLock);
////////////////////////////////////////////////////////
typedef struct tagKEYBDINPUT {
	SHORT wVk;
	SHORT wScan;
	ULONG dwFlags;
	ULONG time;
	ULONG_PTR dwExtraInfo;
} KEYBDINPUT, *PKEYBDINPUT;

typedef struct tagMOUSEINPUT {
	LONG dx;
	LONG dy;
	ULONG mouseData;
	ULONG dwFlags;
	ULONG time;
	ULONG_PTR dwExtraInfo;
} MOUSEINPUT, *PMOUSEINPUT;

typedef struct tagHARDWAREINPUT {
	ULONG uMsg;
	SHORT wParamL;
	SHORT wParamH;
} HARDWAREINPUT, *PHARDWAREINPUT;

typedef struct tagINPUT { 
	ULONG type; 
	union {MOUSEINPUT mi; 
	KEYBDINPUT ki;
	HARDWAREINPUT hi;
	};
}INPUT, *PINPUT;
////////////////////////////////////////////////////////
typedef ULONG (NTAPI*NTUSERSENDINPUT)(ULONG,PINPUT,int);
typedef BOOL (NTAPI *NtUserTranslateMessage)(PULONG    lpMsg,  
											 DWORD dwhkl 
											 );

typedef NTSTATUS (NTAPI*NTDEVICEIOCONTROLFILE)(			
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine /*OPTIONAL*/,
	IN PVOID ApcContext /*OPTIONAL*/,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer /*OPTIONAL*/,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer /*OPTIONAL*/,
	IN ULONG OutputBufferLength
	);

typedef NTSTATUS (NTAPI *T_ZwAllocateVirtualMemory) (
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
	);

typedef NTSTATUS (NTAPI *T_ZwQueryVirtualMemory) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength
	);
#pragma pack (push, 1)

typedef PVOID* PNTPROC;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PNTPROC ServiceTable; 
	PULONG  CounterTable; 
	ULONG   ServiceLimit; 
	PUCHAR  ArgumentTable; 
}
SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;


typedef struct _SERVICE_DESCRIPTOR_TABLE 
{
	SYSTEM_SERVICE_TABLE ntoskrnl;  
	SYSTEM_SERVICE_TABLE win32k;    
	SYSTEM_SERVICE_TABLE iis;
	SYSTEM_SERVICE_TABLE unused;    
}
SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;


#pragma pack(1)


extern PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //根据WRK貌似只有check Build版才有
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

#pragma pack()

ServiceDescriptorTableEntry_t *KeServiceDescriptorTableShadow;

#define SYSCALL(function) MappedSystemCallTable[function]

#define SYSTEM_SERVICE(_function) MappedSystemCallTable[*(PULONG)((PUCHAR)_function+1)]
#define SYSTEM_SERVICE_IDX(_index) MappedSystemCallTable[_index]


#define SDW_SYSTEM_SERVICE(_function) KeServiceDescriptorTableShadow[0].ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]
#define SDW_SYSTEM_SERVICE_IDX(_index) KeServiceDescriptorTableShadow[0].ServiceTableBase[_index]

#define WIN32K_SERVICE(_function) KeServiceDescriptorTableShadow[1].ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]
#define WIN32K_SERVICE_IDX(_index) KeServiceDescriptorTableShadow[1].ServiceTableBase[_index]



//Gets the memory address of an unexported native API from its index in the SSDT
#define SYSTEMSERVICE_NE(_index)  MappedSystemCallTable[_index]

//Gets the SSDT index of a native API from its name
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)

//Exchanges in SSDT the pointer of an exported native API (_Function) with the pointer of a wrapper function (_Hook)
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
	_Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

//Exchanges in SSDT the pointer of an unexported native API (_Index) with the pointer of a wrapper function (_Hook)
#define HOOK_SYSCALL_NE(_Index, _Hook, _Orig )  \
	_Orig =  (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[_Index], (LONG) _Hook)

//Exchanges in SSDT the pointer of a wrapper function (_Hook) with the pointer to the original exported native API (_Function)

#define UNHOOK_SYSCALL(_Function, _Hook)  \
	(PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

//Exchanges in SSDT the pointer of a wrapper function (_Hook) with the pointer to the original unexported native API (_Index)
#define UNHOOK_SYSCALL_NE(_Index, _Hook)  \
	(PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[_Index], (LONG) _Hook)

extern PMDL		g_pmdlSystemCall;
extern PVOID	*MappedSystemCallTable;


typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles; 
	SYSTEM_HANDLE_INFORMATION Information[1]; 
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_THREADS 
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES 
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters; 
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;



NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData (
							  IN PVOID Base,
							  IN BOOLEAN MappedAsImage,
							  IN USHORT DirectoryEntry,
							  OUT PULONG Size
							  );

NTSYSAPI 
	BOOLEAN
	NTAPI
	FsRtlIsNameInExpression(
	PUNICODE_STRING Expression,
	PUNICODE_STRING Name,
	BOOLEAN IgnoreCase,
	PWCH UpcaseTable
	); 

NTKERNELAPI
	UCHAR *
	PsGetProcessImageFileName(
	PEPROCESS Process
	);
#endif
