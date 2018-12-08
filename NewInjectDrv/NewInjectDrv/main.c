#include <ntddk.h>
#include <windef.h>
//////////////////////////////////////////////////////////////////////////
//驱动初始化代码部分
//////////////////////////////////////////////////////////////////////////
//通信定义
#define		FILE_DEVICE_GOM		 0x00008811
#define		BEGINBGP_CTL        (ULONG) CTL_CODE(FILE_DEVICE_GOM, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
//名字
#define NT_DEVICE_NAME L"\\Device\\gg134"
#define DOS_DEVICE_NAME L"\\DosDevices\\gg134"

#define CMD_STRING "GgTestDemo"
#define CMD_LENGTH (sizeof(CMD_STRING)-1)

typedef struct _CMD_CONTEXT_
{
	DWORD dwKey;
	DWORD dwLoadlibraryA;
	DWORD dwDispatchApc;
	CHAR  szDll[MAX_PATH];
}CMD_CONTEXT,*PCMD_CONTEXT;

//////////////////////////////////////////////////////////////////////////
VOID InitInjectApc();
VOID SetAddress(DWORD dwLoadLibrary,DWORD dwApcDispatch,LPCSTR lpszDllName);
//////////////////////////////////////////////////////////////////////////
PFILE_FULL_EA_INFORMATION
	KeFindEA(
	IN PFILE_FULL_EA_INFORMATION  StartEA,
	IN PCHAR	TargetName,
	IN USHORT	TargetNameLength
	)
{
	USHORT i;
	BOOLEAN fbFound;
	PFILE_FULL_EA_INFORMATION ea;

	PAGED_CODE();

	do {
		fbFound = TRUE;

		ea = StartEA;

		StartEA = (FILE_FULL_EA_INFORMATION *)((PUCHAR)StartEA + ea->NextEntryOffset);

		if (ea->EaNameLength != TargetNameLength) {
			continue;
		}

		for (i=0; i < ea->EaNameLength; i++) {
			if (ea->EaName[i] == TargetName[i]) {
				continue;
			}
			fbFound = FALSE;
			break;
		}

		if (fbFound) {
			return ea;
		}

	} while(ea->NextEntryOffset != 0);

	return NULL;
}
//////////////////////////////////////////////////////////////////////////
//这里做处理
//////////////////////////////////////////////////////////////////////////

NTSTATUS ProcessEA(PFILE_FULL_EA_INFORMATION EaBuffer)
{
	PFILE_FULL_EA_INFORMATION Cmd;
	PCMD_CONTEXT cmd_ctx;
	Cmd = KeFindEA(EaBuffer,CMD_STRING,CMD_LENGTH);
	if (Cmd)
	{
		if (Cmd->EaValueLength<sizeof(CMD_CONTEXT))
		{
			return STATUS_INVALID_PARAMETER;
		}
		cmd_ctx = (PCMD_CONTEXT)&Cmd->EaName[Cmd->EaNameLength+1];
		//这里处理CMD就ok了
		DbgPrint("CMd %x\r\n",cmd_ctx->dwKey);
		SetAddress(cmd_ctx->dwLoadlibraryA,cmd_ctx->dwDispatchApc,cmd_ctx->szDll);
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}
////////////////////////////////////////////////////////////////////////// 
BOOLEAN OnDeviceControl( IN PFILE_OBJECT FileObject,
	IN BOOLEAN bWait,
	IN PVOID InputBuffer, IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer, IN ULONG OutputBufferLength,
	IN ULONG IoControlCode, OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject)
{
	IoStatus->Status = STATUS_UNSUCCESSFUL ;
	IoStatus->Information = 0;


	//set the status success
	//set the information to 0 
	switch( IoControlCode)
	{
	default:
		IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
		//return error
		break;
	}
	return TRUE;
}
NTSTATUS
	DeviceControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP pIrp
	)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpStack;
	PVOID inputBuffer, outputBuffer;
	ULONG inputBufferLength, outputBufferLength;
	ULONG ioControlCode;

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation( pIrp);

	//get the current Irp stack location 
	if (irpStack -> MajorFunction == IRP_MJ_DEVICE_CONTROL )
	{

		//we only need the device io control

		inputBuffer = pIrp->AssociatedIrp.SystemBuffer;//irpStack->Parameters.DeviceIoControl.Type3InputBuffer;

		inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

		outputBuffer = pIrp->AssociatedIrp.SystemBuffer;

		outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;


		//system use the same buffer in device io control  

		ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
		if( (ioControlCode&3) == METHOD_NEITHER){
			inputBuffer = irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
			outputBuffer = pIrp->UserBuffer;
		}

		OnDeviceControl( irpStack->FileObject, TRUE,
			inputBuffer, inputBufferLength,
			outputBuffer, outputBufferLength,
			ioControlCode, &pIrp->IoStatus, DeviceObject);

	}
	IoCompleteRequest( pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS
	DrvCreate(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFILE_FULL_EA_INFORMATION StartEA, ea;

	StartEA = (PFILE_FULL_EA_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
	if ( StartEA != NULL )
		ntStatus = ProcessEA(StartEA);
	

	Irp -> IoStatus.Status = ntStatus;
	Irp -> IoStatus.Information = 0;

	IoCompleteRequest ( Irp, IO_NO_INCREMENT );

	return ntStatus;
}
NTSTATUS
	DrvClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}
VOID
	DrvUnload(
	IN PDRIVER_OBJECT DriverObject
	)
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING uniWin32NameString;
	NTSTATUS        ntStatus;

	RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );

	IoDeleteSymbolicLink( &uniWin32NameString );

	if ( deviceObject != NULL )
	{
		IoDeleteDevice( deviceObject );
	}

}
NTSTATUS
	DriverEntry(
	IN PDRIVER_OBJECT		DriverObject,
	IN PUNICODE_STRING		RegistryPath
	)
{
	NTSTATUS        ntStatus;
	PDEVICE_OBJECT  DeviceObject = NULL;
	UNICODE_STRING  UniDeviceName;
	UNICODE_STRING  UniSymLink;

	RtlInitUnicodeString(&UniDeviceName, NT_DEVICE_NAME);
	

	ntStatus = IoCreateDevice(
		DriverObject,
		0,
		&UniDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&UniSymLink, DOS_DEVICE_NAME);
	ntStatus = IoCreateSymbolicLink(&UniSymLink, &UniDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		DrvUnload(DriverObject);
		return ntStatus;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DrvUnload;

	InitInjectApc();
	
	return STATUS_SUCCESS;
}