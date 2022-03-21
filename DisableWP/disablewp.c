#include <ntddk.h>
#include <intrin.h>

#define DEVICE_NAME L"\\Device\\ControlCr0"
#define LINK_NAME L"\\DosDevices\\ControlCr0"

#define IOCTL_REV_CR0 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_CR0 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING SymbolicLinkName;

NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	
	(pDevObj);
	NTSTATUS nStatus = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInLength;
	ULONG uOutLength;
	ULONG uWrite;
	ULONG cr0 = 0;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;

	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;

	uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case IOCTL_WRITE_CR0:
	{
		cr0 = __readcr0();
		cr0 &= 0xfffeffff;
		__writecr0(cr0);
		uWrite = __readcr0();
		memcpy(pIoBuffer, &uWrite, 4);
		nStatus = STATUS_SUCCESS;
		break;
	}
	case IOCTL_REV_CR0:
	{
		//memcpy(&uRead, pIoBuffer, 4);
		cr0 = __readcr0();
		cr0 |= 0x10000;
		__writecr0(cr0);
		uWrite = __readcr0();
		memcpy(pIoBuffer, &uWrite, 4);
		nStatus = STATUS_SUCCESS;
		break;
	}
	default:
		pIrp->IoStatus.Information = 0;
		break;
	}
	pIrp->IoStatus.Information = 4;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
	return;
}
NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}
NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING DeviceName;

	(RegistryPath);

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&SymbolicLinkName, LINK_NAME);
	status = IoCreateDevice(Driver, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (NT_SUCCESS(status))
	{

		Driver->DriverUnload = DriverUnload;
		IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
		for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			Driver->MajorFunction[i] = DriverDefaultHandle;
		}
		Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;
		//pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
		pDeviceObject->Flags |= DO_BUFFERED_IO;

	}

	return STATUS_SUCCESS;
}