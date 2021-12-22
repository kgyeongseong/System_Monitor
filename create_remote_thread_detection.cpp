#include <ntifs.h>
#include <ntddk.h>
#include "SysMon.h"
#include "SysMonCommon.h"
#include "AutoLock.h"

// prototypes
DRIVER_UNLOAD SysMonUnload;
DRIVER_DISPATCH SysMonCreateClose, SysMonRead;
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
void OnImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
void PushItem(LIST_ENTRY* entry);

Globals g_Globals;

/**
 * .
 * 
 * @param  DriverObject 드라이버 객체
 * @param 
 * @return 
 */
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{

	auto status = STATUS_SUCCESS;

	InitializeListHead(&g_Globals.ItemsHead);
	g_Globals.Mutex.Init();

	PDEVICE_OBJECT DeviceObject = nullptr;

	UNICODE_STRING symLink      = RTL_CONSTANT_STRING(L"\\??\\sysmon");
	bool symLinkCreated         = false;

	do {
		UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\sysmon");

		/*디바이스 객체 생성*/
		status                 = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);

		/*디바이스 객체 생성에 실패한 경우*/
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device (0x%08X)\n", status));
			break;
		}

		/*디바이스 객체를 Direct I/O으로 설정*/
		DeviceObject->Flags |= DO_DIRECT_IO; // DO == Device Object

		/*디바이스 객체의 심볼릭 링크 생성*/
		status = IoCreateSymbolicLink(&symLink, &devName);

		/*디바이스 객체의 심볼릭 링크 생성에 실패한 경우*/
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create sym link (0x%08X)\n", status));
			break;
		}

		/*디바이스 객체 생성 체크*/
		symLinkCreated = true;

		/*프로세스 생성, 소멸 알림 콜백 함수 등록*/
		// register for process notifications
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);

		/*프로세스 생성, 소멸 알림 콜백 함수 등록에 실패한 경우*/
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register process callback (0x%08X)\n", status));
			break;
		}

		/*스레드 생성, 소멸 알림 콜백 함수 등록*/
		status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);

		/*스레드 생성, 소멸 알림 콜백 함수 등록에 실패한 경우*/
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set thread callbacks (status=%08X)\n", status));
			break;
		}

		/*이미지 로드 알림 콜백 함수 등록*/
		status = PsSetLoadImageNotifyRoutine(OnImageNotify);

		/*이미지 로드 알림 콜백 함수 등록에 실패한 경우*/
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set load image callbacks (status=%08X)\n", status));
			break;
		}

	} while (false);

	/*디바이스 객체 생성에 실패한 경우*/
	/*디바이스 객체의 심볼릭 링크 생성에 실패한 경우*/
	/*프로세스 생성, 소멸 알림 콜백 함수 등록에 실패한 경우*/
	/*스레드 생성, 소멸 알림 콜백 함수 등록에 실패한 경우*/
	/*이미지 로드 알림 콜백 함수 등록에 실패한 경우*/
	if (!NT_SUCCESS(status)) {
		/*디바이스 객체의 심볼릭 링크가 생성된 경우*/
		if (symLinkCreated)
			/*디바이스 객체의 심볼릭 링크 삭제*/
			IoDeleteSymbolicLink(&symLink);
		/*디바이스 객체가 생성된 경우*/
		if (DeviceObject)
			/*디바이스 객체 삭제*/
			IoDeleteDevice(DeviceObject);
	}

	/*드라이버 언로드 콜백 함수 설정*/
	DriverObject->DriverUnload = SysMonUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SysMonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = SysMonRead;

	return status;
}

/**
 * @fn				 void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
 * @brief			 프로세스 생성, 소멸하는 경우 실행되는 함수
 * @param Process
 * @param ProcessId  HANDLE == Process ID
 * @param CreateInfo PS_CREATE_NOTIFY_INFO 구조체 포인터
 */
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo) {
		/**
		* process block
		*/
		UNICODE_STRING notepad;
		RtlInitUnicodeString(&notepad, L"\\??\\C:\\Windows\\system32\\notepad.exe");
		if (RtlCompareUnicodeString(CreateInfo->ImageFileName, &notepad, TRUE) == 0)
		{
			KdPrint(("This process will be BLOCK!!\n"));
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}

		// process create
		USHORT allocSize = sizeof(FullItem<ProcessCreateInfo>);
		USHORT commandLineSize = 0;
		USHORT ImageFileNameSize = 0;
		if (CreateInfo->CommandLine) {
			commandLineSize = CreateInfo->CommandLine->Length;
			allocSize += commandLineSize;
		}
		if (CreateInfo->ImageFileName) {
			ImageFileNameSize = CreateInfo->ImageFileName->Length;
			allocSize += ImageFileNameSize;
		}
		auto info = (FullItem<ProcessCreateInfo>*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
		if (info == nullptr) {
			KdPrint((DRIVER_PREFIX "failed allocation\n"));
			return;
		}

		auto& item = info->Data;
		KeQuerySystemTimePrecise(&item.Time);
		item.Type = ItemType::ProcessCreate;
		item.Size = sizeof(ProcessCreateInfo) + commandLineSize + ImageFileNameSize;
		item.ProcessId = HandleToULong(ProcessId);
		item.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

		if (commandLineSize > 0) {
			memcpy((UCHAR*)&item + sizeof(item), CreateInfo->CommandLine->Buffer, commandLineSize);
			item.CommandLineLength = commandLineSize / sizeof(WCHAR); // length in WCHARs
			item.CommandLineOffset = sizeof(item);
		}
		else {
			item.CommandLineLength = 0;
		}
		if (ImageFileNameSize > 0) {
			memcpy((UCHAR*)&item + sizeof(item), CreateInfo->ImageFileName->Buffer, ImageFileNameSize);
			item.ImageFileNameLength = ImageFileNameSize / sizeof(WCHAR); // length in WCHARs
			item.ImageFileNameOffset = sizeof(item);
		}
		else {
			item.ImageFileNameLength = 0;
		}
		PushItem(&info->Entry);
	}
	else {
		// process exit
		auto info = (FullItem<ProcessExitInfo>*)ExAllocatePoolWithTag(PagedPool, sizeof(FullItem<ProcessExitInfo>), DRIVER_TAG);
		if (info == nullptr) {
			KdPrint((DRIVER_PREFIX "failed allocation\n"));
			return;
		}

		auto& item = info->Data;
		KeQuerySystemTime(&item.Time);
		item.Type = ItemType::ProcessExit;
		item.ProcessId = HandleToULong(ProcessId);
		item.Size = sizeof(ProcessExitInfo);

		PushItem(&info->Entry);
	}
}

/**
 * @fn	  void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
 * @brief 스레드 생성, 소멸하는 경우 실행되는 함수
 * @param ProcessId
 * @param ThreadId
 * @param Create
 */
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	auto size = sizeof(FullItem<ThreadCreateExitInfo>);
	auto info = (FullItem<ThreadCreateExitInfo>*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
	if (info == nullptr) {
		KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
		return;
	}
	/**
	* http://dreamofareverseengineer.blogspot.com/2014/06/monitoring-thread-injection.html
	* Monitoring Thread Injection
	*/
	if (Create) { // 스레드가 생성되었고
		/*EPROCESS 구조체 변수 선언*/
		PEPROCESS Process;

		/*EPROCESS 구조체 참조 포인터 획득하는 함수*/
		NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);

		/*EPROCESS 구조체 참조 포인터 획득에 실패한 경우*/
		if (!NT_SUCCESS(status))
		{
			KdPrint(("PsLookupProcessByProcessId()\n"));
			return;
		}

		HANDLE idProcess = PsGetCurrentProcessId();
		HANDLE idThread = PsGetCurrentThreadId();

		if (HandleToULong(idProcess) == 4)
		{
			// ignore the system process

			return;
		}

		/*EPROCESS 구조체에서 삽질*/
		LPTSTR lpProcess = (LPTSTR)Process;
		lpProcess = (LPTSTR)(lpProcess + 0x170); // ImageFileName dt _EPROCESS

		if (idProcess != ProcessId) // 스레드를 생성한 프로세스가 현재 프로세스가 아니면
		{
			PEPROCESS iProcess;
			LPTSTR lpProcessIn;
			status = PsLookupProcessByProcessId(idProcess, &iProcess);
			lpProcessIn = (LPTSTR)iProcess;
			lpProcessIn = (LPTSTR)(lpProcessIn + 0x170); // ImageFIleName dt _EPROCESS

			LPTSTR ActiveThreads = (LPTSTR)(lpProcess + 0x2C); // ActiveThreads dt _EPROCESS

			if ((UINT32)*ActiveThreads > 1) // first thread is always created remotely
				KdPrint(("[EDR Thread Injection] Remote Process %d (%s) <thread %d> was injected by Process %d (%s) <thread %d> | Remote Process # Threads: %d\n", ProcessId, lpProcess, ThreadId, idProcess, lpProcessIn, idThread, (UINT32)*ActiveThreads));
		}
	}
	// & : 참조형 변수
	auto& item = info->Data;
	KeQuerySystemTimePrecise(&item.Time);
	item.Size = sizeof(item);
	item.Type = Create ? ItemType::ThreadCreate : ItemType::ThreadExit;
	item.ProcessId = HandleToULong(ProcessId);
	item.ThreadId = HandleToULong(ThreadId);

	PushItem(&info->Entry);
}

/**
 * @fn void OnImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
 * @brief 이미지 로드하는 경우 실행되는 함수
 * \param FullImageName
 * \param ProcessId
 * \param ImageInfo IMAGE_INFO 구조체 포인터
 */
void OnImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (ProcessId == nullptr) {
		// system image, ignore
		return;
	}

	auto size = sizeof(FullItem<ImageLoadInfo>);
	auto info = (FullItem<ImageLoadInfo>*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
	if (info == nullptr) {
		KdPrint((DRIVER_PREFIX "Faield to allocate memory\n"));
		return;
	}

	memset(info, 0, size);

	auto& item = info->Data;
	KeQuerySystemTimePrecise(&item.Time);
	item.Size = sizeof(item);
	item.Type = ItemType::ImageLoad;
	item.ProcessId = HandleToULong(ProcessId);
	item.ImageSize = ImageInfo->ImageSize;
	item.LoadAddress = ImageInfo->ImageBase;

	if (FullImageName) {
		memcpy(item.ImageFileName, FullImageName->Buffer, min(FullImageName->Length, MaxImageFileSize * sizeof(WCHAR)));
	}
	else {
		wcscpy_s(item.ImageFileName, L"(unknown)");
	}

	PushItem(&info->Entry);
}

void PushItem(LIST_ENTRY* entry)
{
	AutoLock<FastMutex> lock(g_Globals.Mutex);
	if (g_Globals.ItemCount > 1024) {
		// too many items, remove oldest one
		auto head = RemoveHeadList(&g_Globals.ItemsHead);
		g_Globals.ItemCount--;
		auto item = CONTAINING_RECORD(head, FullItem<ItemHeader>, Entry);
		ExFreePool(item);
	}
	InsertTailList(&g_Globals.ItemsHead, entry);
	g_Globals.ItemCount++;
}

NTSTATUS SysMonRead(PDEVICE_OBJECT, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto len = stack->Parameters.Read.Length;
	auto status = STATUS_SUCCESS;
	auto count = 0;
	/*
	* NT_ASSERT 매크로는 표현식을 테스트합니다. 표현식이 false이면 매크로는 STATUS_ASSERTION_FAILURE 예외를 발생시키고
	* 예외를 무시하거나 예외를 처리하는 커널 디버거에 칩입하는 옵션을 제공합니다.
	*/
	NT_ASSERT(Irp->MdlAddress); // we're using Direct I/O

	/*
	* MmGetSystemAddressForMdlSafe 매크로는 지정된 MDL이 설명하는 버퍼에 대해 페이징되지 않은 시스템 공간 가상 주소를 반환합니다.
	*/
	auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	if (!buffer) {
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else {
		AutoLock lock(g_Globals.Mutex); // C++ 17
		while (true) {
			if (IsListEmpty(&g_Globals.ItemsHead)) // can also check g_Gloabls.ItemCount
				break;

			auto entry = RemoveHeadList(&g_Globals.ItemsHead);
			auto info = CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry);
			auto size = info->Data.Size;
			if (len < size) {
				// user's buffer is full, insert item back
				InsertHeadList(&g_Globals.ItemsHead, entry);
				break;
			}
			g_Globals.ItemCount--;
			memcpy(buffer, &info->Data, size);
			len -= size;
			buffer += size;
			count += size;
			// free data after copy
			ExFreePool(info);
		}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = count;
	IoCompleteRequest(Irp, 0);
	return status;
}

void SysMonUnload(PDRIVER_OBJECT DriverObject)
{
	// unregister image notifications
	PsRemoveLoadImageNotifyRoutine(OnImageNotify);
	// unregister thread notifications
	PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	// unregister process notifications
	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\sysmon");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	// free remaining items
	while (!IsListEmpty(&g_Globals.ItemsHead)) {
		auto entry = RemoveHeadList(&g_Globals.ItemsHead);
		ExFreePool(CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry));
	}
}

NTSTATUS SysMonCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}
