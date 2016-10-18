#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
//#include <Tlhelp32.h>

#pragma comment (lib, "psapi.lib")
typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION { // Information Class 0
	LONG     ExitStatus;
	PVOID    TebBaseAddress;
	CLIENT_ID ClientId;
	LONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

extern "C" LONG(__stdcall *ZwQueryInformationThread) (
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	) = NULL;


extern "C" LONG(__stdcall *RtlNtStatusToDosError) (
	IN  ULONG status) = NULL;

char * GetErrorMessage(DWORD EID) {
	switch (EID) {
	case EXCEPTION_ACCESS_VIOLATION:
		return "线程违规读写:没有适当权限的虚拟地址";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "线程在底层硬件支持的边界检查下访问数组越界";
	case EXCEPTION_BREAKPOINT:
		return "遇到一个断点";
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		return "线程试图在不支持对齐的硬件上读写未对齐的数据";
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		return "浮点操作的一个操作数不正规.不正规的值表示太小而不能表示一个标准的浮点值";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return "线程浮点除零操作";
	case EXCEPTION_FLT_INEXACT_RESULT:
		return "浮点结果的操作不能准确的代替小数";
	case EXCEPTION_FLT_INVALID_OPERATION:
		return "其他浮点异常";
	case EXCEPTION_FLT_OVERFLOW:
		return "浮点操作的指数超过了相应类型的最大值";
	case EXCEPTION_FLT_STACK_CHECK:
		return "浮点操作的栈越界或下溢出";
	case EXCEPTION_FLT_UNDERFLOW:
		return "浮点操作的指数没有超过相应类型的最大值";
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "线程试图执行无效指令";
	case EXCEPTION_IN_PAGE_ERROR:
		return "线程试图访问一个不存在的页或者无法加载的页";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "线程试图整数除零";
	case EXCEPTION_INT_OVERFLOW:
		return "整数操作的结果占用了结果的最大符号位";
	case EXCEPTION_INVALID_DISPOSITION:
		return "异常处理程序给异常调度器返回了一个无效配置";
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		return "线程试图在一个不可继续执行的异常发生后继续执行";
	case EXCEPTION_PRIV_INSTRUCTION:
		return "线程试图执行当前机器模式不支持的指令";
	case EXCEPTION_SINGLE_STEP:
		return "单步异常";
	case EXCEPTION_STACK_OVERFLOW:
		return "栈溢出";
	default:
		return "未知错误";

	}
}

BOOL ShowThreadInfo(DWORD tid,char * Buffer)
{
	THREAD_BASIC_INFORMATION    tbi;
	PVOID                       startaddr;
	LONG                        status;
	HANDLE                      thread, process;
	LPVOID lpMsgBuf;
	thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (thread == NULL)
		return FALSE;
	status = ZwQueryInformationThread(thread,ThreadQuerySetWin32StartAddress,&startaddr,sizeof(startaddr),NULL);
	if (status < 0)
	{
		CloseHandle(thread);
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, RtlNtStatusToDosError(status), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
		sprintf_s(Buffer,1000, "获取线程信息时出现错误 : %s", (char *)lpMsgBuf);
		return FALSE;
	};
	//sprintf(TEXT("线程 %08x 的起始地址为 %p\n"), tid, startaddr);
	status = ZwQueryInformationThread(thread,ThreadBasicInformation,&tbi,sizeof(tbi),NULL);
	if (status < 0)
	{
		CloseHandle(thread);
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, RtlNtStatusToDosError(status), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
		sprintf_s(Buffer, 1000, "获取线程信息时出现错误 : %s", (char *)lpMsgBuf);
		return FALSE;
	};
	process = ::OpenProcess(PROCESS_ALL_ACCESS,FALSE,(DWORD)tbi.ClientId.UniqueProcess);
	if (process == NULL)
	{
		DWORD error = ::GetLastError();
		CloseHandle(thread);
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
		sprintf_s(Buffer, 1000, "获取线程信息时出现错误 : %s", (char *)lpMsgBuf);
		return FALSE;
	};
	TCHAR modname[0x100];
	GetModuleFileNameEx(process, NULL, modname, 0x100);
	GetMappedFileName(process,startaddr,modname,0x100);
	CloseHandle(process);
	CloseHandle(thread);
	char * buftstart;
	for (int i = strlen(modname); i > 0; i--) {
		if (modname[i] == '\\') {
			buftstart = &modname[i + 1];
			break;
		}
	}
	sprintf_s(Buffer, 1000, "发生在线程 : 0x%08X\n位于 : %s + 0x%08X", tid, buftstart, startaddr);
	return TRUE;
};

long __stdcall err(_EXCEPTION_POINTERS * excp)
{
	char Buffer[1000];
	char ThBuf[1000];
	TCHAR modname[0x100];
	LPVOID lpMsgBuf;
	char * buftstart;
	DWORD dw = GetLastError();
	ShowThreadInfo(GetCurrentThreadId(), ThBuf);
	GetModuleFileNameA(NULL, modname, 0x100);
	for (int i = strlen(modname); i > 0; i--) {
		if (modname[i] == '\\') {
			buftstart = &modname[i + 1];
			break;
		}
	}
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
	sprintf_s(Buffer, "在进程 %s[%d] 中捕获到未处理的异常. \n%s \n\nGetLastError 信息: \n错误码为 : %d \n错误信息为 : %s \nEXCEPTION_POINTERS 信息: \n错误发生于地址 0x%08X ,错误代码为 %08X \n错误信息为 : %s \n\nCPU寄存器为 \nEax : %08X    Ebx : %08X    Ecx : %08X\nEdx : %08X    Esi : %08X    Edi : %08X\nEip : %08X    Esp : %08X    Ebp : %08X\nEFlags : %08X\n\n是否继续执行程序？",
		buftstart,
		GetCurrentProcessId(),
		ThBuf,
		dw,
		(LPSTR)lpMsgBuf,
		excp->ExceptionRecord->ExceptionAddress,
		excp->ExceptionRecord->ExceptionCode,
		GetErrorMessage(excp->ExceptionRecord->ExceptionCode),
		excp->ContextRecord->Eax,
		excp->ContextRecord->Ebx, 
		excp->ContextRecord->Ecx,
		excp->ContextRecord->Edx,
		excp->ContextRecord->Esi,
		excp->ContextRecord->Edi,
		excp->ContextRecord->Eip,
		excp->ContextRecord->Esp,
		excp->ContextRecord->Ebp,
		excp->ContextRecord->EFlags
		);
	int result = MessageBoxA(NULL, Buffer, "捕获到异常", MB_YESNO | MB_TOPMOST);
	switch (result)
	{
	case IDYES:
		return EXCEPTION_CONTINUE_EXECUTION;
		break;
	case IDNO:
		return EXCEPTION_EXECUTE_HANDLER;
		break;
	}
	return   EXCEPTION_CONTINUE_EXECUTION;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	HINSTANCE hNTDLL;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hNTDLL = GetModuleHandle("ntdll");
		(FARPROC&)ZwQueryInformationThread = GetProcAddress(hNTDLL, "ZwQueryInformationThread");
		(FARPROC&)RtlNtStatusToDosError = GetProcAddress(hNTDLL, "RtlNtStatusToDosError");
		SetUnhandledExceptionFilter(err);
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return (TRUE);
}