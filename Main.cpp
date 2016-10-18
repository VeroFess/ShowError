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
		return "�߳�Υ���д:û���ʵ�Ȩ�޵������ַ";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "�߳��ڵײ�Ӳ��֧�ֵı߽����·�������Խ��";
	case EXCEPTION_BREAKPOINT:
		return "����һ���ϵ�";
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		return "�߳���ͼ�ڲ�֧�ֶ����Ӳ���϶�дδ���������";
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		return "���������һ��������������.�������ֵ��ʾ̫С�����ܱ�ʾһ����׼�ĸ���ֵ";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return "�̸߳���������";
	case EXCEPTION_FLT_INEXACT_RESULT:
		return "�������Ĳ�������׼ȷ�Ĵ���С��";
	case EXCEPTION_FLT_INVALID_OPERATION:
		return "���������쳣";
	case EXCEPTION_FLT_OVERFLOW:
		return "���������ָ����������Ӧ���͵����ֵ";
	case EXCEPTION_FLT_STACK_CHECK:
		return "���������ջԽ��������";
	case EXCEPTION_FLT_UNDERFLOW:
		return "���������ָ��û�г�����Ӧ���͵����ֵ";
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "�߳���ͼִ����Чָ��";
	case EXCEPTION_IN_PAGE_ERROR:
		return "�߳���ͼ����һ�������ڵ�ҳ�����޷����ص�ҳ";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "�߳���ͼ��������";
	case EXCEPTION_INT_OVERFLOW:
		return "���������Ľ��ռ���˽����������λ";
	case EXCEPTION_INVALID_DISPOSITION:
		return "�쳣���������쳣������������һ����Ч����";
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		return "�߳���ͼ��һ�����ɼ���ִ�е��쳣���������ִ��";
	case EXCEPTION_PRIV_INSTRUCTION:
		return "�߳���ͼִ�е�ǰ����ģʽ��֧�ֵ�ָ��";
	case EXCEPTION_SINGLE_STEP:
		return "�����쳣";
	case EXCEPTION_STACK_OVERFLOW:
		return "ջ���";
	default:
		return "δ֪����";

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
		sprintf_s(Buffer,1000, "��ȡ�߳���Ϣʱ���ִ��� : %s", (char *)lpMsgBuf);
		return FALSE;
	};
	//sprintf(TEXT("�߳� %08x ����ʼ��ַΪ %p\n"), tid, startaddr);
	status = ZwQueryInformationThread(thread,ThreadBasicInformation,&tbi,sizeof(tbi),NULL);
	if (status < 0)
	{
		CloseHandle(thread);
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, RtlNtStatusToDosError(status), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
		sprintf_s(Buffer, 1000, "��ȡ�߳���Ϣʱ���ִ��� : %s", (char *)lpMsgBuf);
		return FALSE;
	};
	process = ::OpenProcess(PROCESS_ALL_ACCESS,FALSE,(DWORD)tbi.ClientId.UniqueProcess);
	if (process == NULL)
	{
		DWORD error = ::GetLastError();
		CloseHandle(thread);
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
		sprintf_s(Buffer, 1000, "��ȡ�߳���Ϣʱ���ִ��� : %s", (char *)lpMsgBuf);
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
	sprintf_s(Buffer, 1000, "�������߳� : 0x%08X\nλ�� : %s + 0x%08X", tid, buftstart, startaddr);
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
	sprintf_s(Buffer, "�ڽ��� %s[%d] �в���δ������쳣. \n%s \n\nGetLastError ��Ϣ: \n������Ϊ : %d \n������ϢΪ : %s \nEXCEPTION_POINTERS ��Ϣ: \n�������ڵ�ַ 0x%08X ,�������Ϊ %08X \n������ϢΪ : %s \n\nCPU�Ĵ���Ϊ \nEax : %08X    Ebx : %08X    Ecx : %08X\nEdx : %08X    Esi : %08X    Edi : %08X\nEip : %08X    Esp : %08X    Ebp : %08X\nEFlags : %08X\n\n�Ƿ����ִ�г���",
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
	int result = MessageBoxA(NULL, Buffer, "�����쳣", MB_YESNO | MB_TOPMOST);
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