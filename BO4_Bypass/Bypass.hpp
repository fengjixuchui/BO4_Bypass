#pragma once
#include "stdafx.h"

class Bypass {
public:
	Bypass();
	~Bypass();
	static Bypass* GetInstance();
	bool Init(HMODULE hDll), Uninit();
private:
	bool detour_Functions(bool Status);
protected:
#pragma region Member
	static Bypass* Instance;
	static HANDLE hEvent, hProcessHandle, hThread;

	static p_NtQueryVirtualMemory o_NtQueryVirtualMemory;

	static p_EnumWindows o_EnumWindows;
	static p_NtUserQueryWindow o_NtUserQueryWindow;  // GetWindowThreadProcessId -> NtUserQueryWindow
	static p_NtUserFindWindowEx o_NtUserFindWindowEx;
	static p_NtUserWindowFromPoint o_NtUserWindowFromPoint;
	static p_NtUserGetForegroundWindow o_NtUserGetForegroundWindow;
	static p_NtUserGetThreadState o_NtUserGetThreadState;

	static p_NtOpenProcess o_NtOpenProcess;
	static p_NtQuerySystemInformation o_NtQuerySystemInformation;
	static p_NtQueryInformationThread o_NtQueryInformationThread;
	static p_NtSetInformationThread o_NtSetInformationThread;
	static p_NtReadVirtualMemory o_NtReadVirtualMemory;
	static p_ZwQueryInformationProcess o_ZwQueryInformationProcess;
	static p_ZwQueryInformationProcess o_NtWow64QueryInformationProcess64;
	static p_NtWow64QueryVirtualMemory64 o_NtWow64QueryVirtualMemory64;
	static p_NtGetContextThread o_NtGetContextThread;
	static p_NtOpenThread o_NtOpenThread;
	static p_NtWow64ReadVirtualMemory64 o_NtWow64ReadVirtualMemory64;
	static p_NtReadFile o_NtReadFile;
	static p_NtCreateFile o_NtCreateFile;
	static p_RtlInitUnicodeString o_RtlInitUnicodeString;
	static DWORD_PTR hModule;
#pragma endregion Member		
#pragma region Hooks
	static NTSTATUS NTAPI NtSetInformationThread_Hook(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
	static NTSTATUS NTAPI NtQueryVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
	static BOOL CALLBACK EnumWindows_Hook_EnumWindowsProc(HWND hWnd, LPARAM lParam);
	static BOOL WINAPI EnumWindows_Hook(WNDENUMPROC lpEnumFunc, LPARAM lParam);
	static DWORD_PTR NTAPI NtUserQueryWindow_Hook(HWND hWnd, DWORD_PTR Index);
	static HWND NTAPI NtUserFindWindowEx_Hook(IN HWND hwndParent, IN HWND hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType);
	static HWND APIENTRY NtUserWindowFromPoint_Hook(LONG X, LONG Y);
	static HWND APIENTRY NtUserGetForegroundWindow_Hook();
	static DWORD_PTR APIENTRY NtUserGetThreadState_Hook(USERTHREADSTATECLASS ThreadState);
	static NTSTATUS NTAPI NtOpenProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID Inject_GameId);
	static NTSTATUS NTAPI NtQuerySystemInformation_Hook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	static NTSTATUS NTAPI NtReadVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
	static NTSTATUS NTAPI NtWow64QueryVirtualMemory64_Hook(HANDLE ProcessHandle, PVOID64 BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, ULONGLONG MemoryInformationLength, PULONGLONG ReturnLength);
	static NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT pContext);
	static NTSTATUS NTAPI NtOpenThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID Inject_GameId);
	static NTSTATUS NTAPI NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
#pragma endregion Hooks
};