#pragma once
#include "stdafx.h"

#pragma region _PE_STRUCT_
#ifdef _WIN64
typedef struct _WPEB_LDR_DATA {
	ULONG			Length;
	UCHAR			Initialized;
	ULONG64			SsHandle;
	LIST_ENTRY64	InLoadOrderModuleList;
	LIST_ENTRY64	InMemoryOrderModuleList;
	LIST_ENTRY64	InInitializationOrderModuleList;
	PVOID64			EntryInProgress;
	UCHAR			ShutdownInProgress;
	PVOID64			ShutdownThreadId;
} WPEB_LDR_DATA, *WPPEB_LDR_DATA;

typedef struct _WPEB {
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	BYTE				Reserved0;
	ULONG				Reserved1;
	ULONG64				Reserved3;
	ULONG64				ImageBaseAddress;
	_WPEB_LDR_DATA*     LoaderData;
	ULONG64				ProcessParameters;
}WPEB, *WPPEB;

typedef struct _WLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY	    	InLoadOrderModuleList;
	LIST_ENTRY	     	InMemoryOrderModuleList;
	LIST_ENTRY   		InInitializationOrderModuleList;
	ULONG64				BaseAddress;
	ULONG64				EntryPoint;
	ULONG				SizeOfImage;
	UNICODE_STRING		FullDllName;
	UNICODE_STRING		BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
} WLDR_DATA_TABLE_ENTRY, *WPLDR_DATA_TABLE_ENTRY;

#else

typedef struct _WPEB_LDR_DATA {
	DWORD					Length;
	UCHAR					Initialized;
	PVOID	                SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY				InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID					EntryInProgress;
	UCHAR					ShutdownInProgress;
	PVOID					ShutdownThreadId;
} WPEB_LDR_DATA, *WPPEB_LDR_DATA;

typedef struct _WPEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	BYTE Reserved2[9];
	WPPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved3[448];
	ULONG SessionId;
}WPEB, *WPPEB;

typedef struct _WLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY            InLoadOrderModuleList;
	LIST_ENTRY            InMemoryOrderModuleList;
	LIST_ENTRY            InInitializationOrderModuleList;
	PVOID                 BaseAddress;
	PVOID                 EntryPoint;
	ULONG                 SizeOfImage;
	UNICODE_STRING        FullDllName;
	UNICODE_STRING        BaseDllName;
	ULONG                 Flags;
	USHORT				  LoadCount;
	USHORT                 TlsIndex;
	LIST_ENTRY            HashTableEntry;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT *	EntryPointActivationContext;
	PVOID					PatchInformation;
	LIST_ENTRY				ForwarderLinks;
	LIST_ENTRY				ServiceTagLinks;
	LIST_ENTRY				StaticLinks;
	PVOID					ContextInformation;
	DWORD					OriginalBase;
	LARGE_INTEGER			LoadTime;
} WLDR_DATA_TABLE_ENTRY, *WPLDR_DATA_TABLE_ENTRY;
#endif

#pragma endregion



namespace ModuleHidden
{

	static bool Zero(PVOID addr, ULONG_PTR size) {
		DWORD old = 0;
		if (VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old)) {
			ZeroMemory(addr, size);
			VirtualProtect(addr, size, old, &old);
			return TRUE;
		}
		return FALSE;
	}

	static bool CleanPEJunk(ULONG_PTR hDll) {
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hDll;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			DbgLog::Log("ModuleHidden: Invalid IMAGE_DOS_SIGNATURE! \r\n");
			return FALSE;
		}

		PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((PCHAR)hDll + dosHeader->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE) {
			DbgLog::Log("ModuleHidden: Invalid IMAGE_NT_SIGNATURE! \r\n");
			return FALSE;
		}
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pINH + 1);

#ifdef _WIN64
		PIMAGE_DATA_DIRECTORY pdd = ((PIMAGE_NT_HEADERS64)pINH)->OptionalHeader.DataDirectory;
#else
		PIMAGE_DATA_DIRECTORY pdd = ((PIMAGE_NT_HEADERS32)headers)->OptionalHeader.DataDirectory;
#endif

		PIMAGE_IMPORT_DESCRIPTOR iat = (PIMAGE_IMPORT_DESCRIPTOR)(hDll + pdd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (; iat->Name; ++iat)
		{
			auto modName = (PCHAR)(hDll + iat->Name);
#ifdef _WIN64
			PIMAGE_THUNK_DATA64 entry = (PIMAGE_THUNK_DATA64)(hDll + iat->OriginalFirstThunk);
#else
			PIMAGE_THUNK_DATA32 entry = (PIMAGE_THUNK_DATA32)(hDll + iat->OriginalFirstThunk);
#endif
			for (ULONG_PTR index = 0; entry->u1.AddressOfData; index += sizeof(ULONG_PTR), ++entry)
			{
				auto pImport = (PIMAGE_IMPORT_BY_NAME)(hDll + entry->u1.AddressOfData);
				auto importName = pImport->Name;
				DbgLog::Log("ModuleHidden: Wiping import: %s \r\n", importName);
				Zero(importName, strlen(importName));
			}

			DbgLog::Log("ModuleHidden: Wiping import module: %s \r\n", modName);
			Zero(modName, strlen(modName));
		}


		for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++)
		{
			auto section = pSectionHeader[i];
			const char* pName = (const char*)section.Name;

			auto pSectionStart = hDll + section.VirtualAddress;
			auto pSectionEnd = pSectionStart + section.SizeOfRawData;

			// ×Ö·û´®»á±»²ÁÈ¥
			if (pName[0] == '.' && pName[1] == 'r' && pName[2] == 'd' && pName[3] == 'a' && pName[4] == 't'&& pName[5] == 'a')
			{
				ULONG_PTR shitBase = 0;

				for (ULONG_PTR ptr = pSectionStart; ptr < pSectionEnd - 4; ptr++)
				{
					auto str = (char*)ptr;
					if (str[0] == 'G' && str[1] == 'C' && str[2] == 'T' && str[3] == 'L') // whatever that "GCTL" shit is, we gotta clean it up
						shitBase = ptr;
				}
				auto shitSize = 676; // magic number. Change if not enough
				if (shitBase)
				{
					Zero((void*)shitBase, shitSize);
					DbgLog::Log("ModuleHidden: Cleaned GCTL. \r\n");
				}
				else
				{
					DbgLog::Log("ModuleHidden: Couldn't find GCTL shit. \r\n");
				}
			}
			else if (0
				|| pName[0] == '.' && pName[1] == 'r' && pName[2] == 's' && pName[3] == 'r' && pName[4] == 'c'						// .rsrc
				|| pName[0] == '.' && pName[1] == 'r' && pName[2] == 'e' && pName[3] == 'l' && pName[4] == 'o'&& pName[5] == 'c'	// .reloc	
				/*|| pName[0] == '.' && pName[1] == 'p' && pName[2] == 'd' && pName[3] == 'a' && pName[4] == 't'&& pName[5] == 'a' */) // .pdata assuming we need exception support.
			{
				DbgLog::Log("ModuleHidden: Wiping section %s. \r\n", pName);
				Zero((void*)pSectionStart, section.SizeOfRawData);
			}
			else if (pName[0] == '.' && pName[1] == 'd' && pName[2] == 'a' && pName[3] == 't' && pName[4] == 'a') // .data this particular meme can be unstable
			{
				// DbgLog::Log("ModuleHidden: Wiping C++ exception data. \r\n");
				// Zero((void*)(pSectionEnd - 0x1B7), 0x1B7);
				// DbgLog::Log("ModuleHidden: Wiped. \r\n");
			}
		}

		Zero((void*)hDll, pINH->OptionalHeader.SizeOfHeaders);

		return TRUE;
	}

	static bool CleanPESection(HMODULE hDll) {
		_MEMORY_BASIC_INFORMATION mbi;
		DWORD Old = 0;
		ZeroMemory(&mbi, sizeof(mbi));
		if (VirtualQuery(hDll, &mbi, sizeof(mbi))) {
			return Zero(mbi.BaseAddress, mbi.RegionSize);
		}
		return FALSE;
	}

	static bool OnAttach(HMODULE hDll)
	{
		// MessageBoxA(NULL, "#1", "CrashTest", 0);
#ifdef _WIN64
		PLIST_ENTRY64 pListEntry = 0;
		_WLDR_DATA_TABLE_ENTRY* pModule = 0;
		_WPEB* pPEB = reinterpret_cast<_WPEB*>(__readgsqword(0x60));
#else
		PLIST_ENTRY pListEntry = 0;
		_WLDR_DATA_TABLE_ENTRY* pModule = 0;
		_WPEB* pPEB = reinterpret_cast<_WPEB*>(__readfsdword(0x30));
#endif
		if (!pPEB)
			return false;
		// MessageBoxA(NULL, "#2", "CrashTest", 0);
#ifdef _WIN64
		pListEntry = reinterpret_cast<PLIST_ENTRY64>(pPEB->LoaderData->InLoadOrderModuleList.Flink);
#else
		pListEntry = reinterpret_cast<PLIST_ENTRY>(pPEB->LoaderData->InLoadOrderModuleList.Flink);
#endif
		BOOL bFound = FALSE;
		while (pListEntry != &pPEB->LoaderData->InLoadOrderModuleList && pListEntry != NULL) {
			pModule = reinterpret_cast<_WLDR_DATA_TABLE_ENTRY*>(pListEntry->Flink);
#ifdef _WIN64
			if (pModule->BaseAddress == reinterpret_cast<ULONG64>(hDll))
			{
				pModule->InLoadOrderModuleList.Flink->Blink = pModule->InLoadOrderModuleList.Blink;
				pModule->InLoadOrderModuleList.Blink->Flink = pModule->InLoadOrderModuleList.Flink;

				pModule->InMemoryOrderModuleList.Flink->Blink = pModule->InMemoryOrderModuleList.Blink;
				pModule->InMemoryOrderModuleList.Blink->Flink = pModule->InMemoryOrderModuleList.Flink;

				pModule->InInitializationOrderModuleList.Flink->Blink = pModule->InInitializationOrderModuleList.Blink;
				pModule->InInitializationOrderModuleList.Blink->Flink = pModule->InInitializationOrderModuleList.Flink;

				bFound = TRUE;
				break;
			}
			pListEntry = reinterpret_cast<PLIST_ENTRY64>(pListEntry->Flink);
#else
			if (pModule->BaseAddress == hDll)
			{
				pModule->InLoadOrderModuleList.Flink->Blink = pModule->InLoadOrderModuleList.Blink;
				pModule->InLoadOrderModuleList.Blink->Flink = pModule->InLoadOrderModuleList.Flink;

				pModule->InMemoryOrderModuleList.Flink->Blink = pModule->InMemoryOrderModuleList.Blink;
				pModule->InMemoryOrderModuleList.Blink->Flink = pModule->InMemoryOrderModuleList.Flink;

				pModule->InInitializationOrderModuleList.Flink->Blink = pModule->InInitializationOrderModuleList.Blink;
				pModule->InInitializationOrderModuleList.Blink->Flink = pModule->InInitializationOrderModuleList.Flink;

				bFound = TRUE;
				break;
			}
			pListEntry = reinterpret_cast<PLIST_ENTRY>(pListEntry->Flink);
#endif
		}
		// MessageBoxA(NULL, "#3", "CrashTest", 0);

		// Clean Junk
		CleanPEJunk((ULONG_PTR)hDll);

		// Clean PE selection
		// Crash when injected with ManualMap£¬ use `if (bFound)` to avoid.
		if (bFound)
			CleanPESection(hDll);

		return true;
	}
	static bool OnDetach()
	{
		return true;
	}
}