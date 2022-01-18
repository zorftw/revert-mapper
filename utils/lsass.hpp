#pragma once

#pragma comment (lib, "ntdll.lib")
#pragma comment(lib, "Wtsapi32.lib")

#include <TlHelp32.h>
#include <WtsApi32.h>

#ifndef LSASS_H
namespace mapper::lsass {

	namespace detail {

		constexpr auto SYSTEMHANDLEINFORMATION = 16;

		typedef struct _SYSTEM_HANDLE {
			ULONG ProcessId;
			UCHAR ObjectTypeNumber;
			UCHAR Flags;
			USHORT Handle;
			PVOID Object;
			ACCESS_MASK GrantedAccess;
		} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

		typedef struct _SYSTEM_HANDLE_INFORMATION {
			ULONG HandleCount; // Or NumberOfHandles if you prefer
			SYSTEM_HANDLE Handles[1];
		} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

		typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
			DWORD UniqueProcessId;
			WORD HandleType;
			USHORT HandleValue;
			PVOID Object;
			ACCESS_MASK GrantedAccess;
		} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

		typedef struct _OBJECT_TYPE_INFORMATION {
			UNICODE_STRING TypeName;
			ULONG TotalNumberOfObjects;
			ULONG TotalNumberOfHandles;
			ULONG TotalPagedPoolUsage;
			ULONG TotalNonPagedPoolUsage;
			ULONG TotalNamePoolUsage;
			ULONG TotalHandleTableUsage;
			ULONG HighWaterNumberOfObjects;
			ULONG HighWaterNumberOfHandles;
			ULONG HighWaterPagedPoolUsage;
			ULONG HighWaterNonPagedPoolUsage;
			ULONG HighWaterNamePoolUsage;
			ULONG HighWaterHandleTableUsage;
			ULONG InvalidAttributes;
			GENERIC_MAPPING GenericMapping;
			ULONG ValidAccessMask;
			BOOLEAN SecurityRequired;
			BOOLEAN MaintainHandleCount;
			UCHAR TypeIndex;
			CHAR ReservedByte;
			ULONG PoolType;
			ULONG DefaultPagedPoolCharge;
			ULONG DefaultNonPagedPoolCharge;
		} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

		EXTERN_C NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG);
	}

	// speaks for itself
	auto find_pid_by_name(const std::string& name) -> std::size_t {
		auto hn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (!hn)
			return 0;

		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof PROCESSENTRY32;

		if (Process32First(hn, &pe))
		{
			do
			{
				if (std::strstr(pe.szExeFile, name.c_str()) != nullptr)
				{
					CloseHandle(hn);
					return pe.th32ProcessID;
				}
			} while (Process32Next(hn, &pe));
		}

		return 0;
	}

	VOID message_box(LPCSTR Text, LPCSTR Title)
	{
		DWORD response;

		WTSSendMessageA(WTS_CURRENT_SERVER_HANDLE,       // hServer
			WTSGetActiveConsoleSessionId(),  // ID for the console seesion (1)
			const_cast<LPSTR>(Title),        // MessageBox Caption
			strlen(Title),                   // 
			const_cast<LPSTR>(Text),         // MessageBox Text
			strlen(Text),                    // 
			MB_OK,                           // Buttons, etc
			10,                              // Timeout period in seconds
			&response,                       // What button was clicked (if bWait == TRUE)
			TRUE);                          // bWait - Blocks until user click
	}

	// steal a handle from ()
	auto steal_handle(const std::size_t targetProcessId) -> HANDLE {
		NTSTATUS status;
		ULONG handleInfoSize = 0x10000;

		auto handleInfo = reinterpret_cast<detail::PSYSTEM_HANDLE_INFORMATION>(malloc(handleInfoSize));

		while ((status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)detail::SYSTEMHANDLEINFORMATION, handleInfo, handleInfoSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH)
			handleInfo = reinterpret_cast<detail::PSYSTEM_HANDLE_INFORMATION>(realloc(handleInfo, handleInfoSize *= 2));

		if (!NT_SUCCESS(status))
		{
			message_box("Error: Handle Not Found", "Error!");
		}

		for (auto i = 0; i < handleInfo->HandleCount; i++)
		{
			auto handle = handleInfo->Handles[i];

			const auto process = reinterpret_cast<HANDLE>(handle.Handle);
			if (handle.ProcessId == GetCurrentProcessId() && GetProcessId(process) == targetProcessId)
				return process;
		}

		free(handleInfo);

		return nullptr;
	}

}

#define LSASS_H
#endif