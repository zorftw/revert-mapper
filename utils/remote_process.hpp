#pragma once

#ifndef REMOTE_PROCESS_H
#define REMOTE_PROCESS_H

#include "mapper.hpp"
#include "lsass.hpp"
#include <codecvt>
#include <algorithm>

#include <fstream>
#include <map>

namespace remote {

	namespace detail {
		inline auto process = INVALID_HANDLE_VALUE;

		typedef struct _PROCESS_BASIC_INFORMATION64 {
			ULONGLONG Reserved1;
			ULONGLONG PebBaseAddress;
			ULONGLONG Reserved2[2];
			ULONGLONG UniqueProcessId;
			ULONGLONG Reserved3;
		} PROCESS_BASIC_INFORMATION64;

		struct s_remote_module {
			char name[256];
			std::uintptr_t base;

			friend bool operator<(const s_remote_module& a, const s_remote_module& b) {
				return a.base < b.base;
			}
		};

		inline std::vector<s_remote_module> _module_cache;
		inline std::map<s_remote_module, std::vector< std::pair<std::string, std::uint64_t>>> _remote_export_cache;
	}

	auto set_target(HANDLE handle) -> void {
		detail::process = handle;
	}

	auto check_process_handle() -> bool {
		return detail::process != INVALID_HANDLE_VALUE;
	}

	auto read_pbi(detail::PROCESS_BASIC_INFORMATION64& info) -> void {
		if (!check_process_handle()) {
			info.UniqueProcessId = -1;
			return;
		}

		auto status = NtQueryInformationProcess(detail::process, ProcessBasicInformation, &info, sizeof info, NULL);

		if (!NT_SUCCESS(status)) {
			info.UniqueProcessId = -1;
			return;
		}

		// success, lol!
	}

	auto rpm(std::uint64_t address, std::uint8_t* buffer, std::size_t len) -> bool {
		static auto ntdll = GetModuleHandle("ntdll.dll");

		if (!ntdll)
			return false;

		static auto rpm_proc = GetProcAddress(ntdll, "NtReadVirtualMemory");

		if (!rpm_proc)
			return false;

		return NT_SUCCESS(reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE,
			PVOID,
			PVOID,
			ULONG,
			PULONG)>(rpm_proc)(detail::process, (void*)address, buffer, len, nullptr));
	}

	auto read_peb_buffer() -> std::vector<std::uint8_t> {
		detail::PROCESS_BASIC_INFORMATION64 pbi = { 0 };
		read_pbi(pbi);

		if (pbi.UniqueProcessId == -1)
			return std::vector<std::uint8_t>{};

		std::vector<std::uint8_t> res = std::vector<std::uint8_t>(sizeof PEB);
		std::fill(std::begin(res), std::end(res), 0);

		if (!rpm(pbi.PebBaseAddress, &res[0], sizeof PEB))
			return std::vector<std::uint8_t>{};

		return res;
	}

	template <typename T>
	auto read(std::uint64_t address, std::size_t len = sizeof T) -> std::vector<std::uint8_t> {

		std::vector<std::uint8_t> buffer = std::vector<std::uint8_t>(len);
		std::fill(std::begin(buffer), std::end(buffer), 0);

		if (!rpm(address, &buffer[0], len))
			return std::vector<std::uint8_t>{};

		return buffer;

	}

	template <typename T>
	auto read_type(std::uint64_t address, std::size_t len = sizeof T) -> T {
		T buffer{ 0 };

		if (!rpm(address, (std::uint8_t*)&buffer, len))
			return T{ 0 };

		return buffer;
	}

	// Names of modules 
	std::string convert_unicode_to_utf8(std::vector<uint8_t>& raw_bytes)
	{
		std::vector<uint16_t> unicode(raw_bytes.size() >> 1, 0);
		memcpy(unicode.data(), raw_bytes.data(), raw_bytes.size());

		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

		const std::wstring wide_string(unicode.begin(), unicode.end());
		const std::string utf8_string = converter.to_bytes(wide_string);

		return utf8_string;
	}

	auto free(std::intptr_t address) {
		return VirtualFreeEx(detail::process, (void*)address, 0, MEM_RELEASE);
	}

	auto write(std::intptr_t address, void* buffer, std::size_t size) {
		return WriteProcessMemory(detail::process, (void*)address, buffer, size, nullptr);
	}

	// alloc memory for our DLL in x64 memory space
	auto alloc_virtual_memory(std::size_t size) -> std::intptr_t {

		int tries = 0;

		auto address = VirtualAllocEx(detail::process, (void*)(std::numeric_limits<std::uint32_t>::max)(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		tries++;

		if (!((std::intptr_t)address > (std::numeric_limits<std::uint32_t>::max)()))
		{
			do {
				address = (void*)((std::intptr_t)(std::numeric_limits<std::uint32_t>::max)() + 0x1000 * tries);
				tries++;

				address = VirtualAllocEx(detail::process, address, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				if ((std::intptr_t)address > (std::numeric_limits<std::uint32_t>::max)())
					return (std::intptr_t)address;

				VirtualFreeEx(detail::process, address, 0, MEM_RELEASE);

			} while (tries < 10);
		}
		else {
			return (std::intptr_t)address;
		}

		return false;
	}

	auto get_module_cache() -> std::vector<detail::s_remote_module> {
		if (detail::_module_cache.size() > 0)
			return detail::_module_cache;

		return std::vector<detail::s_remote_module>{0};
	}

	// Had to write this specifically in char or else the STL didn't want to use it in std::transform calls, for what reason I don't know
	// but ig it has something to do with type forcing.
	char to_lower(char in)
	{
		return std::tolower(in);
	}

	// TODO: CACHE THIS
	auto find_remote_export(std::string mod, std::string name, bool x86 = true) {
		auto _cache = get_module_cache();

		if (!_cache.size() > 0)
			return (std::uintptr_t)0;

		if (!check_process_handle())
			return (std::uintptr_t)0;

		std::vector<detail::s_remote_module> cache;

		// copy cache
		std::copy_if(std::begin(_cache), std::end(_cache), std::back_inserter(cache), 
			[&](detail::s_remote_module mod) -> auto { 
			return x86 ? mod.base <= (std::numeric_limits<std::uint32_t>::max)() : mod.base >= (std::numeric_limits<std::uint32_t>::max)(); 
		});

		// lower names for simplicity sake
		std::transform(std::begin(cache), std::end(cache), std::begin(cache), [&](detail::s_remote_module mod) -> auto {
			std::transform(std::begin(mod.name), std::end(mod.name), std::begin(mod.name), to_lower);
			return mod;
		});

		// lower fn name
		std::transform(std::begin(name), std::end(name), std::begin(name), to_lower);

		// find temp module
		auto rm_module = std::find_if(std::begin(cache), std::end(cache), [&](detail::s_remote_module remote) -> bool { return std::strstr(remote.name, mod.c_str()); });

		if (rm_module == std::end(cache))
			return (std::uintptr_t)0;
		
		std::vector<std::uint8_t> temp = read<IMAGE_DOS_HEADER>(rm_module->base);
		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(temp.data());
		
		// Do the thing.
		const auto do_the_thing = [&](IMAGE_DATA_DIRECTORY* edirp) -> std::uintptr_t {

			// if this moulde hasn't been cached before
			if (detail::_remote_export_cache.find(*rm_module) == std::end(detail::_remote_export_cache)) {
				auto addy_to_img_export_descriptor = rm_module->base + edirp->VirtualAddress;

				auto _ied = read_type<IMAGE_EXPORT_DIRECTORY>(addy_to_img_export_descriptor);
				auto ied = &_ied;

				auto table_length = sizeof DWORD * ied->NumberOfFunctions;

				auto address_table_buffer = read<DWORD>(rm_module->base + ied->AddressOfFunctions, table_length);
				auto address_table = reinterpret_cast<DWORD*>(address_table_buffer.data());

				auto name_table_buffer = read<DWORD>(rm_module->base + ied->AddressOfNames, table_length);
				auto name_table = reinterpret_cast<DWORD*>(name_table_buffer.data());

				auto ordinal_table_buffer = read<WORD>(rm_module->base + ied->AddressOfNameOrdinals, sizeof WORD * ied->NumberOfFunctions);
				auto ordinal_table = reinterpret_cast<WORD*>(ordinal_table_buffer.data());

				for (unsigned int i = 0; i < ied->NumberOfFunctions; ++i)
				{
					auto name_address = (rm_module->base + name_table[i]);
					auto name_buffer = read<char>(name_address, (sizeof std::uint8_t) * 64);
					char* fn_name = (char*)name_buffer.data();

					auto to_normal = std::string(fn_name);
					std::transform(std::begin(to_normal), std::end(to_normal), std::begin(to_normal), to_lower);

					auto relative_offset = address_table[ordinal_table[i]];
					auto exported_address = ((std::uint64_t)rm_module->base + relative_offset);

					detail::_remote_export_cache[*rm_module].push_back(std::make_pair(to_normal, exported_address));

					name_buffer.clear();
				}
			}

			
			auto entry = detail::_remote_export_cache.find(*rm_module);
			// it's cached now, check if it exists and look up the function
			if (entry != std::end(detail::_remote_export_cache))
			{
				auto res = std::find_if(std::begin(entry->second), std::end(entry->second), [&](std::pair<std::string, std::uint64_t> p) -> bool {
					return std::strstr(p.first.c_str(), name.c_str());
				});

				if (res != std::end(entry->second))
					return res->second;

				return 0;
			}
			else return 0;
		};

		/*
			As far as I know there's no easy way to switch typedefs depending on a runtime variable,
			so do it the hard way for now
		
		*/
		if (x86) {
			temp = read<IMAGE_NT_HEADERS32>(rm_module->base + dos->e_lfanew);
			auto nt = (PIMAGE_NT_HEADERS32)(temp.data());

			DWORD old_prot;
			VirtualProtectEx(remote::detail::process, (void*)rm_module->base, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old_prot);

			auto edirp = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			std::uintptr_t addy;
			if (addy = do_the_thing(edirp))
			{
				VirtualProtectEx(remote::detail::process, (void*)rm_module->base, nt->OptionalHeader.SizeOfHeaders, old_prot, &old_prot);
				return addy;
			}
			
			VirtualProtectEx(remote::detail::process, (void*)rm_module->base, nt->OptionalHeader.SizeOfHeaders, old_prot, &old_prot);
		}
		else {
			temp = read<IMAGE_NT_HEADERS>(rm_module->base + dos->e_lfanew);
			auto nt = (PIMAGE_NT_HEADERS)(temp.data());

			DWORD old_prot;
			VirtualProtectEx(remote::detail::process, (void*)rm_module->base, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old_prot);

			auto edirp = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			
			std::uintptr_t addy;
			if (addy = do_the_thing(edirp))
			{
				VirtualProtectEx(remote::detail::process, (void*)rm_module->base, nt->OptionalHeader.SizeOfHeaders, old_prot, &old_prot);
				return addy;
			}

			VirtualProtectEx(remote::detail::process, (void*)rm_module->base, nt->OptionalHeader.SizeOfHeaders, old_prot, &old_prot);
		}

		return (std::uintptr_t)0;
	}

	std::vector<detail::s_remote_module> get_remote_modules() {
		if (!check_process_handle())
			return std::vector<detail::s_remote_module>{0};

		/*
		auto data = read_peb_buffer();

		if (data.size() == 0)
			return std::vector<detail::s_remote_module>{};

		std::vector<detail::s_remote_module> res;

		PEB* peb = reinterpret_cast<PEB*>(data.data());
		auto peb_ldr_data = read<PEB_LDR_DATA>(reinterpret_cast<std::uint64_t>(peb->Ldr));
		PEB_LDR_DATA* peb_ldr = reinterpret_cast<PPEB_LDR_DATA>(peb_ldr_data.data());
		PEB_LDR_DATA* loader_data = (PEB_LDR_DATA*)peb->Ldr;
		
		const uintptr_t address_to_head = (std::uintptr_t)(((std::uintptr_t)peb_ldr->InMemoryOrderModuleList.Flink - (std::uintptr_t)peb_ldr) + peb->Ldr);

		std::uint64_t address = (std::uint64_t)peb_ldr->InMemoryOrderModuleList.Flink;

		do {
			auto entry = read<LDR_DATA_TABLE_ENTRY>(address);
			LDR_DATA_TABLE_ENTRY* ldr_table_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(entry.data());	

			auto unicode_name = read<std::uint8_t>((std::uint64_t)ldr_table_entry->FullDllName.Buffer, (std::size_t)ldr_table_entry->FullDllName.MaximumLength);
			std::string name = convert_unicode_to_utf8(unicode_name);

			detail::s_remote_module mod = {};
			mod.name = name;
			mod.base = (std::uintptr_t)ldr_table_entry->DllBase;
			res.push_back(mod);

			ldr_table_entry = (LDR_DATA_TABLE_ENTRY*)read<LDR_DATA_TABLE_ENTRY>((std::uint64_t)ldr_table_entry->InMemoryOrderLinks.Flink).data();
			address = (uintptr_t)ldr_table_entry->InMemoryOrderLinks.Flink;

		} while (address != address_to_head);
		*/
		HMODULE hMods[1024];
		DWORD cbNeeded;
		unsigned int i;

		std::vector<detail::s_remote_module> res;

		if (EnumProcessModulesEx(detail::process, hMods, sizeof hMods, &cbNeeded, LIST_MODULES_ALL))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				TCHAR szModName[MAX_PATH];

				// Get the full path to the module's file.

				if (GetModuleFileNameEx(detail::process, hMods[i], szModName,
					sizeof(szModName) / sizeof(TCHAR)))
				{
					// Print the module name and handle value.
					detail::s_remote_module mod{0};
					sprintf_s(mod.name, "%s", szModName);
					mod.base = (std::uint64_t)hMods[i];

					res.push_back(mod);
				}
			}
		}

		detail::_module_cache = res;
		return res;
	}
}

#endif