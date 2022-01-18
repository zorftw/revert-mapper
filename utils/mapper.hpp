#pragma once

#ifndef MAPPER_H
#define MAPPER_H

#include <Windows.h>
#include <winternl.h>
#include <string>
#include <cstdint>
#include <ntstatus.h>
#include <Psapi.h>
#include <vector>

#include "remote_process.hpp"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

namespace mapper {

	struct DLL_PARAM {
		std::uint64_t pTargetDllBuffer;
		std::uint64_t addressOfHookFunction;
		char TargetProcessName[32];
	};

	auto map_into_remote(std::intptr_t buffer) -> bool {
		if (!buffer)
			return false;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
		auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + dos->e_lfanew);

		// simple access
		auto file = &nt->FileHeader;
		auto optional = &nt->OptionalHeader;

		auto remote_buffer = remote::alloc_virtual_memory(nt->OptionalHeader.SizeOfImage);

		auto section_header = IMAGE_FIRST_SECTION(nt);

		// write headers
		if (!remote::write(remote_buffer, (void*)buffer, optional->SizeOfHeaders))
		{
			remote::free(remote_buffer);
			return false;
		}

		// fix imports
		std::uint8_t* location_delta = (std::uint8_t*)(remote_buffer - optional->ImageBase);
		if (location_delta)
		{
			if (!optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
				return 0;

			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(buffer + optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
				{
					if (RELOC_FLAG(*pRelativeInfo))
					{
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(buffer + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(location_delta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}

		// these are all in x64 mem space
		auto possible_imports = { "ntdll.dll", "wow64.dll", "wow64win.dll", "wow64cpu.dll" };

		// fixing imprts
		if (optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(buffer + optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name)
			{
				char* szMod = reinterpret_cast<char*>(buffer + pImportDescr->Name);

				HINSTANCE hDll = LoadLibraryA(szMod);

				ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(buffer + pImportDescr->OriginalFirstThunk);
				ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(buffer + pImportDescr->FirstThunk);

				if (!pThunkRef)
					pThunkRef = pFuncRef;

				for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
				{
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
						*pFuncRef = reinterpret_cast<ULONG_PTR>(GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
					else
					{
						auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(buffer + (*pThunkRef));
						*pFuncRef = reinterpret_cast<ULONG_PTR>(GetProcAddress(hDll, pImport->Name));
					}
				}

				++pImportDescr;
			}
		}

		// free libraries we loaded because we don't want to leave dangled 
		// stuff around, note that these DLLs are NEVER in lsass so if they
		// were to check this could hbe dangerous
		for (const auto& imp : possible_imports)
			if (std::strcmp(imp, "ntdll.dll") != 0)
				FreeLibrary(GetModuleHandle(imp));

		// write sections 
		for (size_t i = 0; i < file->NumberOfSections; ++i, ++section_header)
		{
			if (section_header->SizeOfRawData)
			{
				if (!remote::write(remote_buffer + section_header->VirtualAddress, (void*)(buffer + section_header->PointerToRawData), section_header->SizeOfRawData))
				{
					remote::free(remote_buffer);
					return false;
				}
			}
		}

		/*
		if (optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(remote_buffer + optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback)(base, DLL_PROCESS_ATTACH, nullptr);
		}
		*/
		auto hthread = CreateRemoteThreadEx(remote::detail::process, 0, 0, (LPTHREAD_START_ROUTINE)(remote_buffer + optional->AddressOfEntryPoint), (void*)remote_buffer, 0, 0, 0);
		NtClose(hthread);
	}
}

#endif