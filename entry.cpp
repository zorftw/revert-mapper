#include "utils/mapper.hpp"
#include "utils/remote_process.hpp"
#include "utils/lsass.hpp"

#include <fstream>

void initialize(void* DLL_Param, void* injection_flag) {
	mapper::DLL_PARAM* pdllParam = reinterpret_cast<mapper::DLL_PARAM*>(DLL_Param);
	int* injectionflag = reinterpret_cast<int*>(injection_flag);

	auto handle = mapper::lsass::steal_handle(mapper::lsass::find_pid_by_name(pdllParam->TargetProcessName));

	if (!handle) {
		*injectionflag = false;
		return;
	}

	remote::detail::process = handle;
	auto modules = remote::get_remote_modules();

	auto addy = remote::find_remote_export("kernel32.dll", "VirtualUnlock");
	auto addy3 = remote::find_remote_export("kernel32.dll", "DbgUiDebugActiveProcess");
	auto addy2 = remote::find_remote_export("ntdll.dll", "DbgUserBreakPoint", false);

	std::ofstream out("C:\\find_remote.txt");

	out << "Address: 0x" << std::hex << addy << std::endl;
	out << "DbGUiDebugActiveProcess 0x" << std::hex << addy3 << std::endl;
	out << "address 2: 0x" << std::hex << addy2 << std::endl;

	out.close();

	// cleanup
	//VirtualFree((void*)pdllParam->pTargetDllBuffer, 0, MEM_RELEASE);
	//VirtualFree((void*)pdllParam, 0, MEM_RELEASE);

	remote::detail::process = INVALID_HANDLE_VALUE;
	*injectionflag = true;
	return;
}

long __stdcall DllMain(HMODULE module, std::uint32_t reason, void* lp)
{
	if (reason == DLL_PROCESS_ATTACH)
		initialize(lp, module);

	return true;
}