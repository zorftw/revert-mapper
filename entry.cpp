#include "utils/mapper.hpp"
#include "utils/remote_process.hpp"
#include "utils/lsass.hpp"

#include <fstream>

void initialize(void* DLL_Param, void* injection_flag) {
	using namespace mapper;

	DLL_PARAM* pdllParam = reinterpret_cast<DLL_PARAM*>(DLL_Param);
	int* injectionflag = reinterpret_cast<int*>(injection_flag);

	auto handle = lsass::steal_handle(lsass::find_pid_by_name(pdllParam->TargetProcessName));

	if (!handle) {
		*injectionflag = false;
		return;
	}

	remote::detail::process = handle;
	auto addy = remote::find_remote_export("kernel32.dll", "VirtualUnlock");

	// cleanup
	VirtualFree((void*)pdllParam->pTargetDllBuffer, 0, MEM_RELEASE);
	
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