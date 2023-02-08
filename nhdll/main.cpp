#include "stdafx.h"

_NT_BEGIN

#include "..\updb\module.h"
#include "log.h"
#include "..\inc\initterm.h"
#include "..\detour\detour.h"

void HookMsw(ThreadInfo* pti);
void UnhookMsw(ThreadInfo* pti);
void HookSspi(ThreadInfo* pti);
void UnhookSspi(ThreadInfo* pti);

BOOLEAN WINAPI DllMain(_In_ HMODULE hmod, _In_ DWORD dwReason, _In_opt_ ThreadInfo* pti)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		initterm();
		DisableThreadLibraryCalls(hmod);
		LOG(Init());
		LogTimeStamp();

		DBG_PRINT_ON();
		TrInit();
		if (0 <= SuspendAll(&pti))
		{
			HookMsw(pti);
			HookSspi(pti);
			ResumeAndFree(pti);
		}

		break;
	case DLL_PROCESS_DETACH:
		DbgPrint("DLL_PROCESS_DETACH %p\r\n", pti);

		if (pti)
		{
			// process is terminating
			UnhookSspi(0);
			UnhookMsw(0);
		}
		else
		{
			// FreeLibrary has been called or the DLL load failed 
			SuspendAll(&pti);
			UnhookSspi(pti);
			UnhookMsw(pti);
			ResumeAndFree(pti);
		}

		CModule::Cleanup();
		destroyterm();
		break;
	}
	return TRUE;
}

_NT_END