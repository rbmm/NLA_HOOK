#include "stdafx.h"

_NT_BEGIN

#include "..\updb\module.h"
#include "log.h"
#include "dump.h"
#include "..\detour\detour.h"

SECURITY_STATUS 
SEC_ENTRY
hook_AcquireCredentialsHandleW(
							   _In_opt_  LPWSTR pszPrincipal,                // Name of principal
							   _In_      LPWSTR pszPackage,                  // Name of package
							   _In_      unsigned long fCredentialUse,       // Flags indicating use
							   _In_opt_  void * pvLogonId,                   // Pointer to logon ID
							   _In_opt_  void * pAuthData,                   // Package specific data
							   _In_opt_  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
							   _In_opt_  void * pvGetKeyArgument,            // Value to pass to GetKey()
							   _Out_     PCredHandle phCredential,           // (out) Cred Handle
							   _Out_opt_ PTimeStamp ptsExpiry                // (out) Lifetime (optional)
							   )
{
	static LONG s_id;

	DumpStack(0, __FUNCTION__, Fprint);

	LONG id = InterlockedIncrementNoFence(&s_id);

	DbgPrint("\r\n>> AcquireCredentialsHandle<H%u>(\"%S\", \"%S\", %p)\r\n", id, pszPrincipal, pszPackage, pAuthData);

	if (pAuthData)
	{
		if (!wcscmp(pszPackage, CREDSSP_NAME))
		{
			Dump((PCREDSSP_CRED)pAuthData);
		}
		else if (!wcscmp(pszPackage, TS_SSP_NAME))
		{
			DumpGen(pAuthData);
		}
		else if (!wcscmp(pszPackage, UNISP_NAME) || !wcscmp(pszPackage, SCHANNEL_NAME))
		{
			Dump((PSCHANNEL_CRED)pAuthData);
		}
	}

	SECURITY_STATUS s = AcquireCredentialsHandleW(
		pszPrincipal,                // Name of principal
		pszPackage,                  // Name of package
		fCredentialUse,       // Flags indicating use
		pvLogonId,                   // Pointer to logon ID
		pAuthData,                   // Package specific data
		pGetKeyFn,           // Pointer to GetKey() func
		pvGetKeyArgument,            // Value to pass to GetKey()
		phCredential,           // (out) Cred Handle
		ptsExpiry                // (out) Lifetime (optional)
		);

	DbgPrint("\r\n<< AcquireCredentialsHandle<H%u>(\"%S\" %p%p ) = %x\r\n", id, pszPrincipal, phCredential->dwLower, phCredential->dwUpper, s);
	return s;
}

SECURITY_STATUS 
SEC_ENTRY
hook_AcquireCredentialsHandleA(
							   _In_opt_  LPSTR ,                // Name of principal
							   _In_      LPSTR pszPackage,                  // Name of package
							   _In_      unsigned long fCredentialUse,       // Flags indicating use
							   _In_opt_  void * pvLogonId,                   // Pointer to logon ID
							   _In_opt_  void * pAuthData,                   // Package specific data
							   _In_opt_  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
							   _In_opt_  void * pvGetKeyArgument,            // Value to pass to GetKey()
							   _Out_     PCredHandle phCredential,           // (out) Cred Handle
							   _Out_opt_ PTimeStamp ptsExpiry                // (out) Lifetime (optional)
							   )
{
	DbgPrint("A> AcquireCredentialsHandle\r\n");

	WCHAR wz[0x64];
	MultiByteToWideChar(CP_UTF8, 0, pszPackage, MAXULONG, wz, _countof(wz));

	return hook_AcquireCredentialsHandleW(
		0,                // Name of principal
		wz,                  // Name of package
		fCredentialUse,       // Flags indicating use
		pvLogonId,                   // Pointer to logon ID
		pAuthData,                   // Package specific data
		pGetKeyFn,           // Pointer to GetKey() func
		pvGetKeyArgument,            // Value to pass to GetKey()
		phCredential,           // (out) Cred Handle
		ptsExpiry                // (out) Lifetime (optional)
		);
}

SECURITY_STATUS 
SEC_ENTRY
hook_AcceptSecurityContext(
					  _In_opt_    PCredHandle phCredential,               // Cred to base context
					  _In_opt_    PCtxtHandle phContext,                  // Existing context (OPT)
					  _In_opt_    PSecBufferDesc pInput,                  // Input buffer
					  _In_        unsigned long fContextReq,              // Context Requirements
					  _In_        unsigned long TargetDataRep,            // Target Data Rep
					  _Inout_opt_ PCtxtHandle phNewContext,               // (out) New context handle
					  _Inout_opt_ PSecBufferDesc pOutput,                 // (inout) Output buffers
					  _Out_       unsigned long * pfContextAttr,  // (out) Context attributes
					  _Out_opt_   PTimeStamp ptsExpiry                    // (out) Life span (OPT)
					  )
{
	static LONG s_id;

	DumpStack(0, __FUNCTION__, Fprint);

	LONG id = InterlockedIncrementNoFence(&s_id);

	DbgPrint("\r\n>> AcceptSecurityContext<A%u>( %p%p, %p/%p <<%p %p>>)\r\n", 
		id, phCredential->dwLower, phCredential->dwUpper, 
		phContext, phNewContext, pInput, pOutput);

	if (phContext)
	{
		DbgPrint("hContext = %p%p\r\n", phContext->dwLower, phContext->dwUpper);
	}

	Dump(pInput, "Input-", id, 'A');

	SECURITY_STATUS s = AcceptSecurityContext(phCredential, phContext, pInput, fContextReq, 
		TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsExpiry);

	Dump(pInput, "Input+", id, 'A');

	if (0 <= s)
	{
		if (phNewContext)
		{
			DbgPrint("phNewContext := %p%p\r\n", phNewContext->dwLower, phNewContext->dwUpper);
		}

		Dump(pOutput, "Output", id, 'A');
	}

	DbgPrint("\r\n<< AcceptSecurityContext<A%u> () = %x\r\n", id, s);

	return s;
}


SECURITY_STATUS 
SEC_ENTRY
hook_InitializeSecurityContextW(
								_In_opt_    PCredHandle phCredential,               // Cred to base context
								_In_opt_    PCtxtHandle phContext,                  // Existing context (OPT)
								_In_opt_    SEC_WCHAR * pszTargetName,              // Name of target
								_In_        unsigned long fContextReq,              // Context Requirements
								_In_        unsigned long Reserved1,                // Reserved, MBZ
								_In_        unsigned long TargetDataRep,            // Data rep of target
								_In_opt_    PSecBufferDesc pInput,                  // Input Buffers
								_In_        unsigned long Reserved2,                // Reserved, MBZ
								_Inout_opt_ PCtxtHandle phNewContext,               // (out) New Context handle
								_Inout_opt_ PSecBufferDesc pOutput,                 // (inout) Output Buffers
								_Out_       unsigned long * pfContextAttr,  // (out) Context attrs
								_Out_opt_   PTimeStamp ptsExpiry                    // (out) Life span (OPT)
								)
{
	static LONG s_id;

	LONG id = InterlockedIncrementNoFence(&s_id);

	DumpStack(0, __FUNCTION__, Fprint);

	DbgPrint("\r\n>> InitializeSecurityContext<I%u>( %p%p \"%S\", %p/%p <<%p %p>>)\r\n", 
		id, phCredential->dwLower, phCredential->dwUpper, 
		pszTargetName, phContext, phNewContext, pInput, pOutput);

	if (phContext)
	{
		DbgPrint("hContext = %p%p\r\n", phContext->dwLower, phContext->dwUpper);
	}

	Dump(pInput, "Input-", id, 'I');

	SECURITY_STATUS s = InitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1,
		TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

	Dump(pInput, "Input+", id, 'I');

	if (0 <= s)
	{
		if (phNewContext)
		{
			DbgPrint("phNewContext := %p%p\r\n", phNewContext->dwLower, phNewContext->dwUpper);
		}

		Dump(pOutput, "Output", id, 'I');
	}

	DbgPrint("\r\n<< InitializeSecurityContext<I%u> () = %x\r\n", id, s);

	return s;
}

SECURITY_STATUS 
SEC_ENTRY
hook_InitializeSecurityContextA(
								_In_opt_    PCredHandle phCredential,               // Cred to base context
								_In_opt_    PCtxtHandle phContext,                  // Existing context (OPT)
								_In_opt_    SEC_CHAR * pszTargetName,              // Name of target
								_In_        unsigned long fContextReq,              // Context Requirements
								_In_        unsigned long Reserved1,                // Reserved, MBZ
								_In_        unsigned long TargetDataRep,            // Data rep of target
								_In_opt_    PSecBufferDesc pInput,                  // Input Buffers
								_In_        unsigned long Reserved2,                // Reserved, MBZ
								_Inout_opt_ PCtxtHandle phNewContext,               // (out) New Context handle
								_Inout_opt_ PSecBufferDesc pOutput,                 // (inout) Output Buffers
								_Out_       unsigned long * pfContextAttr,  // (out) Context attrs
								_Out_opt_   PTimeStamp ptsExpiry                    // (out) Life span (OPT)
								)
{
	DbgPrint("A> InitializeSecurityContext<I>\r\n");

	PWSTR psz = 0;
	ULONG cch = 0;

	if (!pszTargetName)
	{
		goto __0;
	}

	while (cch = MultiByteToWideChar(CP_UTF8, 0, pszTargetName, MAXULONG, psz, cch))
	{
		if (psz)
		{
__0:
			return hook_InitializeSecurityContextW(phCredential, phContext, psz, fContextReq, Reserved1,
				TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
		}

		psz = (PWSTR)alloca(cch*sizeof(WCHAR));
	}

	return E_FAIL;
}

SECURITY_STATUS 
SEC_ENTRY
hook_DecryptMessage( _In_ PCtxtHandle         phContext,
					_In_      PSecBufferDesc      pMessage,
					_In_      unsigned long       MessageSeqNo,
					_Out_opt_ unsigned long *     pfQOP)
{
	static LONG s_id;

	LONG id = InterlockedIncrementNoFence(&s_id);

	Dump(pMessage, "DecryptMessage---------", id, 'D');

	SECURITY_STATUS s = DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);

	Dump(pMessage, "DecryptMessage+++++++++", id, 'D');

	DbgPrint("\r\n>< DecryptMessage<D%u>( %p%p )= %x\r\n", id, phContext->dwLower, phContext->dwUpper, s);

	return s;
}

SECURITY_STATUS 
SEC_ENTRY
hook_EncryptMessage( _In_ PCtxtHandle      phContext,
					_In_    unsigned long       fQOP,
					_In_    PSecBufferDesc      pMessage,
					_In_    unsigned long       MessageSeqNo)
{
	static LONG s_id;

	LONG id = InterlockedIncrementNoFence(&s_id);

	Dump(pMessage, "EncryptMessage----------", id, 'E');

	SECURITY_STATUS s = EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);

	Dump(pMessage, "EncryptMessage++++++++++", id, 'E');

	DbgPrint("\r\n<< EncryptMessage<E%u>( %p%p ) = %x\r\n", id, phContext->dwLower, phContext->dwUpper, s);

	return s;
}

DECLARE_T_HOOK(AcquireCredentialsHandleW, 36);
DECLARE_T_HOOK(AcquireCredentialsHandleA, 36);
DECLARE_T_HOOK(AcceptSecurityContext, 36);
DECLARE_T_HOOK(InitializeSecurityContextA, 48);
DECLARE_T_HOOK(InitializeSecurityContextW, 48);
DECLARE_T_HOOK(EncryptMessage, 16);
DECLARE_T_HOOK(DecryptMessage, 16);

T_HOOKS_BEGIN(g_sspi)
	T_HOOK(AcquireCredentialsHandleW),
	T_HOOK(AcquireCredentialsHandleA),
	T_HOOK(AcceptSecurityContext),
	T_HOOK(EncryptMessage),
	T_HOOK(DecryptMessage),
	T_HOOK(InitializeSecurityContextA),
	T_HOOK(InitializeSecurityContextW),
T_HOOKS_END()

void HookSspi(ThreadInfo* pti)
{
	TrHook(g_sspi, _countof(g_sspi), pti);
}

void UnhookSspi(ThreadInfo* pti)
{
	TrUnHook(g_sspi, _countof(g_sspi), pti);
}

_NT_END