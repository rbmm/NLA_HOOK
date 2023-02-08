#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "dump.h"

using namespace SEC;

ULONG __cdecl Fprint( PCSTR Format, ...)
{
	va_list args;
	va_start(args, Format);

	PSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnprintf(buf, len, Format, args)))
	{
		if (buf)
		{
			LOG(write(buf, len));
			break;
		}

		if (!(buf = (PSTR)_malloca(len)))
		{
			break;
		}
	}

	if (buf)
	{
		_freea(buf);
	}

	va_end(args);
	return 0;
}

void SaveCert(BYTE *pbCertEncoded, DWORD cbCertEncoded)
{
	IO_STATUS_BLOCK iosb;

	WCHAR buf[0x100];

	static LONG s;

	if (0 < swprintf_s(buf, _countof(buf), L"\\systemroot\\temp\\cc[%x-%x].cer", GetCurrentProcessId(), InterlockedIncrement(&s)))
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		RtlInitUnicodeString(&ObjectName, buf);

		HANDLE hFile;
		if (0 <= NtCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, 
			&oa, &iosb, 0, 0, FILE_SHARE_READ, FILE_OVERWRITE_IF, 
			FILE_SYNCHRONOUS_IO_NONALERT, 0, 0))
		{
			NtWriteFile(hFile, 0, 0, 0, &iosb, pbCertEncoded, cbCertEncoded, 0, 0);
			NtClose(hFile);
		}
	}
}

void PrintStr(PSTR psz, ULONG cch)
{
	ULONG len;
	do 
	{
		DbgPrint("%.*s", len = min(0x100, cch), psz);
	} while (psz += len, cch -= len);
}

void DumpBytes(const UCHAR* pb, ULONG cb)
{
	PSTR psz = 0;
	ULONG cch = 0;
	while (CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXASCIIADDR, psz, &cch))
	{
		if (psz)
		{
			LOG(write(psz, cch));
			//PrintStr( psz, cch);
			break;
		}

		if (!(psz = (PSTR)_malloca(cch)))
		{
			break;
		}
	}

	if (psz)
	{
		_freea(psz);
	}
}

#define CASE(t) case SECBUFFER_##t: return #t

PCSTR GetBufTypeName(ULONG BufferType, PSTR buf)
{
	switch (BufferType & ~0xF0000000)
	{
		CASE(EMPTY);
		CASE(DATA);
		CASE(TOKEN);
		CASE(PKG_PARAMS);
		CASE(MISSING);
		CASE(EXTRA);
		CASE(STREAM_TRAILER);
		CASE(STREAM_HEADER);
		CASE(NEGOTIATION_INFO);
		CASE(PADDING);
		CASE(STREAM);
		CASE(MECHLIST);
		CASE(MECHLIST_SIGNATURE);
		CASE(TARGET);
		CASE(CHANNEL_BINDINGS);
		CASE(CHANGE_PASS_RESPONSE);
		CASE(TARGET_HOST);
		CASE(ALERT);
		CASE(APPLICATION_PROTOCOLS);
		CASE(SRTP_PROTECTION_PROFILES);
		CASE(SRTP_MASTER_KEY_IDENTIFIER);
		CASE(TOKEN_BINDING);
		CASE(PRESHARED_KEY);
		CASE(PRESHARED_KEY_IDENTITY);
		CASE(DTLS_MTU);
		CASE(SEND_GENERIC_TLS_EXTENSION);
		CASE(SUBSCRIBE_GENERIC_TLS_EXTENSION);
		CASE(FLAGS);
		CASE(TRAFFIC_SECRETS);
	}

	sprintf_s(buf, 16, "%x", BufferType);
	return buf;
}

void Dump(PSecBufferDesc psbd, PCSTR msg, ULONG id, CHAR c)
{
	if (psbd)
	{
		if (ULONG cBuffers = psbd->cBuffers)
		{
			PSecBuffer pBuffers = psbd->pBuffers;
			DbgPrint("PSecBufferDesc<%c%u>(v=%x, n=%x) : %s\r\n", c, id, psbd->ulVersion, cBuffers, msg);

			do 
			{
				char buf[16];
				DbgPrint("\tBufferType = %s, cb = %x, pv = %p\r\n", 
					GetBufTypeName(pBuffers->BufferType, buf), pBuffers->cbBuffer, pBuffers->pvBuffer);

				if (pBuffers->BufferType != SECBUFFER_EMPTY)
				{
					union {
						PVOID pv;
						PUCHAR pb;
					};

					if (pv = pBuffers->pvBuffer)
					{
						//DumpTLS(pb, pBuffers->cbBuffer);
					}
				}

			} while (pBuffers++, --cBuffers);
		}
	}
}

typedef struct KERB_SMARTCARD_CSP_INFO
{   
	ULONG dwCspInfoLen;						// size of this structure w/ payload
	ULONG MessageType; // info type, currently CertHashInfo
	// payload starts, marshaled structure of MessageType
	union {     
		PVOID ContextInformation; // Reserved
		ULONG64 SpaceHolderForWow64; 
	}; 
	ULONG flags; // Reserved
	ULONG KeySpec; // AT_SIGNATURE xor AT_KEYEXCHANGE
	ULONG nCardNameOffset; 
	ULONG nReaderNameOffset; 
	ULONG nContainerNameOffset; 
	ULONG nCSPNameOffset; 
	WCHAR Buffer[];
} *PKERB_SMARTCARD_CSP_INFO;

void Dump(PSCHANNEL_CRED pScCred)
{
	DbgPrint("SCHANNEL_CRED { v=%x, f=%x, n=%x }\r\n", pScCred->dwVersion, pScCred->dwFlags, pScCred->cCreds);

	if (DWORD cCreds = pScCred->cCreds)
	{
		PCCERT_CONTEXT *paCred = pScCred->paCred, pCrtCtx;
		do 
		{
			pCrtCtx = *paCred++;
			SaveCert(pCrtCtx->pbCertEncoded, pCrtCtx->cbCertEncoded);

		} while (--cCreds);
	}
}

void PrintUn(PCUNICODE_STRING pStr, PVOID Base, PCSTR Name)
{
	UNICODE_STRING str = *pStr;

	if (str.Length)
	{
		if ((ULONG_PTR)str.Buffer < MAXUSHORT)
		{
			(PUCHAR&)str.Buffer += (ULONG_PTR)Base;
		}
		DbgPrint("%s: %wZ\r\n", Name, &str);
	}
}

void Dump(PKERB_INTERACTIVE_LOGON pCertLogon)
{
	PrintUn(&pCertLogon->LogonDomainName, pCertLogon, "DomainName");
	PrintUn(&pCertLogon->UserName, pCertLogon, "UserName");
	PrintUn(&pCertLogon->Password, pCertLogon, "Pin");

	PWSTR pszCredentials = pCertLogon->Password.Buffer;

	if ((ULONG_PTR)pszCredentials <= MAXUSHORT)
	{
		(PBYTE&)pszCredentials += (ULONG_PTR)pCertLogon;
	}

	CRED_PROTECTION_TYPE ProtectionType;

	ULONG dwError = BOOL_TO_ERROR(CredIsProtectedW(pszCredentials, &ProtectionType));

	DbgPrint("CredIsProtectedW=%u\r\n", dwError);

	if (dwError == NOERROR)
	{
		ULONG cchPin = 0;
		PWSTR pszPin = 0;

		DbgPrint("ProtectionType=%x\r\n", ProtectionType);

		if (ProtectionType != CredUnprotected)
		{
			ULONG cchCredentials = pCertLogon->Password.Length / sizeof(WCHAR);

			while (ERROR_INSUFFICIENT_BUFFER == (dwError = BOOL_TO_ERROR(CredUnprotect(FALSE, pszCredentials, cchCredentials, pszPin, &cchPin))))
			{
				if (pszPin)
				{
					break;
				}

				pszPin = (PWSTR)alloca(cchPin * sizeof(WCHAR));
			}

			DbgPrint("CredUnprotect= %u, [%x]\r\n", dwError, cchPin);
			if (!dwError)
			{
				DbgPrint("Pin decoded=<%S>\r\n", pszPin);
			}
		}
		else
		{
			DbgPrint("Pin was not encrypted\r\n");
			pszPin = pszCredentials;
		}
	}
}

void Dump(PKERB_CERTIFICATE_LOGON pCertLogon)
{
	Dump((PKERB_INTERACTIVE_LOGON) pCertLogon);

	ULONG CspDataLength = pCertLogon->CspDataLength;

	union {
		PUCHAR CspData;
		PKERB_SMARTCARD_CSP_INFO psci;
	};

	if ((ULONG_PTR)(CspData = pCertLogon->CspData) < MAXUSHORT)
	{
		CspData += (ULONG_PTR)pCertLogon;
	}

	ULONG dwCspInfoLen = psci->dwCspInfoLen;

	if (dwCspInfoLen > CspDataLength || dwCspInfoLen < sizeof(KERB_SMARTCARD_CSP_INFO) + sizeof(WCHAR))
	{
		__debugbreak();
	}

	PWSTR Buffer = psci->Buffer;
	dwCspInfoLen -= sizeof(KERB_SMARTCARD_CSP_INFO) + sizeof(WCHAR);

	*(PWSTR)RtlOffsetToPointer(Buffer, dwCspInfoLen) = 0;

	dwCspInfoLen >>= 1; // dwCspInfoLen /= sizeof(WCHAR);

	ULONG nCardNameOffset = 0, nReaderNameOffset = 0, nContainerNameOffset = 0, nCSPNameOffset = 0;

	if ((nCSPNameOffset = psci->nCSPNameOffset) > dwCspInfoLen ||
		(nCardNameOffset = psci->nCardNameOffset) > dwCspInfoLen ||
		(nReaderNameOffset = psci->nReaderNameOffset) > dwCspInfoLen ||
		(nContainerNameOffset = psci->nContainerNameOffset) > dwCspInfoLen)
	{
		__debugbreak();
	}

	PCWSTR ReaderName = Buffer + nReaderNameOffset;
	PCWSTR ContainerName = Buffer + nContainerNameOffset;

	DbgPrint("MessageType=%x KeySpec=%x\r\nReader=%S\r\nContainer=%S\r\nCard=%S\r\nCSPName=%S\r\n", 
		psci->MessageType, psci->KeySpec, 
		ReaderName, ContainerName, Buffer + nCardNameOffset, Buffer + nCSPNameOffset);
}

void DumpGen(PVOID pAuthData)
{
	if (pAuthData)
	{
		KERB_LOGON_SUBMIT_TYPE MessageType = *(KERB_LOGON_SUBMIT_TYPE*)pAuthData;
		DbgPrint("KERB_LOGON<%p>{%x}\r\n", pAuthData, MessageType);

		switch (MessageType)
		{
		case KerbInteractiveLogon:
			Dump((PKERB_INTERACTIVE_LOGON)pAuthData);
			break;
		case KerbCertificateLogon:
			Dump((PKERB_CERTIFICATE_LOGON)pAuthData);
			break;
		}
	}
}

void Dump(PCREDSSP_CRED pCred)
{
	DbgPrint("CREDSSP_CRED { %u, Schannel=%p, Spnego = %p }\r\n", pCred->Type, pCred->pSchannelCred, pCred->pSpnegoCred);

__0:
	switch (pCred->Type)
	{
	case CredsspSchannelCreds:
		Dump((PSCHANNEL_CRED)pCred->pSchannelCred);
		break;
	case CredsspCertificateCreds:
		Dump((PKERB_CERTIFICATE_LOGON)pCred->pSpnegoCred);
		break;
	case CredsspSubmitBufferBoth:
	case CredsspSubmitBufferBothOld:
		Dump((PSCHANNEL_CRED)pCred->pSchannelCred);
		DumpGen(pCred->pSpnegoCred);
		break;
	case CredsspCredEx:
		pCred = &reinterpret_cast<PCREDSSP_CRED_EX>(pCred)->Cred;
		goto __0;
	}
}

_NT_END
