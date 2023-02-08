#include "stdafx.h"

_NT_BEGIN

#include "..\updb\module.h"
#include "log.h"
#include "dump.h"
#include "..\detour\detour.h"
#include <Ws2spi.h>

RTL_AVL_TABLE g_handle_table;
SRWLOCK g_table_Lock {};
HANDLE g_Port, g_hHeap;
PVOID g_HeapBase;

enum { HEAPSIZE = 0x10000 };

struct FO_CTX : FILE_COMPLETION_INFORMATION 
{
	SOCKET hFile; // init inside new
	LONG _dwRefCount;
	BOOLEAN bSkipOnOk;
	BOOLEAN bSync;
	BOOLEAN bIocp;
	BOOLEAN bClosed;

	FO_CTX(_In_ BOOLEAN NewElement, _In_ BOOLEAN bSynchronous)
	{
		if (NewElement)
		{
			_dwRefCount = 1;
			bSkipOnOk = FALSE;
			bIocp = FALSE;
			bClosed = FALSE;
			bSync = bSynchronous;
			DbgPrint("%s<%p>(%p %x)\r\n", __FUNCTION__, this, hFile, bSynchronous);
		}
		else
		{
			__debugbreak();
		}
	}

	~FO_CTX()
	{
		DbgPrint("%s<%p>(%p [%p, %p])\r\n", __FUNCTION__, this, hFile, Port, Key);
	}

	void AddRef()
	{
		InterlockedIncrementNoFence(&_dwRefCount);
	}

	void Release()
	{
		if (!InterlockedDecrement(&_dwRefCount))
		{
			delete this;
		}
	}

	void* operator new (_In_ size_t s, _In_ SOCKET hFile, _Out_ PBOOLEAN NewElement)
	{
		AcquireSRWLockExclusive(&g_table_Lock);
		hFile = (SOCKET)RtlInsertElementGenericTableAvl(&g_handle_table, CONTAINING_RECORD(&hFile, FO_CTX, hFile), (ULONG)s, NewElement);
		ReleaseSRWLockExclusive(&g_table_Lock);
		return (void*)hFile;
	}

	void operator delete(void* pv)
	{
		AcquireSRWLockExclusive(&g_table_Lock);
		if (!RtlDeleteElementGenericTableAvl(&g_handle_table, pv)) __debugbreak();
		ReleaseSRWLockExclusive(&g_table_Lock);
	}
};

FO_CTX* GetFileContext(_In_ SOCKET FileHandle)
{
	AcquireSRWLockShared(&g_table_Lock);
	FO_CTX* ctx = (FO_CTX*)RtlLookupElementGenericTableAvl(&g_handle_table, CONTAINING_RECORD(&FileHandle, FO_CTX, hFile));
	if (ctx && ctx->bClosed)
	{
		ctx = 0;
	}
	ReleaseSRWLockShared(&g_table_Lock);

	return ctx;
}

RTL_GENERIC_COMPARE_RESULTS NTAPI AvlCompare (
	_In_ RTL_AVL_TABLE *,
	_In_ PVOID FirstStruct,
	_In_ PVOID SecondStruct
	)
{
	SOCKET hFile1 = reinterpret_cast<FO_CTX*>(FirstStruct)->hFile;
	SOCKET hFile2 = reinterpret_cast<FO_CTX*>(SecondStruct)->hFile;

	if (hFile1 < hFile2) return GenericLessThan;
	if (hFile1 > hFile2) return GenericGreaterThan;
	return GenericEqual;
}

PVOID
NTAPI
AvlAlloc (
		  _In_ RTL_AVL_TABLE *,
		  _In_ CLONG ByteSize
		  )
{
	return LocalAlloc(LMEM_FIXED, ByteSize);
}

VOID
NTAPI
AvlFree (
		 _In_ RTL_AVL_TABLE *,
		 _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer
		 )
{
	LocalFree(Buffer);
}

struct IO_CTX : WSAOVERLAPPED
{
	enum { op_recv = 'rrrr' };
	FO_CTX* fo_ctx;
	WSAOVERLAPPED* lpOverlapped;
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine;
	ULONG op;
	WSABUF Buffers[];

	void* operator new(_In_ size_t s, _In_ DWORD dwBufferCount)
	{
		return HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, s + dwBufferCount * sizeof(WSABUF));
	}

	void operator delete (void* pv)
	{
		HeapFree(g_hHeap, 0, pv);
	}

	IO_CTX(_In_ FO_CTX* fo_ctx, _In_ LPWSAOVERLAPPED lpOverlapped, _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
		_In_ LPWSABUF lpBuffers, _In_ DWORD dwBufferCount, _In_ ULONG op) 
		: lpOverlapped(lpOverlapped), op(op), fo_ctx(fo_ctx), lpCompletionRoutine(lpCompletionRoutine) 
	{
		if (dwBufferCount)
		{
			LPWSABUF bufs = Buffers;
			do 
			{
				*bufs++ = *lpBuffers++;
			} while (--dwBufferCount);
		}

		fo_ctx->AddRef();

		DbgPrint("%s<%p>(%.4s fo=%p ovr=%p)\r\n", __FUNCTION__, this, &op, fo_ctx, lpOverlapped);
	}

	~IO_CTX()
	{
		DbgPrint("%s<%p>(%.4s fo=%p ovr=%p)\r\n", __FUNCTION__, this, &op, fo_ctx, lpOverlapped);

		fo_ctx->Release();
	}
};

void DumpBytes(const UCHAR* pb, ULONG cb);

void OnIoComplete(SOCKET hFile, IO_CTX* io_ctx, ULONG dwError, ULONG_PTR dwBytes)
{
	DbgPrint("OnIoComplete[%.4s](File=%p, err=%u info=%p)\r\n", &io_ctx->op, hFile, dwError, dwBytes);

	if (dwError == NOERROR)
	{
		if (dwBytes)
		{
			WSABUF* Buffers = io_ctx->Buffers;
			ULONG len;
			do 
			{
				len = (ULONG)min(Buffers->len, dwBytes);
				DumpBytes((const UCHAR*)Buffers->buf, len);

			} while (Buffers++, dwBytes -= len);
		}
	}

	delete io_ctx;
}

void DumpSend(_In_ LPWSABUF lpBuffers, _In_ DWORD dwBufferCount)
{
	if (dwBufferCount)
	{
		do 
		{
			DumpBytes((const UCHAR*)lpBuffers->buf, lpBuffers->len);
		} while (lpBuffers++, --dwBufferCount);
	}
}

void CALLBACK WsaComplete(
						  _In_ DWORD dwError,
						  _In_ DWORD cbTransferred,
						  _In_ LPWSAOVERLAPPED lpOverlapped,
						  _In_ DWORD dwFlags
						  )
{
	FO_CTX* ctx = reinterpret_cast<IO_CTX*>(lpOverlapped)->fo_ctx;

	DbgPrint("WsaComplete<File=%p Key=%p Port=%p Ctx=%p status=%08X info=%p>\r\n", 
		ctx->hFile, ctx->Key, ctx->Port, lpOverlapped, dwError, cbTransferred);

	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine = reinterpret_cast<IO_CTX*>(lpOverlapped)->lpCompletionRoutine;
	WSAOVERLAPPED* lpOrigOverlapped = reinterpret_cast<IO_CTX*>(lpOverlapped)->lpOverlapped;
	OnIoComplete(ctx->hFile, reinterpret_cast<IO_CTX*>(lpOverlapped), dwError, cbTransferred);

	lpCompletionRoutine(dwError, cbTransferred, lpOrigOverlapped, dwFlags);
}

ULONG CALLBACK WorkThread(HANDLE hPort)
{
	union {
		PVOID Key;
		FO_CTX* ctx;
	};

	union {
		IO_CTX* io_ctx;
		PVOID ApcContext;
	};

	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	while (STATUS_SUCCESS == (status = ZwRemoveIoCompletion(hPort, &Key, &ApcContext, &iosb, 0)))
	{
		DbgPrint("IO<File=%p Key=%p Port=%p Ctx=%p status=%08X info=%p>\r\n", 
			ctx->hFile, ctx->Key, ctx->Port, ApcContext, iosb.Status, iosb.Information);

		// are our ApcContext ?
		if ((ULONG_PTR)ApcContext - (ULONG_PTR)g_HeapBase < HEAPSIZE)
		{
			PVOID Context = io_ctx->lpOverlapped;
			OnIoComplete(ctx->hFile, io_ctx, RtlNtStatusToDosErrorNoTeb(iosb.Status), iosb.Information);
			ApcContext = Context;
		}

		ZwSetIoCompletion(ctx->Port, ctx->Key, ApcContext, iosb.Status, iosb.Information);
	}

	if (status != STATUS_ABANDONED)
	{
		DbgPrint("ZwRemoveIoCompletion=%x\r\n", status);
	}
	
	FreeLibraryAndExitThread((HMODULE)&__ImageBase, status);
}

NTSTATUS
NTAPI
hook_NtSetInformationFile (
						   _In_ HANDLE FileHandle,
						   _Out_ PIO_STATUS_BLOCK IoStatusBlock,
						   _In_reads_bytes_(Length) PVOID FileInformation,
						   _In_ ULONG Length,
						   _In_ FILE_INFORMATION_CLASS FileInformationClass
						   )
{
	switch (FileInformationClass)
	{
	case FileCompletionInformation:
	case FileReplaceCompletionInformation:
		if (Length == sizeof(FILE_COMPLETION_INFORMATION))
		{
			if (FO_CTX* ctx = GetFileContext((SOCKET)FileHandle))
			{
				if (ctx->bSync)
				{
					DbgPrint("SetInformationFile:CompletionInformation<%p> on Sync !!\r\n", ctx);
					return STATUS_INVALID_PARAMETER;
				}

				ctx->Key = reinterpret_cast<PFILE_COMPLETION_INFORMATION>(FileInformation)->Key;
				ctx->Port = reinterpret_cast<PFILE_COMPLETION_INFORMATION>(FileInformation)->Port;
				ctx->bIocp = TRUE;

				DbgPrint("SetInformationFile:CompletionInformation<%p>: %p\r\n", ctx, ctx->Key);

				FILE_COMPLETION_INFORMATION fci = { g_Port, ctx };

				FileInformation = &fci;

				break;
			}
		}
		break;

	case FileIoCompletionNotificationInformation:
		if (Length == sizeof(FILE_IO_COMPLETION_NOTIFICATION_INFORMATION))
		{
			if (FO_CTX* ctx = GetFileContext((SOCKET)FileHandle))
			{
				ULONG Flags = reinterpret_cast<PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION>(FileInformation)->Flags;

				DbgPrint("SetInformationFile:IoCompletionNotificationInformation<%p>: %08x\r\n", ctx, Flags);

				ctx->bSkipOnOk = (Flags & FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) != 0;

				break;
			}

			return STATUS_NO_MEMORY;
		}
		break;
	}

	return NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

EXTERN_C_START

DECLSPEC_IMPORT
BOOL WSPAPI MSAFD_ConnectEx(
							__in      SOCKET s,
							__in      const struct sockaddr* name,
							__in      int namelen,
							__in_opt  PVOID lpSendBuffer,
							__in      DWORD dwSendDataLength,
							__out     LPDWORD lpdwBytesSent,
							__in      LPOVERLAPPED lpOverlapped
					  );

DECLSPEC_IMPORT
int WSPAPI WSPConnect(
					  __in   SOCKET s,
					  __in   const struct sockaddr* name,
					  __in   int namelen,
					  __in   LPWSABUF lpCallerData,
					  __out  LPWSABUF lpCalleeData,
					  __in   LPQOS lpSQOS,
					  __in   LPQOS lpGQOS,
					  __out  LPINT lpErrno
					  );

DECLSPEC_IMPORT
SOCKET WSPAPI WSPSocket(
						_In_ int af,
						_In_ int type,
						_In_ int protocol,
						_In_opt_ LPWSAPROTOCOL_INFOW lpProtocolInfo,
						_In_ GROUP g,
						_In_ DWORD dwFlags,
						_Out_ LPINT lpErrno
						);

DECLSPEC_IMPORT
int WSPAPI WSPSendTo(
					 _In_ SOCKET s,
					 _In_reads_(dwBufferCount) LPWSABUF lpBuffers,
					 _In_ DWORD dwBufferCount,
					 _Out_opt_ LPDWORD lpNumberOfBytesSent,
					 _In_ DWORD dwFlags,
					 _In_reads_bytes_opt_(iTolen) const struct sockaddr FAR * lpTo,
					 _In_ int iTolen,
					 _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
					 _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
					 _In_opt_ LPWSATHREADID lpThreadId,
					 _Out_ LPINT lpErrno
					 );

DECLSPEC_IMPORT
int WSPAPI WSPSend(
				   __in   SOCKET s,
				   __in   LPWSABUF lpBuffers,
				   __in   DWORD dwBufferCount,
				   __out  LPDWORD lpNumberOfBytesSent,
				   __in   DWORD dwFlags,
				   __in   LPWSAOVERLAPPED lpOverlapped,
				   __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
				   __in   LPWSATHREADID lpThreadId,
				   __out  LPINT lpErrno
				   );

DECLSPEC_IMPORT
int WSPAPI WSPRecv(
				   __in     SOCKET s,
				   __inout  LPWSABUF lpBuffers,
				   __in     DWORD dwBufferCount,
				   __out    LPDWORD lpNumberOfBytesRecvd,
				   __inout  LPDWORD lpFlags,
				   __in     LPWSAOVERLAPPED lpOverlapped,
				   __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
				   __in     LPWSATHREADID lpThreadId,
				   __out    LPINT lpErrno
				   );

DECLSPEC_IMPORT
int WSPAPI WSPRecvFrom(
					   __in     SOCKET s,
					   __inout  LPWSABUF lpBuffers,
					   __in     DWORD dwBufferCount,
					   __out    LPDWORD lpNumberOfBytesRecvd,
					   __inout  LPDWORD lpFlags,
					   __out    struct sockaddr* lpFrom,
					   __inout  LPINT lpFromlen,
					   __in     LPWSAOVERLAPPED lpOverlapped,
					   __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
					   __in     LPWSATHREADID lpThreadId,
					   __inout  LPINT lpErrno
					   );

DECLSPEC_IMPORT
int WSPAPI WSPCloseSocket(
						  __in   SOCKET s,
						  __out  LPINT lpErrno
						  );


//////////////////////////////////////////////////////////////////////////

BOOL WSPAPI hook_MSAFD_ConnectEx(
								 __in      SOCKET s,
								 __in      sockaddr* name,
								 __in      int namelen,
								 __in_opt  PVOID lpSendBuffer,
								 __in      DWORD dwSendDataLength,
								 __out     LPDWORD lpdwBytesSent,
								 __in      LPOVERLAPPED lpOverlapped
								 )
{
	WCHAR sz[64];
	ULONG cch = _countof(sz);
	WSAAddressToStringW(name, namelen, 0, sz, &cch);
	DbgPrint("%s(%p %S)\r\n", __FUNCTION__, s, sz);
	return MSAFD_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

int WSPAPI hook_WSPConnect(
						   __in   SOCKET s,
						   __in   sockaddr* name,
						   __in   int namelen,
						   __in   LPWSABUF lpCallerData,
						   __out  LPWSABUF lpCalleeData,
						   __in   LPQOS lpSQOS,
						   __in   LPQOS lpGQOS,
						   __out  LPINT lpErrno
						   )
{
	WCHAR sz[64];
	ULONG cch = _countof(sz);
	WSAAddressToStringW(name, namelen, 0, sz, &cch);
	DbgPrint("%s(%p %S)\r\n", __FUNCTION__, s, sz);
	return WSPConnect( s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}

SOCKET WSPAPI hook_WSPSocket(
							 _In_ int af,
							 _In_ int type,
							 _In_ int protocol,
							 _In_opt_ LPWSAPROTOCOL_INFOW lpProtocolInfo,
							 _In_ GROUP g,
							 _In_ DWORD dwFlags,
							 _Out_ LPINT lpErrno
							 )
{
	SOCKET s = WSPSocket(af, type, protocol, lpProtocolInfo, g, dwFlags, lpErrno);

	DbgPrint("%s(%u-%u-%u %x)\r\n", __FUNCTION__, af, type, protocol, dwFlags);

	DumpStack(0, __FUNCTION__, Fprint);

	if (s != INVALID_SOCKET)
	{
		BOOLEAN NewElement;
		new (s, &NewElement) FO_CTX(NewElement, (dwFlags & WSA_FLAG_OVERLAPPED) == 0);
	}

	return s;
}

int WSPAPI hook_WSPSendTo(
						  _In_ SOCKET s,
						  _In_reads_(dwBufferCount) LPWSABUF lpBuffers,
						  _In_ DWORD dwBufferCount,
						  _Out_opt_ LPDWORD lpNumberOfBytesSent,
						  _In_ DWORD dwFlags,
						  _In_reads_bytes_opt_(iTolen) const struct sockaddr FAR * lpTo,
						  _In_ int iTolen,
						  _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
						  _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
						  _In_opt_ LPWSATHREADID lpThreadId,
						  _Out_ LPINT lpErrno
						  )
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, s, lpOverlapped, lpCompletionRoutine);
	DumpSend(lpBuffers, dwBufferCount);
	return WSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

int WSPAPI hook_WSPSend(
						__in   SOCKET s,
						__in   LPWSABUF lpBuffers,
						__in   DWORD dwBufferCount,
						__out  LPDWORD lpNumberOfBytesSent,
						__in   DWORD dwFlags,
						__in   LPWSAOVERLAPPED lpOverlapped,
						__in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
						__in   LPWSATHREADID lpThreadId,
						__out  LPINT lpErrno
						)
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, s, lpOverlapped, lpCompletionRoutine);
	DumpStack(0, __FUNCTION__, Fprint);

	DumpSend(lpBuffers, dwBufferCount);

	return WSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

int WSPAPI hook_WSPRecvFrom(
							__in     SOCKET s,
							__inout  LPWSABUF lpBuffers,
							__in     DWORD dwBufferCount,
							__out    LPDWORD lpNumberOfBytesRecvd,
							__inout  LPDWORD lpFlags,
							__out    sockaddr* lpFrom,
							__inout  LPINT lpFromlen,
							__in     LPWSAOVERLAPPED lpOverlapped,
							__in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
							__in     LPWSATHREADID lpThreadId,
							__inout  LPINT lpErrno
							)
{
	DbgPrint("%s(File=%p, Ctx=%p, fn=%p)\r\n", __FUNCTION__, s, lpOverlapped, lpCompletionRoutine);

	if (!lpNumberOfBytesRecvd && !lpOverlapped)
	{
		DbgPrint("!!!!!!!!!!!!! WSPRecv:!lpNumberOfBytesRecvd && !lpOverlapped\r\n");
		*lpErrno = ERROR_INVALID_PARAMETER;
		return SOCKET_ERROR;
	}

	IO_CTX* io_ctx = 0;
	FO_CTX* fo_ctx = 0;

	if (fo_ctx = GetFileContext(s))
	{
		if (!fo_ctx->bSync && lpOverlapped)
		{
			if (!((lpCompletionRoutine != 0) ^ fo_ctx->bIocp))
			{
				DbgPrint("!!!!!!!!!!!!! WSPRecv:!(lpCompletionRoutine != 0 ^ fo_ctx->bIocp)\r\n");
				*lpErrno = ERROR_INVALID_PARAMETER;
				return SOCKET_ERROR;
			}

			if (io_ctx = new(dwBufferCount) IO_CTX(fo_ctx, lpOverlapped, lpCompletionRoutine, lpBuffers, dwBufferCount, IO_CTX::op_recv))
			{
				lpOverlapped = io_ctx;
				if (lpCompletionRoutine)
				{
					lpCompletionRoutine = WsaComplete;
				}
			}
			else
			{
				*lpErrno = ERROR_OUTOFMEMORY;
				return SOCKET_ERROR;
			}
		}
	}
	else
	{
		DbgPrint("!!!!!!!!!!!!! WSPRecvFrom:GetFileContext\r\n");
	}

	if (lpOverlapped) lpOverlapped->InternalHigh = 0;

	int r = (sockaddr*)~0 == lpFrom ? 
		WSPRecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno) :
		WSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);;

	ULONG dwError = r ? *lpErrno : NOERROR;

	ULONG NumberOfBytesRecvd = dwError ? 0 : lpOverlapped ? (ULONG)lpOverlapped->InternalHigh : *lpNumberOfBytesRecvd;

	DbgPrint("%s<%p>=%u, [%x]\r\n", __FUNCTION__, s, dwError, NumberOfBytesRecvd);

	if (fo_ctx)
	{
		if (fo_ctx->bSync || !lpOverlapped)
		{
			if (NumberOfBytesRecvd)
			{
				ULONG len;
				do 
				{
					len = min(lpBuffers->len, NumberOfBytesRecvd);
					DumpBytes((const UCHAR*)lpBuffers->buf, len);
				} while (lpBuffers++, NumberOfBytesRecvd -= len);
			}
		}
		else
		{
			switch (dwError)
			{
			case NOERROR:
				if (!fo_ctx->bSkipOnOk)
				{
			case WSA_IO_PENDING:
				break;
				}
				[[fallthrough]];
			default:
				lpCompletionRoutine ? 
					WsaComplete(dwError, 0, lpOverlapped, *lpFlags) : OnIoComplete(s, io_ctx, dwError, lpOverlapped->InternalHigh);			
			}
		}
	}

	return r;
}

int WSPAPI hook_WSPRecv(
						__in     SOCKET s,
						__inout  LPWSABUF lpBuffers,
						__in     DWORD dwBufferCount,
						__out    LPDWORD lpNumberOfBytesRecvd,
						__inout  LPDWORD lpFlags,
						__in     LPWSAOVERLAPPED lpOverlapped,
						__in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
						__in     LPWSATHREADID lpThreadId,
						__out    LPINT lpErrno
						)
{
	return hook_WSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, 
		(sockaddr*)~0, 0, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

int WSPAPI hook_WSPCloseSocket(
							   __in   SOCKET s,
							   __out  LPINT lpErrno
							   )
{
	if (FO_CTX* ctx = GetFileContext(s))
	{
		DbgPrint("%s(File=%p)\r\n", __FUNCTION__, s);
		ctx->bClosed = TRUE;
		ctx->Release();
	}
	return WSPCloseSocket(s, lpErrno);
}

extern PVOID __imp_NtSetInformationFile;

PVOID __imp_WSPSocket, __imp_WSPConnect, __imp_MSAFD_ConnectEx,
__imp_WSPSendTo, __imp_WSPSend, __imp_WSPRecv, __imp_WSPRecvFrom, __imp_WSPCloseSocket;

EXTERN_C_END

T_HOOKS_BEGIN(g_msw)
T_HOOK(NtSetInformationFile),
T_HOOK(WSPSocket),
T_HOOK(WSPCloseSocket),
T_HOOK(MSAFD_ConnectEx),
T_HOOK(WSPConnect),
T_HOOK(WSPRecv),
T_HOOK(WSPRecvFrom),
T_HOOK(WSPSend),
T_HOOK(WSPSendTo),
T_HOOKS_END()

void UnhookMsw(ThreadInfo* pti)
{
	TrUnHook(g_msw, _countof(g_msw), pti);
}

ULONG WINAPI UnloadThread(PVOID)
{
	DbgPrint("UnloadThread=%x\r\n", GetCurrentThreadId());

	LARGE_INTEGER li = { 0, MINLONG };
	do 
	{
		ZwDelayExecution(TRUE, &li);
	} while (RtlNumberGenericTableElementsAvl(&g_handle_table));

	ThreadInfo* pti;
	SuspendAll(&pti);
	UnhookMsw(pti);
	ResumeAndFree(pti);

	if (g_Port) NtClose(g_Port);
	if (g_HeapBase)
	{
		if (g_hHeap) RtlDestroyHeap(g_hHeap);
		VirtualFree(g_HeapBase, 0, MEM_RELEASE);
	}

	FreeLibraryAndExitThread((HMODULE)&__ImageBase, 0);
}

BOOL StartWorker()
{
	if (0 <= RtlCreateUserThread(NtCurrentProcess(), 0, 0, 0, PAGE_SIZE, PAGE_SIZE, UnloadThread, 0, 0, 0))
	{
		if (g_HeapBase = VirtualAlloc(0, HEAPSIZE, MEM_COMMIT, PAGE_READWRITE))
		{
			if (g_hHeap = RtlCreateHeap(0, g_HeapBase, HEAPSIZE, HEAPSIZE, 0, 0))
			{
				SYSTEM_INFO si;
				GetSystemInfo(&si);
				if (si.dwNumberOfProcessors)
				{
					if (0 <= ZwCreateIoCompletion(&g_Port, IO_COMPLETION_ALL_ACCESS, 0, si.dwNumberOfProcessors))
					{
						RtlInitializeGenericTableAvl(&g_handle_table, AvlCompare, AvlAlloc, AvlFree, 0);

						BOOL b = FALSE;
						do 
						{
							if (0 <= LdrAddRefDll(0, (HMODULE)&__ImageBase))
							{
								if (0 > RtlCreateUserThread(NtCurrentProcess(), 0, 0, 0, PAGE_SIZE, PAGE_SIZE, WorkThread, g_Port, 0, 0))
								{
									LdrUnloadDll((HMODULE)&__ImageBase);
								}
								else
								{
									b = TRUE;
								}
							}
						} while (--si.dwNumberOfProcessors);

						return b;
					}
				}
			}
		}
	}

	return FALSE;
}

void HookMsw(ThreadInfo* pti)
{
	CModule* p;

	if (0 <= CModule::Create(LoadLibraryW(L"mswsock"), &p) &&
		(__imp_WSPSocket = p->GetVaFromName("WSPSocket"))&&
		(__imp_WSPCloseSocket = p->GetVaFromName("WSPCloseSocket")) &&
		(__imp_MSAFD_ConnectEx = p->GetVaFromName("MSAFD_ConnectEx"))&&
		(__imp_WSPConnect = p->GetVaFromName("WSPConnect"))&&
		(__imp_WSPSend = p->GetVaFromName("WSPSend"))&&
		(__imp_WSPSendTo = p->GetVaFromName("WSPSendTo"))&&
		(__imp_WSPRecv = p->GetVaFromName("WSPRecv"))&&
		(__imp_WSPRecvFrom = p->GetVaFromName("WSPRecvFrom")) &&
		StartWorker()
		)
	{
		TrHook(g_msw, _countof(g_msw), pti);
	}
}

_NT_END