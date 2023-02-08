#pragma once

template <typename Value, typename Key>
class map : RTL_AVL_TABLE
{
	static RTL_GENERIC_COMPARE_RESULTS NTAPI compare (
		_In_ RTL_AVL_TABLE * /*Table*/,
		_In_ PVOID FirstStruct,
		_In_ PVOID SecondStruct
		)
	{
		return Key::compare(reinterpret_cast<Key*>(FirstStruct), reinterpret_cast<Key*>(SecondStruct));
	}

	PVOID NTAPI alloc (
		_In_ RTL_AVL_TABLE *Table,
		_In_ CLONG ByteSize
		)
	{
		return LocalAlloc(LMEM_FIXED|LMEM_ZEROINIT, ByteSize);
	}

	VOID NTAPI free (
		_In_ struct _RTL_AVL_TABLE * /*Table*/,
		_In_ PVOID Buffer
		)
	{
		LocalFree(Buffer);
	}

	SRWLOCK lock {};

public:
	_NODISCARD Value* operator << (Key key)
	{
		AcquireSRWLockExclusive(&lock);
		BOOLEAN bNew;
		PVOID pv = RtlInsertElementGenericTableAvl(this, static_cast<Value*>(&key), sizeof(Value), &bNew);
		if (pv)
		{
			if (bNew)
			{
				(new(pv) Value)->AddRef();
			}
			else
			{
				__debugbreak();
			}

		}
		ReleaseSRWLockExclusive(&lock);

		return reinterpret_cast<Value*>(pv);
	}

	bool operator >> (Key key)
	{
		AcquireSRWLockExclusive(&lock);
		PVOID pv = RtlLookupElementGenericTable(this, static_cast<Value*>(&key));
		if (pv)
		{
			RtlDeleteElementGenericTableAvl(pv);
			reinterpret_cast<Value*>(pv)->Release();
		}
		ReleaseSRWLockExclusive(&lock);
		return pv != 0;
	}

	_NODISCARD Value* operator[](Key key)
	{
		AcquireSRWLockShared(&lock);
		PVOID pv = RtlLookupElementGenericTable(this, static_cast<Value*>(&key));
		if (pv)
		{
			reinterpret_cast<Value*>(pv)->AddRef();
		}
		ReleaseSRWLockShared(&lock);
		return reinterpret_cast<Value*>(pv);
	}

	map()
	{
		RtlInitializeGenericTableAvl(this, compare, alloc, free, this);
	}
};
#include "map.h"

struct SCKT {
	SOCKET socket;

	static RTL_GENERIC_COMPARE_RESULTS NTAPI compare (
		_In_ RTL_AVL_TABLE * /*Table*/,
		_In_ SCKT* FirstStruct,
		_In_ SCKT* SecondStruct
		)
	{
		if (FirstStruct->socket < SecondStruct->socket) return GenericLessThan;
		if (FirstStruct->socket > SecondStruct->socket) return GenericGreaterThan;
		return GenericEqual;
	}
};

class MySock : public SCKT
{
	PVOID _Key;
	LONG _dwRef = 1;
	BOOLEAN _bAsync;

	~MySock()
	{
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
	}
public:

	MySock()
	{
		DbgPrint("%s<%p>\r\n", __FUNCTION__, this);
	}

	void* operator new(size_t s, void* pv)
	{
		if (s != sizeof(MySock))
		{
			__debugbreak();
			return 0;
		}

		return pv;
	}

	void operator delete(void* pv)
	{
	}

	void AddRef()
	{
		InterlockedIncrement(&_dwRef);
	}

	void Release()
	{
		if (!InterlockedDecrement(&_dwRef))
		{
			delete this;ZwSetIoCompletion()
		}
	}
};
