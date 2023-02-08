#include "stdafx.h"

_NT_BEGIN

#include "log.h"

#ifdef _LOG_

CLogFile CLogFile::s_logfile;

NTSTATUS CLogFile::Init()
{
	IO_STATUS_BLOCK iosb;

	WCHAR buf[0x100];

	NTSTATUS status = STATUS_INTERNAL_ERROR;

	if (0 < swprintf_s(buf, _countof(buf), L"\\systemroot\\temp\\nhdd[%x].log", GetCurrentProcessId()))
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		RtlInitUnicodeString(&ObjectName, buf);

		status = NtCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, 
			&oa, &iosb, 0, 0, FILE_SHARE_READ, FILE_OVERWRITE_IF, 
			FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
	}

	return status;
}

NTSTATUS CLogFile::printf(PCSTR format, ...)
{
	if (!hFile) return STATUS_INVALID_HANDLE;

	va_list args;
	va_start(args, format);

	PSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnprintf(buf, len, format, args)))
	{
		if (buf)
		{
			IO_STATUS_BLOCK iosb;
			NtWriteFile(hFile, 0, 0, 0, &iosb, buf, len, 0, 0);
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

void LogTimeStamp()
{
	LARGE_INTEGER li;
	GetSystemTimeAsFileTime((LPFILETIME)&li);
	TIME_FIELDS tf;
	RtlTimeToTimeFields(&li, &tf);
	CLogFile::s_logfile.printf("\r\n--=[ %u-%02u-%02u %02u:%02u:%02u.%u ]=--\r\n", 
		tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);
}

#endif//_LOG_

_NT_END