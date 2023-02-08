#pragma once

#if 0 // 1
#define DbgPrint /##/
#else
#define _LOG_
#define DbgPrint CLogFile::s_logfile.printf
#pragma message("=========log")
#endif

#ifdef _LOG_

#define LOG(args)  CLogFile::s_logfile.args

class CLogFile
{
private:
	HANDLE hFile;

public:
	/*inline */static CLogFile s_logfile;

	~CLogFile() 
	{
		if (hFile) NtClose(hFile);
	}
	
	CLogFile() : hFile(0) {}
	
	NTSTATUS Init();
	
	NTSTATUS __cdecl printf(PCSTR format, ...);

	NTSTATUS write(LPCVOID data, DWORD cb)
	{
		IO_STATUS_BLOCK iosb;
		return hFile ? NtWriteFile(hFile, 0, 0, 0, &iosb, const_cast<void*>(data), cb, 0, 0) :
			STATUS_INVALID_HANDLE;
	}
};

void LogTimeStamp();

#else

#define LOG(args)  

#endif//_LOG_