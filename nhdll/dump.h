#pragma once

ULONG __cdecl Fprint( PCSTR Format, ...);

void DumpBytes(const UCHAR* pb, ULONG cb);

void Dump(PSecBufferDesc psbd, PCSTR msg, ULONG id, CHAR c);

void DumpGen(PVOID pAuthData);

void Dump(PCREDSSP_CRED pCred);

void Dump(PSCHANNEL_CRED pScCred);