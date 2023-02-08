#define SECURITY_WIN32
#define WINSCARDAPI __declspec(dllimport)
#define DPAPI_IMP DECLSPEC_IMPORT
#define __DPAPI_H__
#include "../inc/stdafx.h"

#include <Security.h >
#include <Credssp.h>
#include <schannel.h>
#include <WinCred.h>

_NT_BEGIN

namespace SEC {
#include <Ntsecapi.h>
};

_NT_END