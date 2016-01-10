#ifndef _OBCALLBACK_ROUTINE_H_
#define _OBCALLBACK_ROUTINE_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID InRegistrationContext, IN  POB_PRE_OPERATION_INFORMATION InPreInfo);
VOID ObjectPostCallback(IN  PVOID InRegistrationContext, IN  POB_POST_OPERATION_INFORMATION InPostInfo);
LPSTR GetProcessNameFromPid(HANDLE pid);
#endif

