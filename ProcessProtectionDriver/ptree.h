#ifndef _PROCESSTREE_H_
#define _PROCESSTREE_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"

struct _PROCESS_LIST_ENTRY {
	LIST_ENTRY ListEntry;
	ULONG Pid;
	PLIST_ENTRY ChildHead;
};

struct _PROCESS_LIST_ENTRY_CHILD
{
	LIST_ENTRY ListEntry;
	ULONG Pid;
	ULONG ParentPid;
};

typedef struct _PROCESS_LIST_ENTRY PROCESS_LIST_ENTRY;
typedef PROCESS_LIST_ENTRY* PPROCESS_LIST_ENTRY;
typedef struct _PROCESS_LIST_ENTRY_CHILD PROCESS_LIST_ENTRY_CHILD;
typedef PROCESS_LIST_ENTRY_CHILD* PPROCESS_LIST_ENTRY_CHILD;


VOID InitializePTree();
VOID DestroyPTree();

VOID AddChildPidToTree(ULONG parentPid, ULONG pid);
VOID InsertPidToTree(ULONG pid);
VOID RemovePidFromTree(ULONG pid);
ULONG FindPidInTree(ULONG pid);
#endif