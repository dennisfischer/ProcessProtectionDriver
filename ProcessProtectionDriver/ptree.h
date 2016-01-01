#ifndef _PROCESSTREE_H_
#define _PROCESSTREE_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"

extern int MAX_ENTRIES;
extern int MAX_TREE_ENTRIES;
extern int pos;
extern long* list;
extern long* chromeTree;


VOID InitializePTree();
VOID DestroyPTree();
BOOLEAN addChildProcessToTree(long parentPid, long pid);
VOID insertProcessToTree(long pid);
VOID removePidFromTree(long pid);
int findPidInTree(long pid);
#endif