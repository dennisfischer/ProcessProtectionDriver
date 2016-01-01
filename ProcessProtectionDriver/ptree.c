#include "stdafx.h"

int MAX_ENTRIES = 10;
int MAX_TREE_ENTRIES = 50;
int pos = 0;
long* list;
long* chromeTree;

void InitializePTree()
{
	list = AllocMemory(1, sizeof(long) * MAX_ENTRIES);
	chromeTree = AllocMemory(1, sizeof(long) * MAX_ENTRIES * MAX_TREE_ENTRIES);
}

void DestoyPTree()
{
	FreeMemory(list);
	FreeMemory(chromeTree);
}

void insertProcessToTree(long InPid)
{
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == 0)
		{
			list[i] = InPid;

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Entries: %d \n", (i + 1));
			return;
		}
	}

	list[pos++] = InPid;
	for (int i = pos*MAX_ENTRIES; i < pos*MAX_ENTRIES + MAX_TREE_ENTRIES; i++)
	{
		chromeTree[i] = 0;
	}
}

BOOLEAN addChildProcessToTree(long InParentPid, long InChildPid)
{
	int position = -1;
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == InParentPid)
		{
			position = i;
			break;
		}
	}
	//Better expand the tree instead of returning
	if (position == -1)
		return FALSE;

	for (int i = position * MAX_TREE_ENTRIES; i < position * MAX_TREE_ENTRIES + MAX_TREE_ENTRIES; i++)
	{
		if (chromeTree[i] == 0)
		{
			chromeTree[i] = InChildPid;

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Children: %d \n", (i + 1));
			return TRUE;
		}
	}

	return FALSE;
}

void removePidFromTree(long InPid)
{
	int position = -1;
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == InPid)
		{
			position = i;
			list[i] = 0;
		}
	}

	if (position == -1) {
		for (int i = 0; i < MAX_ENTRIES * MAX_TREE_ENTRIES; i++)
		{
			if (chromeTree[i] == InPid)
			{
				chromeTree[i] = 0;
			}
		}
	}
	else
	{
		for (int i = position * MAX_TREE_ENTRIES; i < position*MAX_TREE_ENTRIES + MAX_TREE_ENTRIES; i++)
		{
			chromeTree[i] = 0;
		}
	}
}

int findPidInTree(long InPid)
{
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == InPid)
		{
			return i;
		}
	}

	for (int i = 0; i < MAX_TREE_ENTRIES * MAX_ENTRIES; i++)
	{
		if (chromeTree[i] == InPid)
		{
			//return 0-9 depending on pos
			return (int)i / (int)MAX_TREE_ENTRIES;
		}
	}


	return -1;
}