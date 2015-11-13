#pragma once
const int MAX_ENTRIES = 10;
const int MAX_TREE_ENTRIES = 50;
int pos = 0;
long list[MAX_ENTRIES] = { 0 };
long chromeTree[MAX_ENTRIES * MAX_TREE_ENTRIES] = { 0 };

bool addChildProcessToTree(long parentPid, long pid);
void insertProcessToTree(long pid);
void removePidFromTree(long pid);
int findPidInTree(long pid);


inline void insertProcessToTree(long pid)
{
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == 0)
		{
			list[i] = pid;

			DbgPrintEx(
				DPFLTR_IHVDRIVER_ID,
				DPFLTR_ERROR_LEVEL,
				"Entries: %d \n",
				(i + 1)
				);
			return;
		}
	}

	list[pos++] = pid;
	for (int i = pos*MAX_ENTRIES; i < pos*MAX_ENTRIES + MAX_TREE_ENTRIES; i++)
	{
		chromeTree[i] = 0;
	}
}

inline bool addChildProcessToTree(long parentPid, long pid)
{
	int position = -1;
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == parentPid)
		{
			position = i;
			break;
		}
	}
	//Better expand the tree instead of returning
	if (position == -1)
		return false;

	for (int i = position * MAX_TREE_ENTRIES; i < position * MAX_TREE_ENTRIES + MAX_TREE_ENTRIES; i++)
	{
		if (chromeTree[i] == 0)
		{
			chromeTree[i] = pid;


			DbgPrintEx(
				DPFLTR_IHVDRIVER_ID,
				DPFLTR_ERROR_LEVEL,
				"Children: %d \n",
				(i + 1)
				);
			return true;
		}
	}

	return false;
}

 inline void removePidFromTree(long pid)
{
	int position = -1;
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == pid)
		{
			position = i;
			list[i] = 0;
		}
	}

	if (position == -1) {
		for (int i = 0; i < MAX_ENTRIES * MAX_TREE_ENTRIES; i++)
		{
			if (chromeTree[i] == pid)
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

inline int findPidInTree(long pid)
{
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == pid)
		{
			return i;
		}
	}

	for (int i = 0; i < MAX_TREE_ENTRIES * MAX_ENTRIES; i++)
	{
		if (chromeTree[i] == pid)
		{
			//return 0-9 depending on pos
			return int(i / MAX_TREE_ENTRIES);
		}
	}


	return -1;
}