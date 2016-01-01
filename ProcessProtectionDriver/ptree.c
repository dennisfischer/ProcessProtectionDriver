#include "stdafx.h"

PLIST_ENTRY	PListHead;

VOID InitializePTree()
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Init PTree\n");

	PListHead = AllocMemory(TRUE, sizeof(LIST_ENTRY));
	InitializeListHead(PListHead);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Init PTree\n");
}

VOID RemoveChildren(PPROCESS_LIST_ENTRY entry)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Remove Children PTree\n");

	PLIST_ENTRY childHead = entry->ChildHead;
	PLIST_ENTRY child = childHead;
	while (childHead != child->Flink)
	{
		child = child->Flink;
		PPROCESS_LIST_ENTRY_CHILD record = CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry);
		RemoveEntryList(child);
		FreeMemory(record);
	}
	FreeMemory(entry->ChildHead);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Remove Children PTree\n");
}

VOID DestroyPTree()
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Destroy PTree\n");

	PLIST_ENTRY entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;
		PPROCESS_LIST_ENTRY record = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry);
		RemoveChildren(record);
		RemoveEntryList(entry);
		FreeMemory(record);
	}

	FreeMemory(PListHead);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Destroy PTree\n");
}

//Inserts a new parent pid
VOID InsertPidToTree(ULONG InPid)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Insert PTree\n");

	//Check if tree already contains parent and return
	PLIST_ENTRY entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;
		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InPid)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Insert PTree\n");
			return;
		}
	}

	//Otherwise add new parent list entry
	PPROCESS_LIST_ENTRY newEntry = AllocMemory(TRUE, sizeof(PROCESS_LIST_ENTRY));
	newEntry->Pid = InPid;
	newEntry->ChildHead = AllocMemory(TRUE, sizeof(LIST_ENTRY));
	InitializeListHead(newEntry->ChildHead);
	InsertHeadList(PListHead, &(newEntry->ListEntry));

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Insert PTree\n");
}

//Adds a child pid to an existing parent pid entry
VOID AddChildPidToTree(ULONG InParentPid, ULONG InChildPid)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AddChild PTree\n");

	//First find parent
	PLIST_ENTRY entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;

		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InParentPid)
		{
			//Check if child already exists
			PLIST_ENTRY childHead = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->ChildHead;
			PLIST_ENTRY child = childHead;
			while (childHead != child->Flink)
			{
				child = child->Flink;
				if (CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry)->Pid == InChildPid)
				{
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit AddChild PTree\n");
					return;
				}
			}

			//Add new child otherwise
			PPROCESS_LIST_ENTRY_CHILD newEntry = AllocMemory(TRUE, sizeof(PROCESS_LIST_ENTRY_CHILD));
			newEntry->Pid = InChildPid;
			newEntry->ParentPid = InParentPid;
			InsertHeadList(childHead, &(newEntry->ListEntry));
		}
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit AddChild PTree\n");
}

//Finds and removes PID from tree
VOID RemovePidFromTree(ULONG InPid)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Remove Pid PTree\n");

	//First, quickly check parents
	PLIST_ENTRY entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;

		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InPid)
		{
			//Found, remove parent + children
			PPROCESS_LIST_ENTRY record = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry);
			RemoveChildren(record);
			RemoveEntryList(entry);
			FreeMemory(record);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Pid PTree\n");
			return;
		}
	}


	//If not found, check children of all parents
	entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;

		PLIST_ENTRY childHead = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->ChildHead;
		PLIST_ENTRY child = childHead;
		while (childHead != child->Flink)
		{
			child = child->Flink;
			if (CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry)->Pid == InPid)
			{
				PPROCESS_LIST_ENTRY_CHILD record = CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry);

				//Just remove child
				RemoveEntryList(child);
				FreeMemory(record);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Pid PTree\n");
				return;
			}
		}
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Pid PTree\n");
}

//Finds PID inside the tree
ULONG FindPidInTree(ULONG InPid)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Find Pid PTree\n");

	//First, quickly check parents
	PLIST_ENTRY entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;

		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InPid)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Find Pid PTree\n");
			return InPid;
		}
	}

	//If not found, check children of all parents
	entry = PListHead;
	while (PListHead != entry->Flink)
	{
		entry = entry->Flink;

		PLIST_ENTRY childHead = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->ChildHead;
		PLIST_ENTRY child = childHead;
		while (childHead != child->Flink)
		{
			child = child->Flink;
			if (CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry)->Pid == InPid)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Find Pid PTree\n");
				return CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry)->ParentPid;
			}
		}
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Exit Find Pid PTree\n");
	return 0;
}