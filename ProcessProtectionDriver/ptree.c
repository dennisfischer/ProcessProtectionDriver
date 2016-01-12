#include "stdafx.h"

//List Head
PLIST_ENTRY PListHead;
//SpinLock (busy waiting Lock) for thread synchronization
//Mutexes might lead to context change, so busy waiting is overall faster
PKSPIN_LOCK PTreeSpinLock;

//Setups the process tree
VOID InitializePTree()
{
	PTreeSpinLock = AllocMemory(TRUE, sizeof(KSPIN_LOCK));
	KeInitializeSpinLock(PTreeSpinLock);

	KLOCK_QUEUE_HANDLE SpinLockHandle;
	KeAcquireInStackQueuedSpinLock(PTreeSpinLock, &SpinLockHandle);

	//Init list head
	PListHead = AllocMemory(TRUE, sizeof(LIST_ENTRY));
	InitializeListHead(PListHead);
	KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
}

//Removes all children of a given parent process
VOID RemoveChildren(PPROCESS_LIST_ENTRY entry)
{
	//Iterate through list
	PLIST_ENTRY childHead = entry->ChildHead;
	PLIST_ENTRY child = childHead->Flink;
	while (childHead != child->Flink)
	{
		//Get child, free memory and remove list entry
		PPROCESS_LIST_ENTRY_CHILD record = CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry);
		RemoveEntryList(child);
		child = child->Flink;
		FreeMemory(record);
		record = NULL;
	}
	FreeMemory(entry->ChildHead);
	entry->ChildHead = NULL;
}

//Destroys the process tree during driver unload
VOID DestroyPTree()
{
	KLOCK_QUEUE_HANDLE SpinLockHandle;
	KeAcquireInStackQueuedSpinLock(PTreeSpinLock, &SpinLockHandle);

	//Delete all parents
	PLIST_ENTRY entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
		//Get parent, delete childs, free memory and remove list entry
		PPROCESS_LIST_ENTRY record = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry);
		RemoveChildren(record);
		RemoveEntryList(entry);
		entry = entry->Flink;
		FreeMemory(record);
		record = NULL;
	}

	KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
	FreeMemory(PTreeSpinLock);
	PTreeSpinLock = NULL;
}

//Inserts a new parent pid
VOID InsertPidToTree(ULONG InPid)
{
	KLOCK_QUEUE_HANDLE SpinLockHandle;
	KeAcquireInStackQueuedSpinLock(PTreeSpinLock, &SpinLockHandle);

	//Check if tree already contains parent and return
	PLIST_ENTRY entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InPid)
		{
			KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
			return;
		}
		entry = entry->Flink;
	}

	//Otherwise add new parent list entry
	PPROCESS_LIST_ENTRY newEntry = AllocMemory(TRUE, sizeof(PROCESS_LIST_ENTRY));
	newEntry->Pid = InPid;
	newEntry->ChildHead = AllocMemory(TRUE, sizeof(LIST_ENTRY));
	InitializeListHead(newEntry->ChildHead);
	InsertHeadList(PListHead, &(newEntry->ListEntry));

	KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
}

//Adds a child pid to an existing parent pid entry
VOID AddChildPidToTree(ULONG InParentPid, ULONG InChildPid)
{
	KLOCK_QUEUE_HANDLE SpinLockHandle;
	KeAcquireInStackQueuedSpinLock(PTreeSpinLock, &SpinLockHandle);

	//First find parent
	PLIST_ENTRY entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
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
					KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
					return;
				}
			}

			//Add new child otherwise
			PPROCESS_LIST_ENTRY_CHILD newEntry = AllocMemory(TRUE, sizeof(PROCESS_LIST_ENTRY_CHILD));
			newEntry->Pid = InChildPid;
			newEntry->ParentPid = InParentPid;
			InsertHeadList(childHead, &(newEntry->ListEntry));
		}
		entry = entry->Flink;
	}

	KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
}

//Finds and removes PID from tree
VOID RemovePidFromTree(ULONG InPid)
{
	KLOCK_QUEUE_HANDLE SpinLockHandle;
	KeAcquireInStackQueuedSpinLock(PTreeSpinLock, &SpinLockHandle);

	//First, quickly check parents
	PLIST_ENTRY entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InPid)
		{
			//Found, remove parent + children
			PPROCESS_LIST_ENTRY record = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry);
			RemoveChildren(record);
			RemoveEntryList(entry);
			FreeMemory(record);
			record = NULL;
			KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
			return;
		}
		entry = entry->Flink;
	}


	//If not found, check children of all parents
	entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
		//Is PID part of children?
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
				record = NULL;
				KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
				return;
			}
		}
		entry = entry->Flink;
	}

	KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
}

//Finds PID inside the tree
ULONG FindPidInTree(ULONG InPid)
{
	KLOCK_QUEUE_HANDLE SpinLockHandle;
	KeAcquireInStackQueuedSpinLock(PTreeSpinLock, &SpinLockHandle);

	//First, quickly check parents
	PLIST_ENTRY entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
		if (CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->Pid == InPid)
		{
			KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
			return InPid;
		}
		entry = entry->Flink;
	}

	//If not found, check children of all parents
	entry = PListHead->Flink;
	while (PListHead != entry->Flink)
	{
		PLIST_ENTRY childHead = CONTAINING_RECORD(entry, PROCESS_LIST_ENTRY, ListEntry)->ChildHead;
		PLIST_ENTRY child = childHead;
		while (childHead != child->Flink)
		{
			child = child->Flink;
			if (CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry)->Pid == InPid)
			{
				DEBUG("Exit Find Pid PTree\n");
				KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
				return CONTAINING_RECORD(child, PROCESS_LIST_ENTRY_CHILD, ListEntry)->ParentPid;
			}
		}
		entry = entry->Flink;
	}

	KeReleaseInStackQueuedSpinLock(&SpinLockHandle);
	return 0;
}

