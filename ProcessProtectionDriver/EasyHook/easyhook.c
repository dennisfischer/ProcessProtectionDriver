// EasyHook (File: EasyHookSys\main.c)
//
// Copyright (c) 2009 Christoph Husse & Copyright (c) 2015 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project and latest updates.

#include "stdafx.h"

typedef struct _DRIVER_NOTIFICATION_
{
    SLIST_ENTRY		ListEntry;
    ULONG			ProcessId;
}DRIVER_NOTIFICATION, *PDRIVER_NOTIFICATION;


void OnImageLoadNotification(
    IN PUNICODE_STRING  FullImageName,
    IN HANDLE  ProcessId, // where image is mapped
    IN PIMAGE_INFO  ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    LhModuleListChanged = TRUE;
}

NTSTATUS InitEasyHook()
{
	NTSTATUS Status;

	// initialize EasyHook
	if (!NT_SUCCESS(Status = LhBarrierProcessAttach()))
		return Status;

	PsSetLoadImageNotifyRoutine(OnImageLoadNotification);

	LhCriticalInitialize();

	return LhUpdateModuleInformation();
}

VOID FinalizeEasyHook()
{
	// remove all hooks and shutdown thread barrier...
	LhCriticalFinalize();

	LhBarrierProcessDetach();

	PsRemoveLoadImageNotifyRoutine(OnImageLoadNotification);
}

