#define _WIN32_DCOM
#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "queue.c"
#include "anticrash.c"
#include <taskschd.h>
	//char * states[] = {"UNKNOWN", "DISABLED", "QUEUED", "READY", "RUNNING"};

//Now I would LOVE to use recursion here, but BOF...
//So were using a queue


void getTask(const wchar_t * server, const wchar_t * taskname)
{
	//Set up com
	HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if(FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Could not initialize com");
		return;
	}
	//Set up our queue for later
	Pqueue q = queueInit();
	//Get an instance of the task scheduler
	char ** states = antiStringResolve(5, "UNKNOWN", "DISABLED", "QUEUED", "READY", "RUNNING");
	VARIANT Vserver;
	VARIANT VNull;
	VARIANT Vindex;
	VARIANT Vdate;
	TASK_STATE tstate;
	VARIANT_BOOL isEnabled = 0;
	DATE taskdate = 0;
	OLEAUT32$VariantInit(&Vserver);
	OLEAUT32$VariantInit(&VNull);
	OLEAUT32$VariantInit(&Vindex);
	OLEAUT32$VariantInit(&Vdate);
	Vindex.vt = VT_I4;
	Vindex.lVal = 0;
	long taskCount = 0;
	long curCount = 0;
	IID CTaskScheduler;
	IID IIDTaskService;
	//IID IIDTaskFolder;
	OLE32$CLSIDFromString(L"{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}", &CTaskScheduler);
	OLE32$IIDFromString(L"{2faba4c7-4da9-4013-9697-20cc3fd40f85}", &IIDTaskService);
	//OLE32$IIDFromString(L"{8cfac062-a080-4c15-9a88-aa7c2af80dfc}", &IIDTaskFolder);
	ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance( &CTaskScheduler,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           &IIDTaskService,
                           (void**)&pService ); 
	if(FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to initialize Task Scheduler interface");
		goto end;
	}
	//Set up our variant for the server name if we need to

	Vserver.vt = VT_BSTR;
	Vserver.bstrVal = OLEAUT32$SysAllocString(server);
	hr = pService->lpVtbl->Connect(pService, Vserver, VNull, VNull, VNull);
	if(FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Could not connect to requested target %x\n", hr);
		goto end;
	}

	//Now we need to get the root folder 
	//ITaskFolder *pCurFolder = NULL;
	ITaskFolder *pCurFolder = NULL;
	ITaskFolderCollection *pSubfolders = NULL;
	ITaskFolder *pFolder = NULL;
	BSTR rootpath = NULL;
	rootpath = OLEAUT32$SysAllocString(L"\\");
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pCurFolder);
    if( FAILED(hr) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer: %x", hr );
		goto end;
    }

	do{
		//Queue up subfolders
		pCurFolder->lpVtbl->GetFolders(pCurFolder, 0, &pSubfolders);
		pSubfolders->lpVtbl->get_Count(pSubfolders, &taskCount);
		for(long i = 1; i <= taskCount; i++)
		{
			Vindex.lVal = i;
			hr = pSubfolders->lpVtbl->get_Item(pSubfolders,Vindex, &pFolder);
			if(SUCCEEDED(hr))
			{
				q->push(q, pFolder);
			}
		}
		//Get all Registered tasks
		IRegisteredTaskCollection* pTaskCollection = NULL;
		hr = pCurFolder->lpVtbl->GetTasks(pCurFolder, TASK_ENUM_HIDDEN, &pTaskCollection);
		if( FAILED(hr))
		{
			BSTR thisname = NULL;
			pCurFolder->lpVtbl->get_Name(pCurFolder, &thisname);
			BeaconPrintf(CALLBACK_ERROR, "Failed to get tasks for folder %S: %x", thisname,hr );
			OLEAUT32$SysFreeString(thisname);
			goto nextloop;
		}

		pTaskCollection->lpVtbl->get_Count(pTaskCollection, &taskCount);
		for(long i = 1; i <= taskCount; i++)
		{
			IRegisteredTask* pRegisteredTask = NULL;
			Vindex.lVal = i;
			hr = pTaskCollection->lpVtbl->get_Item(pTaskCollection, Vindex, &pRegisteredTask);
			if(SUCCEEDED(hr))
			{
				BSTR str = NULL;
				internal_printf("Task %d\n", ++curCount);
				pRegisteredTask->lpVtbl->get_Name(pRegisteredTask, &str);
				internal_printf("Name: %S\n", str);
				OLEAUT32$SysFreeString(str); str = NULL;

				pRegisteredTask->lpVtbl->get_Path(pRegisteredTask, &str);
				internal_printf("Path: %S\n", str);
				OLEAUT32$SysFreeString(str); str = NULL;

				pRegisteredTask->lpVtbl->get_Enabled(pRegisteredTask, &isEnabled);
				internal_printf("Enabled: %s\n", isEnabled == -1 ? "True" : "False");

				Vdate.vt = VT_DATE;
				pRegisteredTask->lpVtbl->get_LastRunTime(pRegisteredTask, &Vdate.date);
				OLEAUT32$VarFormatDateTime(&Vdate, 0, 0, &str);
				internal_printf("Last Run: %S\n", str);
				OLEAUT32$SysFreeString(str); str = NULL;
				pRegisteredTask->lpVtbl->get_NextRunTime(pRegisteredTask, &Vdate.date);
				OLEAUT32$VarFormatDateTime(&Vdate, 0, 0, &str);
				internal_printf("Next Run: %S\n", str);
				OLEAUT32$SysFreeString(str); str = NULL;
				pRegisteredTask->lpVtbl->get_State(pRegisteredTask, &tstate);
				internal_printf("Current State: %s\n", states[tstate]);
				if(SUCCEEDED(pRegisteredTask->lpVtbl->get_Xml(pRegisteredTask, &str)))
				{

					internal_printf("%S\n", str);
					OLEAUT32$SysFreeString(str);
				}
				else
				{
					internal_printf("Failed to get xml for this task\n");
				}
				internal_printf("--------------------------------\n");

			}
			if(pRegisteredTask)
			{
				pRegisteredTask->lpVtbl->Release(pRegisteredTask);
				pRegisteredTask = NULL;
			}
		}
		nextloop:
		if(pTaskCollection)
		{
			pTaskCollection->lpVtbl->Release(pTaskCollection);
			pTaskCollection = NULL;
		}
		if(pCurFolder)
		{
			pCurFolder->lpVtbl->Release(pCurFolder);
			pCurFolder = NULL;
		}
	}while(pCurFolder = q->pop(q));


	end:
	intFree(states);
	q->free(q);
	if(pService)
	{
		pService->lpVtbl->Release(pService);
		pService = NULL;
	}
	if(rootpath)
	{
		OLEAUT32$SysFreeString(rootpath);
		rootpath = NULL;
	}
	OLEAUT32$VariantClear(&Vserver);
	OLE32$CoUninitialize();
}

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	getTask(L"", L"BIG");
	printoutput(TRUE);
	bofstop();
};
