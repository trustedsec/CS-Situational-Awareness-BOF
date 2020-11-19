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
	VARIANT Vdate;
	BSTR rootpath = NULL;
	BSTR taskpath = NULL;
	TASK_STATE tstate;
	VARIANT_BOOL isEnabled = 0;
	DATE taskdate = 0;
	OLEAUT32$VariantInit(&Vserver);
	OLEAUT32$VariantInit(&VNull);
	OLEAUT32$VariantInit(&Vdate);
	IID CTaskScheduler = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
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
		BeaconPrintf(CALLBACK_ERROR, "Could not connect to requested target %lx\n", hr);
		goto end;
	}

	//Now we need to get the root folder 
	//ITaskFolder *pCurFolder = NULL;
	ITaskFolder *pCurFolder = NULL;

	rootpath = OLEAUT32$SysAllocString(L"\\");
	hr = pService->lpVtbl->GetFolder(pService, rootpath, &pCurFolder);
    if( FAILED(hr) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer: %lx", hr );
		goto end;
    }

	
	IRegisteredTask* pRegisteredTask = NULL;
	taskpath = OLEAUT32$SysAllocString(taskname);
	hr = pCurFolder->lpVtbl->GetTask(pCurFolder, taskpath, &pRegisteredTask);
	if(SUCCEEDED(hr))
	{
		BSTR str = NULL;
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
	else{
		internal_printf("Could not find a task at given path of %S\n", taskpath);
		internal_printf("When using query you must give the full path and name of the task you are looking for\n");
	}
	if(pRegisteredTask)
	{
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		pRegisteredTask = NULL;
	}
	if(pCurFolder)
	{
		pCurFolder->lpVtbl->Release(pCurFolder);
		pCurFolder = NULL;
	}


	end:
	if(taskpath)
	{
		OLEAUT32$SysFreeString(taskpath);
		taskpath = NULL;
	}
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

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	const wchar_t * hostname;
	const wchar_t * taskname;
	BeaconDataParse(&parser, Buffer, Length);
	hostname = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	taskname = (const wchar_t *)BeaconDataExtract(&parser, NULL);
	if(!bofstart())
	{
		return;
	}
	getTask(hostname, taskname);
	printoutput(TRUE);

};

#else
int main(){
	getTask(L"", L"\\Microsoft\\Windows\\Autochk\\Proxy");
	return 0;
}

#endif

