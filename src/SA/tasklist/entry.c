#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "wmi.c"


#define WMI_QUERY_PROCESSES			L"SELECT * FROM Win32_Process"
#define WMI_KEYS_PROCESSES			L"Name,ProcessId,ParentProcessId,SessionId,CommandLine"
#define RESULTS_OUTPUT_FORMAT		"%-32S %10S %16S %10S %-80S\n"
#define RESULTS_NAME_COL			0
#define RESULTS_PROCESSID_COL		1
#define RESULTS_PARENTPROCESSID_COL	2
#define RESULTS_SESSIONID_COL		3
#define RESULTS_COMMANDLINE_COL		4

HRESULT task_list(
	LPWSTR pwszResource
)
{
	HRESULT	hr = S_OK;
	WMI		m_WMI;
	size_t	ullQuerySize = 0;
	LPWSTR	lpwszQuery = NULL;
	BSTR**	ppbstrResults = NULL;
	DWORD	dwRowCount = 0;
	DWORD	dwColumnCount = 0;
	DWORD	dwCurrentRowIndex = 0;
	DWORD	dwCurrentColumnIndex = 0;

	// Initialize COM
	hr = Wmi_Initialize(&m_WMI);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Initialize failed: 0x%08lx", hr);
		goto fail;
	}

	// Connect to WMI on host
	hr = Wmi_Connect(&m_WMI, pwszResource );
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Connect failed: 0x%08lx", hr);
		goto fail;
	}

	// Run the WMI query
	hr = Wmi_Query(&m_WMI, WMI_QUERY_PROCESSES);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Query failed: 0x%08lx", hr);
		goto fail;
	}

	// Parse the results
	hr = Wmi_ParseResults(&m_WMI, WMI_KEYS_PROCESSES, &ppbstrResults, &dwRowCount, &dwColumnCount);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_ParseResults failed: 0x%08lx", hr);
		goto fail;
	}

	// Display the resuls
	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		internal_printf(
			RESULTS_OUTPUT_FORMAT, 
			ppbstrResults[dwCurrentRowIndex][RESULTS_NAME_COL], 
			ppbstrResults[dwCurrentRowIndex][RESULTS_PROCESSID_COL], 
			ppbstrResults[dwCurrentRowIndex][RESULTS_PARENTPROCESSID_COL],
			ppbstrResults[dwCurrentRowIndex][RESULTS_SESSIONID_COL],
			ppbstrResults[dwCurrentRowIndex][RESULTS_COMMANDLINE_COL]
		);
	}
	hr = S_OK;

fail:

	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
			SAFE_FREE(ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex]);
		}
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ppbstrResults[dwCurrentRowIndex]);
	}
	if (ppbstrResults)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ppbstrResults);
		ppbstrResults = NULL;
	}

	Wmi_Finalize(&m_WMI);
	
	return hr;
}

#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	HRESULT hr = S_OK;
	datap parser;
	wchar_t * server;

	BeaconDataParse(&parser, Buffer, Length);
	server = (wchar_t *)BeaconDataExtract(&parser, NULL);

	if (!bofstart())
	{
		return;
	}

	hr = task_list(server);

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "task_list failed: 0x%08lx", hr);
	}

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	char * server = argv[1];
	wchar_t wserver[260] = {0};
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, server, -1, wserver, 260);
	HRESULT hr = task_list(wserver);
	if(FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "task_list failed: 0x%08lx", hr);
	}

	return 0;
}

#endif


	




