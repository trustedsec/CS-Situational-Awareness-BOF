#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "wmi.c"


//#define WMI_QUERY_PROCESSES			L"SELECT * FROM Win32_Process"
//#define WMI_KEYS_PROCESSES			L"Name,ProcessId,ParentProcessId,SessionId,CommandLine"
//#define RESULTS_OUTPUT_FORMAT		"%-32S %10S %16S %10S %-80S\n"
#define RESULTS_OUTPUT_FORMAT		"%S, "


HRESULT wmi_query(
	LPWSTR pwszServer,
	LPWSTR pwszQuery
)
{
	HRESULT	hr = S_OK;
	WMI		m_WMI;
	size_t	ullColumnsSize = 0;
	LPWSTR	lpwszColumns = NULL;	
	BSTR**	ppbstrResults = NULL;
	DWORD	dwRowCount = 0;
	DWORD	dwColumnCount = 0;
	DWORD	dwCurrentRowIndex = 0;
	DWORD	dwCurrentColumnIndex = 0;

	hr = S_OK;

	BeaconPrintf(CALLBACK_OUTPUT, "pwszServer: %S", pwszServer);
	BeaconPrintf(CALLBACK_OUTPUT, "pwszQuery:  %S", pwszQuery);

	// Initialize COM
	hr = Wmi_Initialize(&m_WMI);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Initialize failed: 0x%08lx", hr);
		goto fail;
	}

	// Connect to WMI on host
	hr = Wmi_Connect(&m_WMI, pwszServer );
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Connect failed: 0x%08lx", hr);
		goto fail;
	}

	// Run the WMI query
	hr = Wmi_Query(&m_WMI, pwszQuery);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Query failed: 0x%08lx", hr);
		goto fail;
	}

	// Parse the results
	hr = Wmi_ParseResults(&m_WMI, lpwszColumns, &ppbstrResults, &dwRowCount, &dwColumnCount);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_ParseResults failed: 0x%08lx", hr);
		goto fail;
	}

	// Display the resuls
	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
			internal_printf( RESULTS_OUTPUT_FORMAT, ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );
		}
		internal_printf( RESULTS_OUTPUT_FORMAT, "\n" );
	}

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

	hr = Wmi_Finalize(&m_WMI);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Destroy failed: 0x%08lx", hr);
	}

	return hr;
}

VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	HRESULT hr = S_OK;
	datap parser;
	wchar_t * server;
	wchar_t * query_string;

	BeaconDataParse(&parser, Buffer, Length);
	server = (wchar_t *)BeaconDataExtract(&parser, NULL);
	query_string = (wchar_t *)BeaconDataExtract(&parser, NULL);

	if (!bofstart())
	{
		return;
	}

	hr = wmi_query(server, query_string);

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "wmi_query failed: 0x%08lx", hr);
	}

	printoutput(TRUE);

	bofstop();
};

	




