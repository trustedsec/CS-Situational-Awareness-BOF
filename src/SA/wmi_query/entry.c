#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "wmi.c"

HRESULT wmi_query(
	LPWSTR pwszServer,
	LPWSTR pwszNameSpace,	
	LPWSTR pwszQuery,
	LPWSTR pwszResource
)
{
	HRESULT	hr						= S_OK;
	WMI		m_WMI;
	size_t	ullColumnsSize			= 0;
	LPWSTR	lpwszColumns			= NULL;	
	BSTR**	ppbstrResults			= NULL;
	DWORD	dwRowCount				= 0;
	DWORD	dwColumnCount			= 0;
	DWORD	dwCurrentRowIndex		= 0;
	DWORD	dwCurrentColumnIndex	= 0;

	// Initialize COM
	hr = Wmi_Initialize(&m_WMI);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_Initialize failed: 0x%08lx", hr);
		goto fail;
	}

	// Connect to WMI on host
	hr = Wmi_Connect(&m_WMI, pwszResource);
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
	hr = Wmi_ParseAllResults(&m_WMI, &ppbstrResults, &dwRowCount, &dwColumnCount);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Wmi_ParseAllResults failed: 0x%08lx", hr);
		goto fail;
	}

	// Display the resuls in CSV format
	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
            if ( 0 == dwCurrentColumnIndex )		
            {
    			internal_printf( "%S", ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );			
            }
            else
            {
                internal_printf( ", %S", ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );    			
            }
		}
		internal_printf( "\n" );
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
	wchar_t * pwszServer = NULL;
	wchar_t * pwszNameSpace = NULL;	
	wchar_t * pwszQuery = NULL;
	wchar_t * pwszResource = NULL;

	if (!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	pwszServer = (wchar_t *)BeaconDataExtract(&parser, NULL);
	pwszNameSpace = (wchar_t *)BeaconDataExtract(&parser, NULL);	
	pwszQuery = (wchar_t *)BeaconDataExtract(&parser, NULL);
	pwszResource = (wchar_t *)BeaconDataExtract(&parser, NULL);
	
	hr = wmi_query(pwszServer, pwszNameSpace, pwszQuery, pwszResource);

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "wmi_query failed: 0x%08lx", hr);
	}

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;

	hr = wmi_query(L".", L"root\\cimv2", L"select * from win32_process");

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "wmi_query failed: 0x%08lx", hr);
	}
	return 0;
}
#endif

	




