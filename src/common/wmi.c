#include <windows.h>
#include <stdio.h>
#include <oleauto.h>
#include <wbemcli.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include "beacon.h"
#include "bofdefs.h"
#include "wmi.h"

#define KEY_SEPARATOR			L" ,\t\n"
#define HEADER_ROW				0
#define WMI_QUERY_LANGUAGE		L"WQL"
#define WMI_NAMESPACE_CIMV2		L"root\\cimv2"
#define RESOURCE_FMT_STRING		L"\\\\%s\\%s"
#define RESOURCE_LOCAL_HOST		L"."
#define ERROR_RESULT			L"*ERROR*"
#define EMPTY_RESULT			L"(EMPTY)"
#define NULL_RESULT				L"(NULL)"

#define SAFE_RELEASE( interfacepointer )	\
	if ( (interfacepointer) != NULL )	\
	{	\
		(interfacepointer)->lpVtbl->Release(interfacepointer);	\
		(interfacepointer) = NULL;	\
	}
#define SAFE_FREE( string_ptr )	\
	if ( (string_ptr) != NULL )	\
	{	\
		OLEAUT32$SysFreeString(string_ptr);	\
		(string_ptr) = NULL;	\
	}



HRESULT Wmi_Initialize(WMI* pWmi)
{
	HRESULT	hr = S_OK;

	pWmi->pWbemServices = NULL;
	pWmi->pWbemLocator  = NULL;
	pWmi->pEnumerator = NULL;
	pWmi->bstrLanguage  = NULL;
	pWmi->bstrNameSpace = NULL;
	pWmi->bstrNetworkResource = NULL;
	pWmi->bstrQuery = NULL;
	
	pWmi->bstrLanguage = OLEAUT32$SysAllocString(WMI_QUERY_LANGUAGE);
	pWmi->bstrNameSpace = OLEAUT32$SysAllocString(WMI_NAMESPACE_CIMV2);

	// Initialize COM parameters
	hr = OLE32$CoInitializeEx(
		NULL, 
		COINIT_APARTMENTTHREADED
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoInitializeEx failed: 0x%08lx", hr);
		goto fail;
	}

	// Initialize COM process security
	hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0);
	if (FAILED(hr))
	{
		if (RPC_E_TOO_LATE != hr)
		{
			BeaconPrintf(CALLBACK_ERROR, "OLE32$CoInitializeSecurity failed: 0x%08lx", hr);
			OLE32$CoUninitialize();
			goto fail;
		}
	}
	
	hr = S_OK;

fail:

	return hr;
}

HRESULT Wmi_Connect(
	WMI* pWmi, 
	LPWSTR pwszServer
)
{
	HRESULT hr = S_OK;
	size_t	ullNetworkResourceSize = 0;
	LPWSTR	lpwszNetworkResource = NULL;

	CLSID	CLSID_WbemLocator = { 0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0, 0xAA, 0, 0x4B, 0x2E, 0x24} };
	IID		IID_IWbemLocator = { 0xDC12A687, 0x737F, 0x11CF, {0x88, 0x4D, 0, 0xAA, 0, 0x4B, 0x2E, 0x24} };
	
	ullNetworkResourceSize = (2 + MSVCRT$wcslen(pwszServer) + 1 + MSVCRT$wcslen(WMI_NAMESPACE_CIMV2) + 1) * sizeof(wchar_t);
	lpwszNetworkResource = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ullNetworkResourceSize);
	if (NULL == lpwszNetworkResource)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}

	if (MSVCRT$wcslen(pwszServer) > 0)
	{
		if (-1 == MSVCRT$swprintf(lpwszNetworkResource, RESOURCE_FMT_STRING, pwszServer, WMI_NAMESPACE_CIMV2))
		{
			hr = WBEM_E_INVALID_NAMESPACE;
			BeaconPrintf(CALLBACK_ERROR, "MSVCRT$swprintf failed: 0x%08lx", hr);
			goto fail;
		}
	}
	else
	{
		if (-1 == MSVCRT$swprintf(lpwszNetworkResource, RESOURCE_FMT_STRING, RESOURCE_LOCAL_HOST, WMI_NAMESPACE_CIMV2))
		{
			hr = WBEM_E_INVALID_NAMESPACE;
			BeaconPrintf(CALLBACK_ERROR, "MSVCRT$swprintf failed: 0x%08lx", hr);
			goto fail;
		}
	}
	
	pWmi->bstrServer = OLEAUT32$SysAllocString(pwszServer);
	pWmi->bstrNetworkResource = OLEAUT32$SysAllocString(lpwszNetworkResource);

	// Obtain the initial locator to Windows Management on host computer
	SAFE_RELEASE(pWmi->pWbemLocator);
	hr = OLE32$CoCreateInstance(
		&CLSID_WbemLocator,
		0,
		CLSCTX_ALL,
		&IID_IWbemLocator,
		(LPVOID *)&(pWmi->pWbemLocator)
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance failed: 0x%08lx", hr);
		OLE32$CoUninitialize();
		goto fail;
	}

	// Connect to the WMI namespace on host computer with the current user
	hr = pWmi->pWbemLocator->lpVtbl->ConnectServer(
		pWmi->pWbemLocator,
		pWmi->bstrNetworkResource,
		NULL,
		NULL,
		NULL,
		0,
		NULL,
		NULL,
		&(pWmi->pWbemServices)
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "ConnectServer failed: 0x%08lx", hr);
		goto fail;
	}

	// Set the IWbemServices proxy so that impersonation of the user (client) occurs
	hr = OLE32$CoSetProxyBlanket(
		(IUnknown *)(pWmi->pWbemServices),
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_DYNAMIC_CLOAKING
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoSetProxyBlanket failed: 0x%08lx", hr);
		goto fail;
	}

	hr = S_OK;

fail:
	if (lpwszNetworkResource)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwszNetworkResource);
		lpwszNetworkResource = NULL;
	}
	return hr;
}

HRESULT Wmi_Query(
	WMI* pWmi, 
	LPWSTR pwszQuery
)
{
	HRESULT hr = 0;

	// Free any previous queries
	SAFE_FREE(pWmi->bstrQuery);

	// Set the query
	pWmi->bstrQuery = OLEAUT32$SysAllocString(pwszQuery);

	// Free any previous results
	SAFE_RELEASE(pWmi->pEnumerator);

	// Use the IWbemServices pointer to make requests of WMI
	hr = pWmi->pWbemServices->lpVtbl->ExecQuery(
		pWmi->pWbemServices,
		pWmi->bstrLanguage,
		pWmi->bstrQuery,
		WBEM_FLAG_BIDIRECTIONAL,
		NULL,
		&(pWmi->pEnumerator));

	if (hr != S_OK)
	{
		SAFE_RELEASE(pWmi->pEnumerator);
		BeaconPrintf(CALLBACK_ERROR, "ExecQuery failed: 0x%08lx", hr);
		goto fail;
	}

	// Set the IWbemServices proxy so that impersonation of the user (client) occurs
	hr = OLE32$CoSetProxyBlanket(
		(IUnknown *)(pWmi->pEnumerator),
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_DYNAMIC_CLOAKING
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoSetProxyBlanket failed: 0x%08lx", hr);
		goto fail;
	}

	hr = S_OK;

fail:
	return hr;
}


HRESULT Wmi_ParseResults(
	WMI* pWmi,
	LPWSTR pwszKeys,
	BSTR*** ppwszResults,
	LPDWORD pdwRowCount,
	LPDWORD pdwColumnCount
)
{
	HRESULT hr = 0;
	BSTR bstrColumns = NULL;
	BSTR** bstrResults = NULL;
	BSTR* bstrCurrentRow = NULL;
	DWORD dwColumnCount = 1;
	DWORD dwRowCount = 0;
	LPWSTR pCurrentKey = NULL;
	DWORD dwIndex = 0;
	IWbemClassObject *pWbemClassObjectResult = NULL;
	ULONG ulResultCount = 0;
	VARIANT varProperty;

	// Fill in the header row
	// Count the number of header columns
	bstrColumns = OLEAUT32$SysAllocString(pwszKeys);
	for(dwIndex = 0; bstrColumns[dwIndex]; dwIndex++)
	{
		if (bstrColumns[dwIndex] == L',')
			dwColumnCount++;
	} 
	// Allocate space for the columns in the header row
	bstrCurrentRow = (BSTR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BSTR)*dwColumnCount);
	if (NULL == bstrCurrentRow)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}
	// Fill in each column in the header row
	pCurrentKey = MSVCRT$wcstok(bstrColumns, KEY_SEPARATOR); ;
	for(dwIndex = 0; pCurrentKey; dwIndex++)
	{
		bstrCurrentRow[dwIndex] = OLEAUT32$SysAllocString(pCurrentKey);
		pCurrentKey = MSVCRT$wcstok(NULL, KEY_SEPARATOR);
	} 
	// Allocate space for the results including the current row
	dwRowCount++;
	bstrResults = (BSTR**)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BSTR*)*dwRowCount);
	if (NULL == bstrResults)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}
	bstrResults[dwRowCount-1] = bstrCurrentRow;
	bstrCurrentRow = NULL;

	// Loop through the enumeration of results
	hr = WBEM_S_NO_ERROR;
	while (WBEM_S_NO_ERROR == hr)
	{
		// Get the next result in our enumeration of results
		hr = pWmi->pEnumerator->lpVtbl->Next(pWmi->pEnumerator, WBEM_INFINITE, 1, &pWbemClassObjectResult, &ulResultCount);
		if (hr == S_OK && ulResultCount > 0) 
		{
			if (pWbemClassObjectResult == NULL) 
			{
				continue;
			}

			// Allocate space for the columns in the current row
			bstrCurrentRow = (BSTR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BSTR)*dwColumnCount);
			if (NULL == bstrCurrentRow)
			{
				hr = WBEM_E_OUT_OF_MEMORY;
				BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
				goto fail;
			}
			
			// Loop through each column/key and get that property from the current result
			for (dwIndex = 0; dwIndex < dwColumnCount; dwIndex++)
			{
				pCurrentKey = bstrResults[HEADER_ROW][dwIndex];

				OLEAUT32$VariantInit(&varProperty);

				// Get the corresponding entry from the current result for the current key
				hr = pWbemClassObjectResult->lpVtbl->Get(pWbemClassObjectResult, pCurrentKey, 0, &varProperty, 0, 0);
				if (FAILED(hr))
				{
					BeaconPrintf(CALLBACK_ERROR, "pWbemClassObjectResult->lpVtbl->Get failed: 0x%08lx", hr);
					//goto fail;
					continue;
				}

				if (VT_EMPTY == varProperty.vt)
				{
					bstrCurrentRow[dwIndex] = OLEAUT32$SysAllocString(EMPTY_RESULT);
				}
				else if (VT_NULL == varProperty.vt)
				{
					bstrCurrentRow[dwIndex] = OLEAUT32$SysAllocString(NULL_RESULT);
				}
				else
				{
					hr = OLEAUT32$VariantChangeType(&varProperty, &varProperty, VARIANT_ALPHABOOL, VT_BSTR);
					if (FAILED(hr))
					{
						hr = WBEM_S_NO_ERROR;
						bstrCurrentRow[dwIndex] = OLEAUT32$SysAllocString(ERROR_RESULT);
					}
					else
					{
						bstrCurrentRow[dwIndex] = OLEAUT32$SysAllocString(varProperty.bstrVal);
					}
				}

				OLEAUT32$VariantClear(&varProperty);

			} // end for loop through each column/key

			// Allocate space for the results including the current row
			dwRowCount++;
			bstrResults = (BSTR**)KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bstrResults, sizeof(BSTR*)*dwRowCount);
			if (NULL == bstrResults)
			{
				hr = WBEM_E_OUT_OF_MEMORY;
				BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapReAlloc failed: 0x%08lx", hr);
				goto fail;
			}
			bstrResults[dwRowCount - 1] = bstrCurrentRow;
			bstrCurrentRow = NULL;

			// Release the current result
			pWbemClassObjectResult->lpVtbl->Release(pWbemClassObjectResult);

		} // end if we got a pWbemClassObjectResult

	} // end While loop through enumeration of results


	*ppwszResults = bstrResults;
	*pdwRowCount = dwRowCount;
	*pdwColumnCount = dwColumnCount;
fail:
	SAFE_FREE(bstrColumns);

	return hr;
}

HRESULT Wmi_Finalize(
	WMI* pWmi
)
{
	HRESULT hr = S_OK;

	SAFE_RELEASE(pWmi->pWbemServices);
	SAFE_RELEASE(pWmi->pWbemLocator);
	SAFE_RELEASE(pWmi->pWbemLocator);

	SAFE_FREE(pWmi->bstrLanguage);
	SAFE_FREE(pWmi->bstrServer);
	SAFE_FREE(pWmi->bstrNameSpace);
	SAFE_FREE(pWmi->bstrNetworkResource);
	SAFE_FREE(pWmi->bstrQuery);

	// un-initialize the COM library
	OLE32$CoUninitialize();

fail:
	return hr;
}
