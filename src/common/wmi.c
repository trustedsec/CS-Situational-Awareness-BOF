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

#define SAFE_DESTROY( arraypointer )	\
	if ( (arraypointer) != NULL )	\
	{	\
		OLEAUT32$SafeArrayDestroy(arraypointer);	\
		(arraypointer) = NULL;	\
	}
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
	pWmi->bstrServer = NULL;
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
	LPWSTR pwszServerArg,
	LPWSTR pwszNameSpaceArg
)
{
	HRESULT hr = S_OK;
	LPWSTR  pwszServer = NULL;
	LPWSTR  pwszNameSpace = NULL;	
	size_t	ullNetworkResourceSize = 0;
	LPWSTR	lpwszNetworkResource = NULL;


	CLSID	CLSID_WbemLocator = { 0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0, 0xAA, 0, 0x4B, 0x2E, 0x24} };
	IID		IID_IWbemLocator = { 0xDC12A687, 0x737F, 0x11CF, {0x88, 0x4D, 0, 0xAA, 0, 0x4B, 0x2E, 0x24} };
	
	// Get the server
	pwszServer = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH*sizeof(wchar_t));
	if (NULL == pwszServer)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}
	if ( (NULL != pwszServerArg) && (MSVCRT$wcslen(pwszServerArg) > 0) )
	{
		MSVCRT$wcscpy_s(pwszServer, MAX_PATH, pwszServerArg);
	}
	else
	{
		MSVCRT$wcscpy_s(pwszServer, MAX_PATH, RESOURCE_LOCAL_HOST);		
	}
	
	// Get the namespace	
	pwszNameSpace = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH*sizeof(wchar_t));
	if (NULL == pwszNameSpace)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}
	if ( (NULL != pwszNameSpaceArg) && (MSVCRT$wcslen(pwszNameSpaceArg) > 0) )
	{
		MSVCRT$wcscpy_s(pwszNameSpace, MAX_PATH, pwszNameSpaceArg);
	}
	else
	{
		MSVCRT$wcscpy_s(pwszNameSpace, MAX_PATH, WMI_NAMESPACE_CIMV2);		
	}
	
	// Create the full resource path from the server and namespace
	ullNetworkResourceSize = (2 + MSVCRT$wcslen(pwszServer) + 1 + MSVCRT$wcslen(pwszNameSpace) + 1) * sizeof(wchar_t);
	lpwszNetworkResource = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ullNetworkResourceSize);
	if (NULL == lpwszNetworkResource)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}
	if (-1 == MSVCRT$_snwprintf(lpwszNetworkResource, ullNetworkResourceSize, RESOURCE_FMT_STRING, pwszServer, pwszNameSpace))
	{
		hr = WBEM_E_INVALID_NAMESPACE;
		BeaconPrintf(CALLBACK_ERROR, "MSVCRT$swprintf failed: 0x%08lx", hr);
		goto fail;
	}
	
	// Set the properties in the WMI object
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
    // Free local allocations
	if (pwszServer)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pwszServer);
		pwszServer = NULL;
	}
	if (pwszNameSpace)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pwszNameSpace);
		pwszNameSpace = NULL;
	}
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
	if (FAILED(hr))
	{
    	BeaconPrintf(CALLBACK_ERROR, "ExecQuery failed: 0x%08lx", hr);
		SAFE_RELEASE(pWmi->pEnumerator);
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
    	SAFE_RELEASE(pWmi->pEnumerator);
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
	BSTR    bstrColumns = NULL;
	BSTR**  bstrResults = NULL;
	BSTR*   bstrCurrentRow = NULL;
	DWORD   dwColumnCount = 1;
	DWORD   dwRowCount = 0;
	LPWSTR  pCurrentKey = NULL;
	DWORD   dwIndex = 0;
	IWbemClassObject *pWbemClassObjectResult = NULL;
	ULONG   ulResultCount = 0;
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
		hr = pWmi->pEnumerator->lpVtbl->Next(pWmi->pEnumerator, WBEM_INFINITE, 1, &pWbemClassObjectResult, &ulResultCount); //Scanbuild false positive
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

// Get a list of all the properties returned from the query
// Then call the normal ParseResults using all the returned 
// properties as the keys/columns
HRESULT Wmi_ParseAllResults(
	WMI* pWmi,
	BSTR*** ppwszResults,
	LPDWORD pdwRowCount,
	LPDWORD pdwColumnCount
)
{
	HRESULT     hr = 0;
	IWbemClassObject *pWbemClassObjectResult = NULL;
	ULONG       ulResultCount = 0;
	LONG        lFlags = WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY;
	SAFEARRAY*  psaProperties = NULL;
	LONG        lLBound = 0;
	LONG        lUBound = 0;
	size_t      ullKeysLength = 1;
	LPWSTR      pwszKeys = NULL;
	LONG        lKeyCount = 0;
	VARIANT     varProperty;

	pwszKeys = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ullKeysLength*sizeof(wchar_t));
	if (NULL == pwszKeys)
	{
		hr = WBEM_E_OUT_OF_MEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx", hr);
		goto fail;
	}
	
    // Get the first result in our enumeration of results
	hr = pWmi->pEnumerator->lpVtbl->Next(pWmi->pEnumerator, WBEM_INFINITE, 1, &pWbemClassObjectResult, &ulResultCount);
	if (FAILED(hr))
	{
	    BeaconPrintf(CALLBACK_ERROR, "pEnumerator->Next failed: 0x%08lx", hr);
		goto fail;
	}
	else if (ulResultCount == 0 || pWbemClassObjectResult == NULL)
	{
	    BeaconPrintf(CALLBACK_ERROR, "No results");
	    goto fail;
	}
		
			
	// Get a list of all the properties in the object
	hr = pWbemClassObjectResult->lpVtbl->GetNames(pWbemClassObjectResult, NULL, lFlags, NULL, &psaProperties );
	if ( FAILED(hr) )
	{
	    BeaconPrintf(CALLBACK_ERROR, "pWbemClassObjectResult->GetNames failed: 0x%08lx", hr);
		goto fail;
	}
	hr = OLEAUT32$SafeArrayGetLBound(psaProperties, 1, &lLBound);
    if ( FAILED(hr) )
    {
	    BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayGetLBound failed: 0x%08lx", hr);
		goto fail;
	}
	hr = OLEAUT32$SafeArrayGetUBound(psaProperties, 1, &lUBound);
    if ( FAILED(hr) )
    {
	    BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayGetUBound failed: 0x%08lx", hr);
		goto fail;
	}
	
	// Iterate through all the properties and create a CSV key list
	for (LONG lIndex = lLBound; lIndex <= lUBound; ++lIndex )
    {
        LPWSTR pwszCurrentName = NULL;
        hr = OLEAUT32$SafeArrayGetElement(psaProperties, &lIndex, &pwszCurrentName);
        if ( FAILED(hr) )
        {
	        BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayGetElement(%ld) failed: 0x%08lx", lIndex, hr);
		    goto fail;
	    }
	    
	    OLEAUT32$VariantInit(&varProperty);

		// Get the corresponding property for the current property name
		hr = pWbemClassObjectResult->lpVtbl->Get(pWbemClassObjectResult, pwszCurrentName, 0, &varProperty, 0, 0);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "pWbemClassObjectResult->lpVtbl->Get failed: 0x%08lx", hr);
			//goto fail;
			continue;
		}

        // Check the type of property because we aren't interested in references
		if (VT_BYREF & varProperty.vt)
		{
			BeaconPrintf(CALLBACK_OUTPUT, "%S is a reference, so skip", pwszCurrentName);
		}
		else
		{
            ullKeysLength = ullKeysLength + MSVCRT$wcslen( pwszCurrentName ) + 1;
            pwszKeys = (LPWSTR)KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, pwszKeys, sizeof(wchar_t)*ullKeysLength);
            if (NULL == pwszKeys)
	        {
		        hr = WBEM_E_OUT_OF_MEMORY;
		        BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapReAlloc failed: 0x%08lx", hr);
		        OLEAUT32$VariantClear(&varProperty);
		        goto fail;
	        }
	        // If this isn't the first column, prepend a comma
	        if ( 0 != lKeyCount )
	        {
	            pwszKeys = MSVCRT$wcscat(pwszKeys, L",");
	        }
            pwszKeys = MSVCRT$wcscat(pwszKeys, pwszCurrentName);
            
            lKeyCount++;
        }
        
        OLEAUT32$VariantClear(&varProperty);
	}
	
	// Release the current result
	pWbemClassObjectResult->lpVtbl->Release(pWbemClassObjectResult);
	
	// Reset the enumeration
	hr = pWmi->pEnumerator->lpVtbl->Reset(pWmi->pEnumerator);
	if ( FAILED(hr) )
	{
	    BeaconPrintf(CALLBACK_ERROR, "Reset failed: 0x%08lx", hr);
		goto fail;
	}
	
	// Get the results for all the properties using the newly create key list
	hr = Wmi_ParseResults( pWmi, pwszKeys, ppwszResults, pdwRowCount, pdwColumnCount );
	
fail:

	if (pwszKeys)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pwszKeys);
		pwszKeys = NULL;
	}
	
    SAFE_DESTROY(psaProperties);

	return hr;
}

void Wmi_Finalize(
	WMI* pWmi
)
{
	SAFE_RELEASE(pWmi->pWbemServices);
	SAFE_RELEASE(pWmi->pWbemLocator);

	SAFE_FREE(pWmi->bstrLanguage);
	SAFE_FREE(pWmi->bstrServer);
	SAFE_FREE(pWmi->bstrNameSpace);
	SAFE_FREE(pWmi->bstrNetworkResource);
	SAFE_FREE(pWmi->bstrQuery);

	// un-initialize the COM library
	OLE32$CoUninitialize();

	return;
}
