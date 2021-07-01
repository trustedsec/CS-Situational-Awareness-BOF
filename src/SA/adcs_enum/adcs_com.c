#include <windows.h>
#include <stdio.h>
#include <oleauto.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <combaseapi.h>
#include "beacon.h"
#include "bofdefs.h"
#include "adcs_com.h"

#define STR_NOT_AVAILALBE L"N/A"

#define CERTCONFIG_FIELD_CONFIG L"Config"
#define CERTCONFIG_FIELD_WEBERNOLLMENTSERVERS L"WebEnrollmentServers"

#define PROPTYPE_INT 1
#define PROPTYPE_DATE 2
#define PROPTYPE_BINARY 3
#define PROPTYPE_STRING 4

#define STR_CATYPE_ENTERPRISE_ROOT L"Enterprise Root"
#define STR_CATYPE_ENTERPRISE_SUB L"Enterprise Sub"
#define STR_CATYPE_STANDALONE_ROOT L"Standalone Root"
#define STR_CATYPE_STANDALONE_SUB L"Standalone Sub"

#define STR_AUTHENTICATION_NONE L"None"
#define STR_AUTHENTICATION_ANONYMOUS L"Anonymous"
#define STR_AUTHENTICATION_KERBEROS L"Kerberos"
#define STR_AUTHENTICATION_USERNAMEANDPASSWORD L"UserNameAndPassword"
#define STR_AUTHENTICATION_CLIENTCERTIFICATE L"ClientCertificate"

#define STR_TRUE L"True"
#define STR_FALSE L"False"

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


HRESULT adcs_com_Initialize(ADCS* pADCS)
{
	HRESULT	hr = S_OK;

	pADCS->pConfig = NULL;
	pADCS->pRequest = NULL;	
	pADCS->ulCertificateServicesServerCount = 0;

	// Initialize COM parameters
	hr = OLE32$CoInitializeEx(
		NULL, 
		COINIT_APARTMENTTHREADED
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoInitializeEx failed: 0x%08lx\n", hr);
		goto fail;
	}

	hr = S_OK;

fail:

	return hr;
}

HRESULT adcs_com_Connect(
	ADCS* pADCS
)
{
	HRESULT hr = S_OK;

	CLSID	CLSID_CCertConfig = { 0x372fce38, 0x4324, 0x11D0, {0x88, 0x10, 0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C} };
	IID		IID_ICertConfig2 = { 0x7a18edde, 0x7e78, 0x4163, {0x8d, 0xed, 0x78, 0xe2, 0xc9, 0xce, 0xe9, 0x24} };

	//{98AFF3F0-5524-11D0-8812-00A0C903B83C}
	CLSID	CLSID_CCertRequest = { 0x98AFF3F0, 0x5524, 0x11D0, {0x88, 0x12, 0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C} };
	//{A4772988-4A85-4FA9-824E-B5CF5C16405A}
	IID		IID_ICertRequest2 = { 0xA4772988, 0x4A85, 0x4FA9, {0x82, 0x4E, 0xB5, 0xCF, 0x5C, 0x16, 0x40, 0x5A} };


	// Create an instance of the CertConfig class with the ICertConfig2 interface
	SAFE_RELEASE(pADCS->pConfig);
	hr = OLE32$CoCreateInstance(
		&CLSID_CCertConfig,
		0,
		CLSCTX_INPROC_SERVER,
		&IID_ICertConfig2,
		(LPVOID *)&(pADCS->pConfig)
		
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance(CLSID_CCertConfig,IID_ICertConfig2) failed: 0x%08lx\n", hr);
		OLE32$CoUninitialize();
		goto fail;
	}

	// Create an instance of the CertRequest class with the ICertRequest2 interface
	SAFE_RELEASE(pADCS->pRequest);
	hr = OLE32$CoCreateInstance(
		&CLSID_CCertRequest,
		0,
		CLSCTX_INPROC_SERVER,
		&IID_ICertRequest2,
		(LPVOID *)&(pADCS->pRequest)
		
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance(CLSID_CCertRequest,IID_ICertRequest2) failed: 0x%08lx\n", hr);
		OLE32$CoUninitialize();
		goto fail;
	}

	hr = S_OK;

fail:
	
	return hr;
}

HRESULT adcs_com_GetWebEnrollmentServers(
	ADCS* pADCS,
	ULONG ulCertificateServicesServerIndex
)
{
	HRESULT hr = S_OK;
	BSTR 	bstrCCFieldWebEnrollmentServers = NULL;
	BSTR 	bstrWebEnrollmentServers = NULL;
	LPWSTR	swzTokenize = NULL;
	UINT	dwTokenizeLength = 0;
	LPWSTR	swzToken = NULL;
	ULONG	dwTokenValue = 0;


	bstrCCFieldWebEnrollmentServers = OLEAUT32$SysAllocString(CERTCONFIG_FIELD_WEBERNOLLMENTSERVERS);

	hr = pADCS->pConfig->lpVtbl->GetField(
			pADCS->pConfig,
			bstrCCFieldWebEnrollmentServers,
			&(bstrWebEnrollmentServers)
	);
	if (FAILED(hr))
	{
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount = 0;
		hr = S_OK;
		goto fail;
	}

	// Parse the WebEnrollmentServer array
	dwTokenizeLength = OLEAUT32$SysStringLen(bstrWebEnrollmentServers);
	swzTokenize = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR)*(dwTokenizeLength+1));
	if (NULL == swzTokenize)
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}
	MSVCRT$wcscpy(swzTokenize, bstrWebEnrollmentServers);

	// Get the number of entries in the array
	swzToken = MSVCRT$wcstok(swzTokenize, L"\n");
	pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount = MSVCRT$wcstoul(swzToken, NULL, 10);
	//internal_printf( "ulWebEnrollmentServerCount: %lu\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount );
	pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers = (WebEnrollmentServer*)KERNEL32$HeapAlloc(
		KERNEL32$GetProcessHeap(), 
		HEAP_ZERO_MEMORY, 
		sizeof(WebEnrollmentServer)*(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount)
	);
	if (NULL == pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers)
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}

	// Loop through and parse the entries
	for(ULONG ulWebEnrollmentServerIndex=0; ulWebEnrollmentServerIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount; ulWebEnrollmentServerIndex++)
	{
		// Get the authentication type
		swzToken = MSVCRT$wcstok(NULL, L"\n");
		if (NULL == swzToken)
		{
			break;
		}
		if (swzToken[0] == L'1')
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication = OLEAUT32$SysAllocString(STR_AUTHENTICATION_ANONYMOUS);
		}
		else if (swzToken[0] == L'2')
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication = OLEAUT32$SysAllocString(STR_AUTHENTICATION_KERBEROS);
		}
		else if (swzToken[0] == L'4')
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication = OLEAUT32$SysAllocString(STR_AUTHENTICATION_USERNAMEANDPASSWORD);
		}
		else if (swzToken[0] == L'8')
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication = OLEAUT32$SysAllocString(STR_AUTHENTICATION_CLIENTCERTIFICATE);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication = OLEAUT32$SysAllocString(STR_AUTHENTICATION_NONE);
		}
		
		// Get the Priority
		swzToken = MSVCRT$wcstok(NULL, L"\n");
		if (NULL == swzToken)
		{
			break;
		}
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrPriority = OLEAUT32$SysAllocString(swzToken);

		// Get the Uri
		swzToken = MSVCRT$wcstok(NULL, L"\n");
		if (NULL == swzToken)
		{
			break;
		}
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrUri = OLEAUT32$SysAllocString(swzToken);

		// Get the RenewalOnly flag
		swzToken = MSVCRT$wcstok(NULL, L"\n");
		if (NULL == swzToken)
		{
			break;
		}
		if (swzToken[0] == L'0')
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrRenewalOnly = OLEAUT32$SysAllocString(STR_FALSE);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrRenewalOnly = OLEAUT32$SysAllocString(STR_TRUE);
		}
	}

fail:
	
	if(swzTokenize)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, swzTokenize);
		swzTokenize = NULL;
	}

	SAFE_FREE(bstrWebEnrollmentServers);
	SAFE_FREE(bstrCCFieldWebEnrollmentServers);

	return hr;
}

HRESULT adcs_com_GetTemplates(
	ADCS* pADCS,
	ULONG ulCertificateServicesServerIndex
)
{
	HRESULT hr = S_OK;
	BSTR 	bstrCCFieldWebEnrollmentServers = NULL;
	BSTR 	bstrWebEnrollmentServers = NULL;
	LPWSTR	swzTokenize = NULL;
	UINT	dwTokenizeLength = 0;
	LPWSTR	swzToken = NULL;
	ULONG	dwTokenValue = 0;
	VARIANT varProperty;

	OLEAUT32$VariantInit(&varProperty);


	// Retrieve the CR_PROP_TEMPLATES property
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName,
		CR_PROP_TEMPLATES,
		0,
		PROPTYPE_STRING,
		0,
		&varProperty
	);
	if (FAILED(hr))
	{
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount = 0;
		hr = S_OK;
		goto fail;
	}
	//internal_printf( "CR_PROP_TEMPLATES varProperty.bstrVal: %S\n", varProperty.bstrVal );
	dwTokenizeLength = OLEAUT32$SysStringLen(varProperty.bstrVal);
	swzTokenize = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR)*(dwTokenizeLength+1));
	if (NULL == swzTokenize)
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}
	MSVCRT$wcscpy(swzTokenize, varProperty.bstrVal);

	// Get the number of entries in the array
	swzToken = swzTokenize;
	for (dwTokenValue=0; swzToken[dwTokenValue]; swzToken[dwTokenValue]==L'\n' ? dwTokenValue++ : *swzToken++);
	pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount = dwTokenValue/2;
	//internal_printf( "ulTemplateCount: %lu\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount );
	pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates = (Template*)KERNEL32$HeapAlloc(
		KERNEL32$GetProcessHeap(), 
		HEAP_ZERO_MEMORY, 
		sizeof(Template)*(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount)
	);
	if (NULL == pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates)
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}

	swzToken = MSVCRT$wcstok(swzTokenize, L"\n");
	if (NULL == swzToken)
	{
		hr = TYPE_E_UNSUPFORMAT;
		BeaconPrintf(CALLBACK_ERROR, "Failed to parse templates string\n");
		goto fail;
	}
	

	// Loop through and parse the entries
	for(ULONG ulTemplateIndex=0; ulTemplateIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount; ulTemplateIndex++)
	{
		// Get the name
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrName = OLEAUT32$SysAllocString(swzToken);

		// Get the OID
		swzToken = MSVCRT$wcstok(NULL, L"\n");
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID = OLEAUT32$SysAllocString(swzToken);

		// Get the next Name
		swzToken = MSVCRT$wcstok(NULL, L"\n");
	}

fail:
	
	if(swzTokenize)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, swzTokenize);
		swzTokenize = NULL;
	}

	OLEAUT32$VariantClear(&varProperty);

	return hr;
}

HRESULT adcs_com_GetCertificateServicesServer(
	ADCS* pADCS,
	ULONG ulCertificateServicesServerIndex
)
{
	HRESULT hr = S_OK;
	VARIANT varProperty;

	OLEAUT32$VariantInit(&varProperty);

	// Retrieve the CR_PROP_DNSNAME property
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName,
		CR_PROP_DNSNAME,
		0,
		PROPTYPE_STRING,
		0,
		&varProperty
	);
	if (FAILED(hr))
	{
		//BeaconPrintf(CALLBACK_ERROR, "GetCAProperty(CR_PROP_DNSNAME) failed: 0x%08lx\n", hr);
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCADNSName = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
		//goto fail;
	}
	else
	{
		//internal_printf( "CR_PROP_DNSNAME varProperty.bstrVal: %S\n", varProperty.bstrVal );
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCADNSName = OLEAUT32$SysAllocString(varProperty.bstrVal);
	}

	OLEAUT32$VariantClear(&varProperty);

	// Retrieve the CR_PROP_SHAREDFOLDER property
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName,
		CR_PROP_SHAREDFOLDER,
		0,
		PROPTYPE_STRING,
		0,
		&varProperty
	);
	if (FAILED(hr))
	{
		//BeaconPrintf(CALLBACK_ERROR, "GetCAProperty(CR_PROP_SHAREDFOLDER) failed: 0x%08lx\n", hr);
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAShareFolder = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
		//goto fail;
	}
	else
	{
		//internal_printf( "CR_PROP_SHAREDFOLDER varProperty.bstrVal: %S\n", varProperty.bstrVal );
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAShareFolder = OLEAUT32$SysAllocString(varProperty.bstrVal);
	}

	// Retrieve the CR_PROP_CATYPE property
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName,
		CR_PROP_CATYPE,
		0,
		PROPTYPE_INT,
		0,
		&varProperty
	);
	if (FAILED(hr))
	{
		//BeaconPrintf(CALLBACK_ERROR, "GetCAProperty(CR_PROP_CATYPE) failed: 0x%08lx\n", hr);
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
		//goto fail;
	}
	else
	{
		//internal_printf( "CR_PROP_CATYPE varProperty.intVal: %d\n", varProperty.intVal );
		switch(varProperty.intVal)
		{
			case 0: //ENTERPRISE_ROOT
			{
				pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType = OLEAUT32$SysAllocString(STR_CATYPE_ENTERPRISE_ROOT);
				break;
			}
			case 1: //ENTERPRISE_SUB
			{
				pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType = OLEAUT32$SysAllocString(STR_CATYPE_ENTERPRISE_SUB);
				break;
			}
			case 2: //STANDALONE_ROOT
			{
				pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType = OLEAUT32$SysAllocString(STR_CATYPE_STANDALONE_ROOT);
				break;
			}
			case 3: //STANDALONE_SUB
			{
				pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType = OLEAUT32$SysAllocString(STR_CATYPE_STANDALONE_SUB);
				break;
			}
		}
	}
	
	// Attempt to retrieve the WebEnrollmentServers field for the current configuration
	//internal_printf( "Attempt to retrieve the Templates for the current configuration[%lu]\n", ulCertificateServicesServerIndex);
	hr = adcs_com_GetTemplates(pADCS, ulCertificateServicesServerIndex);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_GetTemplates failed: 0x%08lx\n", hr);
		goto fail;
	}
	
	hr = S_OK;

fail:
	
	OLEAUT32$VariantClear(&varProperty);

	return hr;
}


HRESULT adcs_com_GetCertificateServices(
	ADCS* pADCS
)
{
	HRESULT hr = S_OK;
	BSTR 	bstrCCFieldConfig = NULL;
	
	bstrCCFieldConfig = OLEAUT32$SysAllocString(CERTCONFIG_FIELD_CONFIG);

	// Retrieve the number of Certificate Services Servers in the enterprise
	//internal_printf( "Retrieve the number of Certificate Services Servers in the enterprise\n");
    hr = pADCS->pConfig->lpVtbl->Reset(
		pADCS->pConfig,
		0, 
		(LONG*)&(pADCS->ulCertificateServicesServerCount)
	);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "Reset failed: 0x%08lx\n", hr);
		goto fail;
    }
	//internal_printf( "ulCertificateServicesServerCount: %lu\n", pADCS->ulCertificateServicesServerCount );

	// Allocate space for the Certificate Services Servers results
	//internal_printf( "Allocate space for results\n");
	pADCS->lpCertificateServicesServers = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, pADCS->ulCertificateServicesServerCount*sizeof(CertificateServicesServer));
	if ( NULL == pADCS->lpCertificateServicesServers )
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}	

	// Loop through all the Certificate Services Servers in the enterprise
	//internal_printf( "Loop through all the Certificate Services Servers in the enterprise\n");
	for(ULONG ulCertificateServicesServerIndex = 0; ulCertificateServicesServerIndex < pADCS->ulCertificateServicesServerCount; ulCertificateServicesServerIndex++)
	{
		LONG lNextIndex = 0;
		
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName = NULL;

		// Retrieve the Config field for the current configuration
		//internal_printf( "Retrieve the Config field for the current configuration[%lu]\n", ulCertificateServicesServerIndex);
    	hr = pADCS->pConfig->lpVtbl->GetField(
			pADCS->pConfig,
			bstrCCFieldConfig, 
			&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName)
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "GetField(%S) failed: 0x%08lx\n", bstrCCFieldConfig, hr);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName);
			goto fail;
		}
		//internal_printf( "bstrConfigName: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName );
		
		// Attempt to retrieve the WebEnrollmentServers field for the current configuration
		//internal_printf( "Attempt to retrieve the WebEnrollmentServers field for the current configuration[%lu]\n", ulCertificateServicesServerIndex);
		hr = adcs_com_GetWebEnrollmentServers(pADCS, ulCertificateServicesServerIndex);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "adcs_com_GetWebEnrollmentServers failed: 0x%08lx\n", hr);
			goto fail;
		}

		// Attempt to retrieve the Certificate Authority information for the current configuration
		//internal_printf( "Attempt to retrieve the Certificate Authority information for the current configuration[%lu]\n", ulCertificateServicesServerIndex);
		hr = adcs_com_GetCertificateServicesServer(pADCS, ulCertificateServicesServerIndex);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "adcs_com_GetCertificateServicesServer failed: 0x%08lx\n", hr);
			goto fail;
		}

		// Retrieve the next available Certificate Services
		//internal_printf( "Retrieve the next available Certificate Services[%lu]\n", ulCertificateServicesServerIndex);
    	hr = pADCS->pConfig->lpVtbl->Next(
			pADCS->pConfig,
			&lNextIndex
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "Next failed: 0x%08lx\n", hr);
			goto fail;
		}

	} // end for loop through the configurations

	hr = S_OK;

fail:

	
	SAFE_FREE(bstrCCFieldConfig);

	return hr;
}


HRESULT adcs_com_PrintInfo(
	ADCS* pADCS
)
{
	HRESULT hr = S_OK;

	// Make sure we have results
	if ( ( NULL == pADCS->lpCertificateServicesServers ) || ( 0 == pADCS->ulCertificateServicesServerCount) )
	{
		BeaconPrintf(CALLBACK_ERROR, "No CAs to list");
		hr = ERROR_DS_NO_RESULTS_RETURNED;
		goto fail;
	}

	// Loop through all results
	internal_printf("Certificate Services Servers: (%lu)\n", pADCS->ulCertificateServicesServerCount);
	internal_printf("================================================================================\n");
	for( ULONG ulCertificateServicesServerIndex=0; ulCertificateServicesServerIndex<pADCS->ulCertificateServicesServerCount; ulCertificateServicesServerIndex++)
	{
		internal_printf(" Config Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName);
		internal_printf("  CA DNS Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCADNSName);
		internal_printf("  CA Type: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType);
		internal_printf("  CA Share Folder: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAShareFolder);
		internal_printf("  Web Enrollment Servers: (%lu)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount);
		if (0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount)
		{
			internal_printf("  ------------------------------------------------------------------------------\n");
			for( ULONG ulWebEnrollmentServerIndex = 0; ulWebEnrollmentServerIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount; ulWebEnrollmentServerIndex++)
			{
				internal_printf("   Uri: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrUri);
				internal_printf("   Authentication: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication);
				internal_printf("   Priority: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrPriority);
				internal_printf("   RenewalOnly: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrRenewalOnly);
				internal_printf("  ------------------------------------------------------------------------------\n");
			}
		}
		internal_printf("  Templates: (%lu)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount);
		if (0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount)
		{
			internal_printf("  ------------------------------------------------------------------------------\n");
			for( ULONG ulTemplateIndex = 0; ulTemplateIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount; ulTemplateIndex++)
			{
				internal_printf("   Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrName);
				internal_printf("   OID: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID);
				internal_printf("  ------------------------------------------------------------------------------\n");
			}
		}
		internal_printf("================================================================================\n");
	}

fail:

	return hr;
}

void adcs_com_Finalize(
	ADCS* pADCS
)
{
	SAFE_RELEASE(pADCS->pRequest);
	SAFE_RELEASE(pADCS->pConfig);

	if ( NULL != pADCS->lpCertificateServicesServers )
	{
		for( LONG ulCertificateServicesServerIndex=0; ulCertificateServicesServerIndex<pADCS->ulCertificateServicesServerCount; ulCertificateServicesServerIndex++)
		{
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrConfigName);
			for( ULONG ulWebEnrollmentServerIndex = 0; ulWebEnrollmentServerIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount; ulWebEnrollmentServerIndex++)
			{
				SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrUri);
				SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication);
				SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrPriority);
				SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrRenewalOnly);
			}
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCADNSName);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAShareFolder);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType);
			for( ULONG ulTemplateIndex = 0; ulTemplateIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount; ulTemplateIndex++)
			{
				SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrName);
				SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID);
			}
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrTemplates);
		}
	}
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers);

	// un-initialize the COM library
	OLE32$CoUninitialize();

	return;
}
