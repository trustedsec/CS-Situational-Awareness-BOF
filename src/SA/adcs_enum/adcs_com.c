#include <windows.h>
#include <stdio.h>
#include <oleauto.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <combaseapi.h>
#include <sddl.h>
#include <iads.h>
#include "beacon.h"
#include "bofdefs.h"
#include "adcs_com.h"

#define DEFINE_MY_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }

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


DEFINE_MY_GUID(CertificateEnrollment,0x0e10c968,0x78fb,0x11d2,0x90,0xd4,0x00,0xc0,0x4f,0x79,0xdc,0x55);
DEFINE_MY_GUID(CertificateAutoEnrollment,0xa05b8cc2,0x17bc,0x4802,0xa7,0x10,0xe7,0xc1,0x5a,0xb8,0x66,0xa2);
DEFINE_MY_GUID(CertificateAll,0x00000000,0x0000,0x0000,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);



HRESULT adcs_com_Initialize(
	ADCS* pADCS
)
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
		
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName = NULL;

		// Retrieve the Config field for the current configuration
		//internal_printf( "Retrieve the Config field for the current configuration[%lu]\n", ulCertificateServicesServerIndex);
    	hr = pADCS->pConfig->lpVtbl->GetField(
			pADCS->pConfig,
			bstrCCFieldConfig, 
			&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName)
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "GetField(%S) failed: 0x%08lx\n", bstrCCFieldConfig, hr);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName);
			goto fail;
		}
		//internal_printf( "bstrFullName: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName );

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


HRESULT adcs_com_GetCertificateServicesServer(
	ADCS* pADCS,
	ULONG ulCertificateServicesServerIndex
)
{
	HRESULT hr = S_OK;
	VARIANT varProperty;

	OLEAUT32$VariantInit(&varProperty);


	// Attempt to get the name
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName,
		CR_PROP_CANAME,
		0,
		PROPTYPE_STRING,
		0,
		&varProperty
	);
	if (FAILED(hr))
	{
		//BeaconPrintf(CALLBACK_ERROR, "GetCAProperty(CR_PROP_CANAME) failed: 0x%08lx\n", hr);
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAName = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
		//goto fail;
	}
	else
	{
		//internal_printf( "CR_PROP_DNSNAME varProperty.bstrVal: %S\n", varProperty.bstrVal );
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAName = OLEAUT32$SysAllocString(varProperty.bstrVal);
	}
	OLEAUT32$VariantClear(&varProperty);

	// Attempt to get the DNS name
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName,
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


	// Attempt to get the Type
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName,
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
	OLEAUT32$VariantClear(&varProperty);


	// Attempt to get the Shared Folder
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName,
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
	OLEAUT32$VariantClear(&varProperty);


	// Attempt to get the WebEnrollmentServers
	hr = adcs_com_GetWebEnrollmentServers(pADCS, ulCertificateServicesServerIndex);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_GetWebEnrollmentServers failed: 0x%08lx\n", hr);
		goto fail;
	}


	// Attempt to get the Templates
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
	LPWSTR	swzNextToken = NULL;
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
	swzToken = MSVCRT$wcstok_s(swzTokenize, L"\n", &swzNextToken);
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
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
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
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
		if (NULL == swzToken)
		{
			break;
		}
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrPriority = OLEAUT32$SysAllocString(swzToken);

		// Get the Uri
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
		if (NULL == swzToken)
		{
			break;
		}
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrUri = OLEAUT32$SysAllocString(swzToken);

		// Get the RenewalOnly flag
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
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
	LPWSTR	swzNextToken = NULL;
	ULONG	dwTokenValue = 0;
	VARIANT varProperty;
	IX509CertificateRequestPkcs7V2 * pPkcs = NULL;
	IX509CertificateTemplate * pTemplate = NULL;
	

	//{884E2044-217D-11DA-B2A4-000E7BBB2B09}
	CLSID	CLSID_CX509CertificateRequestPkcs7 = { 0x884E2044, 0x217D, 0x11DA, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	//{728ab35c-217d-11da-b2a4-000e7bbb2b09}
	IID		IID_IX509CertificateRequestPkcs7V2 = { 0x728ab35c, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };



	OLEAUT32$VariantInit(&varProperty);

	// Retrieve the CR_PROP_TEMPLATES property
	hr = pADCS->pRequest->lpVtbl->GetCAProperty(
		pADCS->pRequest,
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName,
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

	swzToken = MSVCRT$wcstok_s(swzTokenize, L"\n", &swzNextToken);
	if (NULL == swzToken)
	{
		hr = TYPE_E_UNSUPFORMAT;
		BeaconPrintf(CALLBACK_ERROR, "Failed to parse templates string\n");
		goto fail;
	}

	// Loop through and parse the Template entries
	for(ULONG ulTemplateIndex=0; ulTemplateIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount; ulTemplateIndex++)
	{
		// Get the name
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrName = OLEAUT32$SysAllocString(swzToken);

		// Get the OID
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
		pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID = OLEAUT32$SysAllocString(swzToken);

		// Get the next Name
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);

		// Create an instance of the X509CertificateRequestPkcs7 class with the IX509CertificateRequestPkcs7 interface
		SAFE_RELEASE(pPkcs);
		hr = OLE32$CoCreateInstance(
			&CLSID_CX509CertificateRequestPkcs7,
			0,
			CLSCTX_INPROC_SERVER,
			&IID_IX509CertificateRequestPkcs7V2,
			(LPVOID *)&(pPkcs)
			
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance(CLSID_CX509CertificateRequestPkcs7,IID_IX509CertificateRequestPkcs7V2) failed: 0x%08lx\n", hr);
			//goto fail;
			//hr = S_OK;
			continue;
		}

		// Initializes the certificate request by using the template name
		hr = pPkcs->lpVtbl->InitializeFromTemplateName(
			pPkcs,
			ContextUser,
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "InitializeFromTemplateName(%S) failed: 0x%08lx\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID, hr);
			//goto fail;
			//hr = S_OK;
			continue;
		}

		// Get the template
		SAFE_RELEASE(pTemplate);
		hr = pPkcs->lpVtbl->get_Template(
			pPkcs,
			&pTemplate
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_Template(%S) failed: 0x%08lx\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID, hr);
			//goto fail;
			//hr = S_OK;
			continue;
		}

		// Get the TemplatePropFriendlyName
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropFriendlyName,
			&varProperty
		);
		if (FAILED(hr))
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrFriendlyName = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrFriendlyName = OLEAUT32$SysAllocString(varProperty.bstrVal);
		}
		OLEAUT32$VariantClear(&varProperty);

		// Get the TemplatePropValidityPeriod
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropValidityPeriod,
			&varProperty
		);
		if (FAILED(hr))
		{
			//BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropValidityPeriod) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lValidityPeriod = varProperty.lVal;
		}
		OLEAUT32$VariantClear(&varProperty);

		// Get the TemplatePropRenewalPeriod
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropRenewalPeriod,
			&varProperty
		);
		if (FAILED(hr))
		{
			//BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropRenewalPeriod) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lRenewalPeriod = varProperty.lVal;
		}
		OLEAUT32$VariantClear(&varProperty);


		// Get the TemplatePropEnrollmentFlags
		// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplateenrollmentflag
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropEnrollmentFlags,
			&varProperty
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropEnrollmentFlags) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentFlags = varProperty.intVal;
		}
		OLEAUT32$VariantClear(&varProperty);

		// Get the TemplatePropSubjectNameFlags
		// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplatesubjectnameflag
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropSubjectNameFlags,
			&varProperty
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropSubjectNameFlags) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwSubjectNameFlags = varProperty.intVal;
		}
		OLEAUT32$VariantClear(&varProperty);

/*
		// Get the TemplatePropPrivateKeyFlags
		// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplateprivatekeyflag
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropPrivateKeyFlags,
			&varProperty
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropPrivateKeyFlags) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwPrivateKeyFlags = varProperty.intVal;
		}
		OLEAUT32$VariantClear(&varProperty);

		// Get the TemplatePropGeneralFlags
		// See https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/ne-certenroll-x509certificatetemplategeneralflag
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropGeneralFlags,
			&varProperty
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropGeneralFlags) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwGeneralFlags = varProperty.intVal;
		}
		OLEAUT32$VariantClear(&varProperty);
*/

		// Get the TemplatePropRASignatureCount
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropRASignatureCount,
			&varProperty
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropRASignatureCount) failed: 0x%08lx\n", hr);
		}
		else
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwSignatureCount = varProperty.intVal;
		}
		OLEAUT32$VariantClear(&varProperty);

		// Get the TemplatePropEKUs
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropEKUs,
			&varProperty
		);
		if (FAILED(hr))
		{
			//BeaconPrintf(CALLBACK_ERROR, "get_Property(TemplatePropEKUs) failed: 0x%08lx\n", hr);
		}
		else
		{
			if ( NULL == varProperty.pdispVal )
			{
				BeaconPrintf(CALLBACK_ERROR, "TemplatePropEKUs is NULL\n");
			}
			else // parse IObjectIds
			{
				IObjectIds * pObjectIds = NULL;
				IEnumVARIANT *pEnum = NULL;
				LPUNKNOWN pUnk = NULL;
				VARIANT var;
				IDispatch *pDisp = NULL;
				ULONG lFetch = 0;
				IObjectId * pObjectId = NULL;
				ULONG ulUsagesIndex = 0;

				IID IID_IEnumVARIANT = { 0x00020404, 0x0000, 0x0000, {0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46} };
				//728ab300-217d-11da-b2a4-000e7bbb2b09
				IID IID_IObjectId = { 0x728ab300, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

				pObjectIds = (IObjectIds*)varProperty.pdispVal;

				hr = pObjectIds->lpVtbl->get_Count(pObjectIds, &(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].ulUsagesCount));
				if (FAILED(hr))
				{
					BeaconPrintf(CALLBACK_ERROR, "get_Count failed: 0x%08lx\n", hr);
				}
				else // parse get_Count IObjectIds
				{
					pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages = (BSTR*)KERNEL32$HeapAlloc(
						KERNEL32$GetProcessHeap(), 
						HEAP_ZERO_MEMORY, 
						sizeof(BSTR)*(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].ulUsagesCount)
					);
					if (NULL == pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages)
					{
						hr = E_OUTOFMEMORY;
						BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
						goto fail;
					}

					pObjectIds->lpVtbl->get__NewEnum(pObjectIds, &pUnk);
					SAFE_RELEASE(pObjectIds);

					pUnk->lpVtbl->QueryInterface(pUnk, &IID_IEnumVARIANT, (void**) &pEnum);
					SAFE_RELEASE(pUnk);

					OLEAUT32$VariantInit(&var);
					hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &lFetch);
					while(SUCCEEDED(hr) && lFetch > 0)
					{
						if (lFetch == 1)
						{
							pDisp = V_DISPATCH(&var);
							pDisp->lpVtbl->QueryInterface(pDisp, &IID_IObjectId, (void**)&pObjectId); 
							SAFE_RELEASE(pDisp);

							hr = pObjectId->lpVtbl->get_FriendlyName(
								pObjectId, 
								&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages[ulUsagesIndex])
							);
							if (FAILED(hr))
							{
								BeaconPrintf(CALLBACK_ERROR, "get_FriendlyName failed: 0x%08lx\n", hr);
							}

							SAFE_RELEASE(pObjectId);
							ulUsagesIndex++;
						}

						OLEAUT32$VariantClear(&var);

						hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &lFetch);
					} // end loop through IObjectIds via enumerator
				} // end else parse get_Count IObjectIds
			}  // end else parse IObjectIds
		} // end else get the TemplatePropEKUs was successful
		OLEAUT32$VariantClear(&varProperty);

		// Get the TemplatePropSecurityDescriptor
		OLEAUT32$VariantClear(&varProperty);
		hr = pTemplate->lpVtbl->get_Property(
			pTemplate,
			TemplatePropSecurityDescriptor,
			&varProperty
		);
		if (FAILED(hr))
		{
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwnerSid = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
			pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwner = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
		}
		else
		{
			PISECURITY_DESCRIPTOR_RELATIVE pSecurityDescriptor = NULL;
			ULONG ulSecurityDescriptorSize = 0;

			if (FALSE == ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(
				varProperty.bstrVal, 
				SDDL_REVISION_1, 
				(PSECURITY_DESCRIPTOR)(&pSecurityDescriptor), 
				&ulSecurityDescriptorSize
				)
			)
			{
				pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwnerSid = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
				pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwner = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
			}
			else
			{
				LPWSTR swzStringSid = NULL;
				WCHAR swzName[MAX_PATH];
				DWORD cchName = MAX_PATH;
				WCHAR swzDomainName[MAX_PATH];
				DWORD cchDomainName = MAX_PATH;
				WCHAR swzFullName[MAX_PATH*2];
				DWORD cchFullName = MAX_PATH*2;
				SID_NAME_USE sidNameUse;

				if (FALSE == ADVAPI32$ConvertSidToStringSidW(
					(PSID)((LPBYTE)pSecurityDescriptor + pSecurityDescriptor->Owner),
					&swzStringSid
				)
				)
				{
					pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwnerSid = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
				}
				else
				{
					pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwnerSid = OLEAUT32$SysAllocString(swzStringSid);
				}
				if (swzStringSid)
				{
					KERNEL32$LocalFree(swzStringSid);
					swzStringSid = NULL;
				}

				cchName = MAX_PATH;
				MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == ADVAPI32$LookupAccountSidW(
						NULL,
						(PSID)((LPBYTE)pSecurityDescriptor + pSecurityDescriptor->Owner),
						swzName,
						&cchName,
						swzDomainName,
						&cchDomainName,
						&sidNameUse
					)
				)
				{
					pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwner = OLEAUT32$SysAllocString(STR_NOT_AVAILALBE);
				}
				else
				{
					cchFullName = MAX_PATH*2;
					MSVCRT$memset(swzFullName, 0, cchFullName*sizeof(WCHAR));	
					MSVCRT$_snwprintf(swzFullName, cchFullName, L"%s\\%s", swzDomainName, swzName);
					pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwner = OLEAUT32$SysAllocString(swzFullName);
				}

				// GetAclInformation(), GetAce()
				ACL_SIZE_INFORMATION aclSizeInformation;
				if ( ADVAPI32$GetAclInformation(
						(PACL)((LPBYTE)pSecurityDescriptor + pSecurityDescriptor->Dacl),
						&aclSizeInformation,
						sizeof(aclSizeInformation),
						AclSizeInformation
					)
				)
				{
					//internal_printf("AceCount: %lu\n", aclSizeInformation.AceCount);
					for(DWORD dwAceIndex=0; dwAceIndex<aclSizeInformation.AceCount; dwAceIndex++)
					{
						ACE_HEADER * pAceHeader = NULL;
						ACCESS_ALLOWED_ACE* pAce = NULL;
						ACCESS_ALLOWED_OBJECT_ACE* pAceObject = NULL;
						PSID pPrincipalSid = NULL;
						BSTR bstrName = NULL;
						BOOL bDeleteName = TRUE;
						hr = E_UNEXPECTED;

						if (ADVAPI32$GetAce(
								(PACL)((LPBYTE)pSecurityDescriptor + pSecurityDescriptor->Dacl),
								dwAceIndex,
								(LPVOID)&pAceHeader
							)
						)
						{
							pAceObject = (ACCESS_ALLOWED_OBJECT_ACE*)pAceHeader;
							pAce = (ACCESS_ALLOWED_ACE*)pAceHeader;

							if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType)
							{
								pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType));
							}
							else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType)
							{
								pPrincipalSid = (PSID)(&(pAce->SidStart));
							}
							else
							{
								continue;
							}

							cchName = MAX_PATH;
							MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
							cchDomainName = MAX_PATH;
							MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
							if (FALSE == ADVAPI32$LookupAccountSidW(
									NULL,
									pPrincipalSid,
									swzName,
									&cchName,
									swzDomainName,
									&cchDomainName,
									&sidNameUse
								)
							)
							{
								continue;
							}
								
							cchFullName = MAX_PATH*2;
							MSVCRT$memset(swzFullName, 0, cchFullName*sizeof(WCHAR));	
							MSVCRT$_snwprintf(swzFullName, cchFullName, L"%s\\%s", swzDomainName, swzName);
							bstrName = OLEAUT32$SysAllocString(swzFullName);
							if (NULL==bstrName)
							{
								continue;
							}

							if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask)
							{
								if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags)
								{
									if (
										IsEqualGUID(&CertificateEnrollment, &pAceObject->ObjectType) ||
										IsEqualGUID(&CertificateAutoEnrollment, &pAceObject->ObjectType) ||
										IsEqualGUID(&CertificateAll, &pAceObject->ObjectType)
										)
									{
										hr = _bstr_list_insert( 
											&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentPrincipalsCount),
											&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals),
											bstrName
										);
									}
								} // end if ACE_OBJECT_TYPE_PRESENT
							} // end if ADS_RIGHT_DS_CONTROL_ACCESS
							
							// Check if Enrollment permission
							if (ADS_RIGHT_GENERIC_ALL & pAceObject->Mask)
							{
								hr = _bstr_list_insert( 
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentPrincipalsCount),
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals),
									bstrName
								);
							} // end if Enrollment permission
							
							// Check if WriteOwner permission
							if ( 
								(ADS_RIGHT_GENERIC_ALL & pAceObject->Mask) ||
								(ADS_RIGHT_WRITE_OWNER & pAceObject->Mask)
							)
							{
								hr = _bstr_list_insert( 
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteOwnerPrincipalsCount),
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteOwnerPrincipals),
									bstrName
								);
							} // end if WriteOwner permission
							
							// Check if WriteDacl permission
							if ( 
								(ADS_RIGHT_GENERIC_ALL & pAceObject->Mask) ||
								(ADS_RIGHT_WRITE_DAC & pAceObject->Mask)
							)
							{
								hr = _bstr_list_insert( 
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteDaclPrinciaplsCount),
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteDaclPrincipals),
									bstrName
								);
							} // end if WriteDacl permission
							
							// Check if WriteProperty permission
							if ( 
								(ADS_RIGHT_GENERIC_ALL & pAceObject->Mask) ||
								(ADS_RIGHT_GENERIC_WRITE & pAceObject->Mask) ||
								(ADS_RIGHT_DS_WRITE_PROP & pAceObject->Mask)
							)
							{
								hr = _bstr_list_insert( 
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWritePropertyPrincipalsCount),
									&(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWritePropertyPrincipals),
									bstrName
								);
							} // end if WriteProperty permission
							
							if (FAILED(hr))
							{
								SAFE_FREE(bstrName);
							}
						} // end if GetAce was successful
					} // end for loop through ACEs (AceCount)
				} // end else GetAclInformation was successful
			} // end else ConvertStringSecurityDescriptorToSecurityDescriptorW was successful

			if (pSecurityDescriptor)
			{
				KERNEL32$LocalFree(pSecurityDescriptor);
				pSecurityDescriptor = NULL;
			}
		} // end else Get the TemplatePropSecurityDescriptor was successful
	} // end loop through and parse the Template entries

	hr = S_OK;

fail:
	
	if(swzTokenize)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, swzTokenize);
		swzTokenize = NULL;
	}

	OLEAUT32$VariantClear(&varProperty);

	SAFE_RELEASE(pTemplate);

	SAFE_RELEASE(pPkcs);

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
		BeaconPrintf(CALLBACK_ERROR, "No Certificate Services Servers to list");
		hr = ERROR_DS_NO_RESULTS_RETURNED;
		goto fail;
	}

	// Loop through all results
	internal_printf("Certificate Services Servers: (%lu)\n", pADCS->ulCertificateServicesServerCount);
	internal_printf("================================================================================\n");
	for( ULONG ulCertificateServicesServerIndex=0; ulCertificateServicesServerIndex<pADCS->ulCertificateServicesServerCount; ulCertificateServicesServerIndex++)
	{
		internal_printf("  Enterprise CA Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAName);
		internal_printf("  DNS Hostname: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCADNSName);
		internal_printf("  Full Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName);
		internal_printf("  CA Type: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType);
		internal_printf("  CA Share Folder: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAShareFolder);
		internal_printf("  Web Enrollment Servers: (%lu)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount);
		if ( 
			( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers ) &&
			(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount)
		)
		{ 
			internal_printf("  ------------------------------------------------------------------------------\n");
			for( ULONG ulWebEnrollmentServerIndex = 0; ulWebEnrollmentServerIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount; ulWebEnrollmentServerIndex++)
			{
				internal_printf("    Uri: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrUri);
				internal_printf("    Authentication: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication);
				internal_printf("    Priority: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrPriority);
				internal_printf("    RenewalOnly: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrRenewalOnly);
				internal_printf("  ------------------------------------------------------------------------------\n");
			}
		}
		internal_printf("  Templates: (%lu)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount);
		if ( 
			( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates ) &&
			(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount)
		)
		{
			internal_printf("  ------------------------------------------------------------------------------\n");
			for( ULONG ulTemplateIndex = 0; ulTemplateIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount; ulTemplateIndex++)
			{
				internal_printf("    Template Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrName);
				internal_printf("    Friendly Name: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrFriendlyName);
				internal_printf("    OID: %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID);
				internal_printf("    Validity Period: %ld years (%ld seconds)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lValidityPeriod/31536000, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lValidityPeriod);
				internal_printf("    Renewal Period: %ld days (%ld seconds)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lRenewalPeriod/86400, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lRenewalPeriod);
				internal_printf("    Certificate Name Flags: %08x\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwSubjectNameFlags);
				internal_printf("    Enrollment Flags: %08x\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentFlags);
				//internal_printf("    Private Key Flags: %08x\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwPrivateKeyFlags);
				//internal_printf("    General Flags: %08x\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwGeneralFlags);
				internal_printf("    Authorized Signatures Requred: %u\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwSignatureCount);
				internal_printf("    Extended Usage:\n");
				if ( 
					( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages ) &&
					(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].ulUsagesCount)
				)
				{
					for( ULONG ulUsageIndex = 0; ulUsageIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].ulUsagesCount; ulUsageIndex++)
					{
						internal_printf("      %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages[ulUsageIndex]);
					}
				}
				else
				{
					internal_printf("      %S\n", STR_NOT_AVAILALBE);
				}
				internal_printf("    Owner: %S (%S)\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwner, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwnerSid);
				internal_printf("    Enrollment Principals:\n");
				if ( 
					( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals ) &&
					(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentPrincipalsCount)
				)
				{
					for( ULONG dwEnrollmentPrincipalsIndex = 0; dwEnrollmentPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentPrincipalsCount; dwEnrollmentPrincipalsIndex++)
					{
						internal_printf("      %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals[dwEnrollmentPrincipalsIndex]);
					}
				}
				else
				{
					internal_printf("      %S\n", STR_NOT_AVAILALBE);
				}
				internal_printf("    WriteOwner Principals:\n");
				if ( 
					( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteOwnerPrincipals ) &&
					(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteOwnerPrincipalsCount)
				)
				{
					for( ULONG dwWriteOwnerPrincipalsIndex = 0; dwWriteOwnerPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteOwnerPrincipalsCount; dwWriteOwnerPrincipalsIndex++)
					{
						internal_printf("      %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteOwnerPrincipals[dwWriteOwnerPrincipalsIndex]);
					}
				}
				else
				{
					internal_printf("      %S\n", STR_NOT_AVAILALBE);
				}
				internal_printf("    WriteDacl Principals:\n");
				if ( 
					( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteDaclPrincipals ) &&
					(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteDaclPrinciaplsCount)
				)
				{
					for( ULONG dwWriteDaclPrincipalsIndex = 0; dwWriteDaclPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteDaclPrinciaplsCount; dwWriteDaclPrincipalsIndex++)
					{
						internal_printf("      %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteDaclPrincipals[dwWriteDaclPrincipalsIndex]);
					}
				}
				else
				{
					internal_printf("      %S\n", STR_NOT_AVAILALBE);
				}
				internal_printf("    WriteProperty Principals:\n");
				if ( 
					( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWritePropertyPrincipals ) &&
					(0 < pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWritePropertyPrincipalsCount)
				)
				{
					for( ULONG dwWritePropertyPrincipalsIndex = 0; dwWritePropertyPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWritePropertyPrincipalsCount; dwWritePropertyPrincipalsIndex++)
					{
						internal_printf("      %S\n", pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWritePropertyPrincipals[dwWritePropertyPrincipalsIndex]);
					}
				}
				else
				{
					internal_printf("      %S\n", STR_NOT_AVAILALBE);
				}

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
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrFullName);
			if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers )
			{
				for( ULONG ulWebEnrollmentServerIndex = 0; ulWebEnrollmentServerIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulWebEnrollmentServerCount; ulWebEnrollmentServerIndex++)
				{
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrUri);
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrAuthentication);
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrPriority);
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers[ulWebEnrollmentServerIndex].bstrRenewalOnly);
				}
				KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpWebEnrollmentServers);
			}
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCADNSName);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAShareFolder);
			SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].bstrCAType);
			if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates )
			{
				for( ULONG ulTemplateIndex = 0; ulTemplateIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].ulTemplateCount; ulTemplateIndex++)
				{
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOID);
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrName);
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrFriendlyName);
					if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages )
					{
						for( ULONG ulUsageIndex = 0; ulUsageIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].ulUsagesCount; ulUsageIndex++)
						{
							SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages[ulUsageIndex]);
						}
						KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrUsages);	
					}
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwner);
					SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].bstrOwnerSid);
					if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals )
					{
						for( ULONG dwEnrollmentPrincipalsIndex = 0; dwEnrollmentPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwEnrollmentPrincipalsCount; dwEnrollmentPrincipalsIndex++)
						{
							SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals[dwEnrollmentPrincipalsIndex]);
						}
						KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrEnrollmentPrincipals);	
					}
					if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteOwnerPrincipals )
					{
						for( ULONG dwWriteOwnerPrincipalsIndex = 0; dwWriteOwnerPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteOwnerPrincipalsCount; dwWriteOwnerPrincipalsIndex++)
						{
							SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteOwnerPrincipals[dwWriteOwnerPrincipalsIndex]);
						}
						KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteOwnerPrincipals);	
					}
					if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteDaclPrincipals )
					{
						for( ULONG dwWriteDaclPrincipalsIndex = 0; dwWriteDaclPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWriteDaclPrinciaplsCount; dwWriteDaclPrincipalsIndex++)
						{
							SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteDaclPrincipals[dwWriteDaclPrincipalsIndex]);
						}
						KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWriteDaclPrincipals);	
					}
					if ( NULL != pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWritePropertyPrincipals )
					{
						for( ULONG dwWritePropertyPrincipalsIndex = 0; dwWritePropertyPrincipalsIndex<pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].dwWritePropertyPrincipalsCount; dwWritePropertyPrincipalsIndex++)
						{
							SAFE_FREE(pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWritePropertyPrincipals[dwWritePropertyPrincipalsIndex]);
						}
						KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates[ulTemplateIndex].lpbstrWritePropertyPrincipals);	
					}
				}
				KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers[ulCertificateServicesServerIndex].lpTemplates);
			}
		}
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pADCS->lpCertificateServicesServers);
	}
	

	// un-initialize the COM library
	OLE32$CoUninitialize();

	return;
}
