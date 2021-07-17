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
#include "adcs_enum_cas.h"

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


HRESULT _adcs_get_PolicyServerListManager()
{
	HRESULT hr = S_OK;
	IX509PolicyServerListManager * pPolicyServerListManager = NULL;
	LONG lPolicyServerUrlCount = 0;
	IX509PolicyServerUrl * pPolicyServerUrl = NULL;
		
	//{91f39029-217f-11da-b2a4-000e7bbb2b09}
	CLSID	CLSID_IX509PolicyServerListManager = { 0x91f39029, 0x217f, 0x11DA, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	//{884e204b-217d-11da-b2a4-000e7bbb2b09}
	IID		IID_IX509PolicyServerListManager = { 0x884e204b, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	SAFE_RELEASE(pPolicyServerListManager);
	//internal_printf( "OLE32$CoCreateInstance(CLSID_IX509PolicyServerListManager, IID_IX509PolicyServerListManager)\n");
	hr = OLE32$CoCreateInstance(
		&CLSID_IX509PolicyServerListManager,
		0,
		CLSCTX_INPROC_SERVER,
		&IID_IX509PolicyServerListManager,
		(LPVOID *)&(pPolicyServerListManager)
		
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance(CLSID_IX509PolicyServerListManager, IID_IX509PolicyServerListManager) failed: 0x%08lx\n", hr);
		goto PolicyServerListManager_fail;
	}

	//internal_printf( "pPolicyServerListManager->lpVtbl->Initialize(ContextUser, PsfLocationGroupPolicy | PsfLocationRegistry)\n");
	hr = pPolicyServerListManager->lpVtbl->Initialize(
		pPolicyServerListManager,
		ContextUser,
		PsfLocationGroupPolicy | PsfLocationRegistry
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "Initialize(ContextUser, PsfLocationGroupPolicy | PsfLocationRegistry) failed: 0x%08lx\n", hr);
		goto PolicyServerListManager_fail;
	}

	//internal_printf( "pPolicyServerListManager->lpVtbl->get_Count()\n");
	hr = pPolicyServerListManager->lpVtbl->get_Count(
		pPolicyServerListManager,
		&lPolicyServerUrlCount
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "get_Count() failed: 0x%08lx\n", hr);
		goto PolicyServerListManager_fail;
	}
		

	internal_printf( "Found %ld policy servers\n", lPolicyServerUrlCount);
	for(LONG lPolicyServerIndex=0; lPolicyServerIndex<lPolicyServerUrlCount; lPolicyServerIndex++)
	{
		SAFE_RELEASE(pPolicyServerUrl);
		//internal_printf( "pPolicyServerListManager->lpVtbl->get_ItemByIndex()\n");
		hr = pPolicyServerListManager->lpVtbl->get_ItemByIndex(
			pPolicyServerListManager,
			lPolicyServerIndex,
			&pPolicyServerUrl
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "get_ItemByIndex() failed: 0x%08lx\n", hr);
			goto PolicyServerListManager_fail;
		}

		hr = _adcs_get_PolicyServerUrl(pPolicyServerUrl);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "_adcs_get_PolicyServerUrl(pPolicyServerUrl) failed: 0x%08lx\n", hr);
			goto PolicyServerListManager_fail;
		}

	} // end for loop through IX509PolicyServerUrl

	hr = S_OK;

PolicyServerListManager_fail:

	SAFE_RELEASE(pPolicyServerUrl);
	SAFE_RELEASE(pPolicyServerListManager);

	return hr;
}


HRESULT _adcs_get_PolicyServerUrl(IX509PolicyServerUrl * pPolicyServerUrl)
{
	HRESULT hr = S_OK;
	BSTR bstrPolicyServerUrl = NULL;
	BSTR bstrPolicyServerFriendlyName = NULL;
	BSTR bstrPolicyServerId = NULL;

	//internal_printf( "pPolicyServerUrl->lpVtbl->get_Url()\n");
	hr = pPolicyServerUrl->lpVtbl->get_Url(
		pPolicyServerUrl,
		&bstrPolicyServerUrl
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "get_Url() failed: 0x%08lx\n", hr);
		goto PolicyServerUrl_fail;
	}
	//internal_printf( "bstrPolicyServerUrl: %S\n", bstrPolicyServerUrl);

	//internal_printf( "pPolicyServerUrl->lpVtbl->GetStringProperty(PsPolicyID)\n");
	hr = pPolicyServerUrl->lpVtbl->GetStringProperty(
		pPolicyServerUrl,
		PsPolicyID,
		&bstrPolicyServerId
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "GetStringProperty(PsPolicyID) failed: 0x%08lx\n", hr);
		goto PolicyServerUrl_fail;
	}
	//internal_printf( "bstrPolicyServerId: %S\n", bstrPolicyServerId);vvvv

	//internal_printf( "pPolicyServerUrl->lpVtbl->GetStringProperty(PsFriendlyName)\n");
	hr = pPolicyServerUrl->lpVtbl->GetStringProperty(
		pPolicyServerUrl,
		PsFriendlyName,
		&bstrPolicyServerFriendlyName
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "GetStringProperty(PsFriendlyName) failed: 0x%08lx\n", hr);
		goto PolicyServerUrl_fail;
	}
	//internal_printf( "bstrPolicyServerFriendlyName: %S\n", bstrPolicyServerFriendlyName);
	internal_printf( "Enumerating enrollment policy servers for %S...\n", bstrPolicyServerFriendlyName);

	hr = _adcs_get_EnrollmentPolicyServer(bstrPolicyServerUrl, bstrPolicyServerId);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_EnrollmentPolicyServer(bstrPolicyServerUrl, bstrPolicyServerId) failed: 0x%08lx\n", hr);
		goto PolicyServerUrl_fail;
	}

	hr = S_OK;

PolicyServerUrl_fail:

	SAFE_FREE(bstrPolicyServerUrl);
	SAFE_FREE(bstrPolicyServerFriendlyName);
	SAFE_FREE(bstrPolicyServerId);

	return hr;
}


HRESULT _adcs_get_EnrollmentPolicyServer(BSTR bstrPolicyServerUrl, BSTR bstrPolicyServerId)
{
	HRESULT hr = S_OK;
	IX509EnrollmentPolicyServer * pEnrollmentPolicyServer = NULL;
	ICertificationAuthorities * pCAs = NULL;
	LONG lCAsCount = 0;
	ICertificationAuthority * pCertificateAuthority = NULL;

	//{91f39027-217f-11da-b2a4-000e7bbb2b09}
	CLSID	CLSID_CX509EnrollmentPolicyActiveDirectory = { 0x91f39027, 0x217f, 0x11DA, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	//{13b79026-2181-11da-b2a4-000e7bbb2b09}
	IID		IID_IX509EnrollmentPolicyServer = { 0x13b79026, 0x2181, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	SAFE_RELEASE(pEnrollmentPolicyServer);
	//internal_printf( "CoCreateInstance(CLSID_CX509EnrollmentPolicyActiveDirectory, IID_IX509EnrollmentPolicyServer)\n");
	hr = OLE32$CoCreateInstance(
		&CLSID_CX509EnrollmentPolicyActiveDirectory,
		0,
		CLSCTX_INPROC_SERVER,
		&IID_IX509EnrollmentPolicyServer,
		(LPVOID *)&(pEnrollmentPolicyServer)
		
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoCreateInstance(CLSID_CX509EnrollmentPolicyActiveDirectory, IID_IX509EnrollmentPolicyServer) failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}

	//internal_printf( "pEnrollmentPolicyServer->Initialize(bstrPolicyServerUrl, bstrPolicyServerId, X509AuthKerberos, TRUE, ContextUser)\n");
	hr = pEnrollmentPolicyServer->lpVtbl->Initialize(
		pEnrollmentPolicyServer,
		bstrPolicyServerUrl,
		bstrPolicyServerId,
		X509AuthKerberos,
		TRUE,
		ContextUser
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pEnrollmentPolicyServer->Initialize(bstrPolicyServerUrl, bstrPolicyServerId, X509AuthKerberos, TRUE, ContextUser) failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}

	//internal_printf( "pEnrollmentPolicyServer->lpVtbl->LoadPolicy(LoadOptionReload)\n");
	hr = pEnrollmentPolicyServer->lpVtbl->LoadPolicy(
		pEnrollmentPolicyServer,
		LoadOptionReload
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pEnrollmentPolicyServer->lpVtbl->LoadPolicy(LoadOptionReload) failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}

	SAFE_RELEASE(pCAs);
	//internal_printf( "GetCAs()\n");
	hr = pEnrollmentPolicyServer->lpVtbl->GetCAs(
		pEnrollmentPolicyServer,
		&pCAs
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "GetCAs() failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}

	//internal_printf( "pCAs->lpVtbl->get_Count()\n");
	hr = pCAs->lpVtbl->get_Count(
		pCAs,
		&lCAsCount
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCAs->lpVtbl->get_Count() failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}
	//internal_printf( "lCAsCount: %ld\n", lCAsCount);
	internal_printf( "Found %ld CAs\n", lCAsCount);

	for(LONG lCAsIndex=0; lCAsIndex<lCAsCount; lCAsIndex++)
	{
		SAFE_RELEASE(pCertificateAuthority);
		//internal_printf( "pCAs->lpVtbl->get_ItemByIndex()\n");
		hr = pCAs->lpVtbl->get_ItemByIndex(
			pCAs,
			lCAsIndex,
			&pCertificateAuthority
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "pCAs->lpVtbl->get_ItemByIndex() failed: 0x%08lx\n", hr);
			goto EnrollmentPolicyServer_fail;
		}

		hr = _adcs_get_CertificationAuthority(pCertificateAuthority);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "_adcs_get_CertificationAuthority(pCertificateAuthority) failed: 0x%08lx\n", hr);
			goto EnrollmentPolicyServer_fail;
		}
	} // end for loop through ICertificationAuthority

	hr = S_OK;

EnrollmentPolicyServer_fail:

	SAFE_RELEASE(pCertificateAuthority);
	SAFE_RELEASE(pCAs);
	SAFE_RELEASE(pEnrollmentPolicyServer);

	return hr;
}


HRESULT _adcs_get_CertificationAuthority(ICertificationAuthority * pCertificateAuthority)
{
	HRESULT hr = S_OK;
	VARIANT varProperty;
	

	OLEAUT32$VariantInit(&varProperty);

	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropCommonName)\n");
	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropCommonName,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropCommonName) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	//internal_printf( "CAPropCommonName: %S\n", varProperty.bstrVal);
	internal_printf( "Enterprise CA Name: %S\n", varProperty.bstrVal);

	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropDNSName)\n");
	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropDNSName,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropDNSName) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	//internal_printf( "CAPropDNSName: %S\n", varProperty.bstrVal);
	internal_printf( "DNS Hostname: %S\n", varProperty.bstrVal);

	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropDistinguishedName)\n");
	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropDistinguishedName,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropDistinguishedName) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	if (varProperty.pdispVal)
	{
		BSTR bstrName = NULL;
		IX500DistinguishedName * pDistinguishedName = (IX500DistinguishedName*)varProperty.pdispVal;
		hr = pDistinguishedName->lpVtbl->get_Name(pDistinguishedName, &bstrName);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "pDistinguishedName->lpVtbl->get_Name(pDistinguishedName, &bstrName) failed: 0x%08lx\n", hr);
			goto CertificationAuthority_fail;
		}
		internal_printf( "Distinguished Name: %S\n", bstrName);
	}

	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropCertificate)\n");
	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropCertificate,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropCertificate) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	internal_printf( "Certificate:\n");
	hr = _adcs_get_Certificate(&varProperty);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_Certificate(&varProperty) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	
	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropWebServers)\n");
	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropWebServers,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropWebServers) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	internal_printf( "Web Servers:\n");
	hr = _adcs_get_WebServers(&varProperty);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_WebServers(&varProperty) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}


	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropCertificateTypes)\n");
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropCertificateTypes,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropCertificateTypes) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	internal_printf( "Templates:\n");
	hr = _adcs_get_CertificateTypes(&varProperty);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_CertificateTypes(&varProperty) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}


	//internal_printf( "pCertificateAuthority->lpVtbl->get_Property(CAPropSecurity)\n");
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateAuthority->lpVtbl->get_Property(
		pCertificateAuthority,
		CAPropSecurity,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateAuthority->lpVtbl->get_Property(CAPropSecurity) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	internal_printf( "Permissions:\n");
	hr = _adcs_get_Security(varProperty.bstrVal);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_Security(varProperty.bstrVal) failed: 0x%08lx\n", hr);
		goto CertificationAuthority_fail;
	}
	
	hr = S_OK;

CertificationAuthority_fail:

	OLEAUT32$VariantClear(&varProperty);

	return hr;
}


HRESULT _adcs_get_Certificate(VARIANT* lpvarCertifcate)
{
	HRESULT hr = S_OK;
	LPBYTE lpCertificate = NULL;
	ULONG ulCertificateSize = 0;

		

	if (lpvarCertifcate->parray)
	{
		ulCertificateSize = lpvarCertifcate->parray->rgsabound->cElements-1;
		internal_printf( "ulCertificateSize: %lu\n", ulCertificateSize);

		hr = OLEAUT32$SafeArrayAccessData( lpvarCertifcate->parray, (void**)(&lpCertificate) );
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayAccessData( lpvarCertifcate->parray, &lpvarCertifcate ) failed: 0x%08lx\n", hr);
			goto Certificate_fail;
		}

		internal_printf( "lpCertificate: %p\n", lpCertificate);
		for(ULONG i=0; i<ulCertificateSize; i++)
		{
			internal_printf( "%02x ", lpCertificate[i]);
			if(39==i%40)
				internal_printf("\n");
		}


		hr = OLEAUT32$SafeArrayUnaccessData( lpvarCertifcate->parray );
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "OLEAUT32$SafeArrayUnaccessData( lpvarCertifcate->parray ) failed: 0x%08lx\n", hr);
			goto Certificate_fail;
		}
	}
	else
	{
		internal_printf( "  %S\n", STR_NOT_AVAILALBE);
	}

	hr = S_OK;

Certificate_fail:

	return hr;
}


HRESULT _adcs_get_WebServers(VARIANT* lpvarWebServers)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrWebServer = NULL;
	LPWSTR swzTokenize = NULL;

	if (lpvarWebServers->parray)
	{
		hr = OLEAUT32$SafeArrayGetElement(lpvarWebServers->parray, &lItemIdx, &bstrWebServer);
		while(SUCCEEDED(hr))
		{
			ULONG dwWebServerCount = 0;
			LPWSTR swzToken = NULL;
			LPWSTR swzNextToken = NULL;
			UINT dwTokenizeLength = OLEAUT32$SysStringLen(bstrWebServer);
			swzTokenize = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR)*(dwTokenizeLength+1));
			if (NULL == swzTokenize)
			{
				hr = E_OUTOFMEMORY;
				BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed: 0x%08lx\n", hr);
				goto WebServers_fail;
			}
			MSVCRT$wcscpy(swzTokenize, bstrWebServer);

			// Get the number of entries in the array
			swzToken = MSVCRT$wcstok_s(swzTokenize, L"\n", &swzNextToken);
			dwWebServerCount = MSVCRT$wcstoul(swzToken, NULL, 10);
			for(ULONG ulWebEnrollmentServerIndex=0; ulWebEnrollmentServerIndex<dwWebServerCount; ulWebEnrollmentServerIndex++)
			{
				// Get the authentication type
				swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
				if (NULL == swzToken) {	break; }
				// Get the Priority
				swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
				if (NULL == swzToken) {	break; }
				// Get the Uri
				swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
				if (NULL == swzToken) {	break; }
				internal_printf( "  %S\n", swzToken);
				// Get the RenewalOnly flag
				swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
				if (NULL == swzToken) {	break; }
			}

			if(swzTokenize)
			{
				KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, swzTokenize);
				swzTokenize = NULL;
			}

			++lItemIdx;
			hr = OLEAUT32$SafeArrayGetElement(lpvarWebServers->parray, &lItemIdx, &bstrWebServer);	
		}
		//SAFE_FREE(bstrWebServer);
	}
	else
	{
		internal_printf( "  %S\n", STR_NOT_AVAILALBE);
	}

	hr = S_OK;

WebServers_fail:

	//SAFE_FREE(bstrWebServer);

	if(swzTokenize)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, swzTokenize);
		swzTokenize = NULL;
	}

	return hr;
}


HRESULT _adcs_get_Security(BSTR bstrDacl)
{
	HRESULT hr = S_OK;

	PISECURITY_DESCRIPTOR_RELATIVE pSecurityDescriptor = NULL;
	ULONG ulSecurityDescriptorSize = 0;
	LPWSTR swzStringSid = NULL;
	WCHAR swzName[MAX_PATH];
	DWORD cchName = MAX_PATH;
	WCHAR swzDomainName[MAX_PATH];
	DWORD cchDomainName = MAX_PATH;
	WCHAR swzFullName[MAX_PATH*2];
	DWORD cchFullName = MAX_PATH*2;
	SID_NAME_USE sidNameUse;

	if (bstrDacl)
	{
		internal_printf( "  %S\n", bstrDacl);

		if (FALSE == ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(
			bstrDacl, 
			SDDL_REVISION_1, 
			(PSECURITY_DESCRIPTOR)(&pSecurityDescriptor), 
			&ulSecurityDescriptorSize
			)
		)
		{
			hr = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW() failed: 0x%08lx\n", hr);
			goto Security_fail;
		}

		if (FALSE == ADVAPI32$ConvertSidToStringSidW(
			(PSID)((LPBYTE)pSecurityDescriptor + pSecurityDescriptor->Owner),
			&swzStringSid
		)
		)
		{
			hr = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$ConvertSidToStringSidW() failed: 0x%08lx\n", hr);
			goto Security_fail;
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
			hr = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$LookupAccountSidW() failed: 0x%08lx\n", hr);
			goto Security_fail;;
		}

		internal_printf( "  Owner: %S\\%S (%S)\n", swzDomainName, swzName, swzStringSid);

		if (swzStringSid)
		{
			KERNEL32$LocalFree(swzStringSid);
			swzStringSid = NULL;
		}
	}
	else
	{
		internal_printf( "  %S\n", STR_NOT_AVAILALBE);
	}

	hr = S_OK;

Security_fail:

	if (swzStringSid)
	{
		KERNEL32$LocalFree(swzStringSid);
		swzStringSid = NULL;
	}

	if (pSecurityDescriptor)
	{
		KERNEL32$LocalFree(pSecurityDescriptor);
		pSecurityDescriptor = NULL;
	}

	return hr;
}


HRESULT _adcs_get_CertificateTypes(VARIANT* lpvarArray)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrItem = NULL;

	if (lpvarArray->parray)
	{
		hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);
		while(SUCCEEDED(hr))
		{
			if (bstrItem)
			{
				internal_printf( "  %S\n", bstrItem);	
			}
			else
			{
				internal_printf( "  %S\n", STR_NOT_AVAILALBE);	
			}
			

			++lItemIdx;
			hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);	
		}
		//SAFE_FREE(bstrItem);
	}
	else
	{
		internal_printf( "  %S\n", STR_NOT_AVAILALBE);
	}

	hr = S_OK;

CertificateTypes_fail:

	//SAFE_FREE(bstrItem);

	return hr;
}



HRESULT _adcs_get_VT_ARRAY_BSTR(VARIANT* lpvarArray)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrItem = NULL;

	if (lpvarArray->parray)
	{
		hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);
		while(SUCCEEDED(hr))
		{
			if (bstrItem)
			{
				internal_printf( "%S\n", bstrItem);	
			}
			else
			{
				internal_printf( "%S\n", STR_NOT_AVAILALBE);	
			}
			

			++lItemIdx;
			hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);	
		}
		//SAFE_FREE(bstrItem);
	}
	else
	{
		internal_printf( "*ARRAY is EMPTY*\n");
	}

	hr = S_OK;

VT_ARRAY_BSTR_fail:

	//SAFE_FREE(bstrItem);

	return hr;
}




HRESULT adcs_enum_cas()
{
	HRESULT hr = S_OK;

	hr = OLE32$CoInitializeEx(
		NULL, 
		COINIT_APARTMENTTHREADED
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "OLE32$CoInitializeEx failed: 0x%08lx\n", hr);
		goto enum_fail;
	}
	
	hr = _adcs_get_PolicyServerListManager();
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_PolicyServerListManager() failed: 0x%08lx\n", hr);
		goto enum_fail;
	}

	hr = S_OK;
	
enum_fail:	
	
	OLE32$CoUninitialize();

	return hr;	
}
