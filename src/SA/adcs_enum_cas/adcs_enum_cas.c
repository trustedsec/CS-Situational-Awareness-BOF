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

#define CHECK_RETURN_FALSE( function, return_value, result) \
	if (FALSE == return_value) \
	{ \
		result = KERNEL32$GetLastError(); \
		BeaconPrintf(CALLBACK_ERROR, "%s failed: 0x%08lx\n", function, result); \
		goto fail; \
	}
#define CHECK_RETURN_NULL( function, return_value, result) \
	if (NULL == return_value) \
	{ \
		result = E_INVALIDARG; \
		BeaconPrintf(CALLBACK_ERROR, "%s failed\n", function); \
		goto fail; \
	}
#define CHECK_RETURN_FAIL( function, result ) \
	if (FAILED(result)) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "%s failed: 0x%08lx\n", function, result); \
		goto fail; \
	}
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
#define SAFE_LOCAL_FREE( local_ptr ) \
	if (local_ptr) \
	{ \
		KERNEL32$LocalFree(local_ptr); \
		local_ptr = NULL; \
	}
#define SAFE_INT_FREE( int_ptr ) \
	if (int_ptr) \
	{ \
		intFree(int_ptr); \
		int_ptr = NULL; \
	}
#define SAFE_CERTFREECERTIFICATECHAIN( cert_chain_context ) \
	if(cert_chain_context) \
	{ \
		CRYPT32$CertFreeCertificateChain(cert_chain_context); \
		cert_chain_context = NULL; \
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
		
	CLSID	CLSID_IX509PolicyServerListManager = { 0x91f39029, 0x217f, 0x11DA, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID		IID_IX509PolicyServerListManager = { 0x884e204b, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	SAFE_RELEASE(pPolicyServerListManager);
	hr = OLE32$CoCreateInstance(&CLSID_IX509PolicyServerListManager, 0,	CLSCTX_INPROC_SERVER, &IID_IX509PolicyServerListManager, (LPVOID *)&(pPolicyServerListManager));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_IX509PolicyServerListManager)", hr);

	hr = pPolicyServerListManager->lpVtbl->Initialize(pPolicyServerListManager, ContextUser, PsfLocationGroupPolicy | PsfLocationRegistry);
	CHECK_RETURN_FAIL("pPolicyServerListManager->lpVtbl->Initialize()", hr);

	hr = pPolicyServerListManager->lpVtbl->get_Count(pPolicyServerListManager, &lPolicyServerUrlCount);
	CHECK_RETURN_FAIL("pPolicyServerListManager->lpVtbl->get_Count()", hr);

	internal_printf("\n[*] Found %ld policy servers\n", lPolicyServerUrlCount);
	for(LONG lPolicyServerIndex=0; lPolicyServerIndex<lPolicyServerUrlCount; lPolicyServerIndex++)
	{
		SAFE_RELEASE(pPolicyServerUrl);
		hr = pPolicyServerListManager->lpVtbl->get_ItemByIndex(pPolicyServerListManager, lPolicyServerIndex, &pPolicyServerUrl);
		CHECK_RETURN_FAIL("pPolicyServerListManager->lpVtbl->get_ItemByIndex()", hr);

		hr = _adcs_get_PolicyServerUrl(pPolicyServerUrl);
		CHECK_RETURN_FAIL("_adcs_get_PolicyServerUrl()", hr);

	} // end for loop through IX509PolicyServerUrl

	hr = S_OK;

fail:

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

	hr = pPolicyServerUrl->lpVtbl->get_Url(pPolicyServerUrl, &bstrPolicyServerUrl);
	CHECK_RETURN_FAIL("pPolicyServerUrl->lpVtbl->get_Url()", hr);

	hr = pPolicyServerUrl->lpVtbl->GetStringProperty(pPolicyServerUrl, PsPolicyID, &bstrPolicyServerId);
	CHECK_RETURN_FAIL("pPolicyServerUrl->lpVtbl->GetStringProperty(PsPolicyID)", hr);

	hr = pPolicyServerUrl->lpVtbl->GetStringProperty(pPolicyServerUrl, PsFriendlyName, &bstrPolicyServerFriendlyName);
	CHECK_RETURN_FAIL("pPolicyServerUrl->lpVtbl->GetStringProperty(PsFriendlyName)", hr);
	internal_printf("\n[*] Enumerating enrollment policy servers for %S...\n", bstrPolicyServerFriendlyName);

	hr = _adcs_get_EnrollmentPolicyServer(bstrPolicyServerUrl, bstrPolicyServerId);
	CHECK_RETURN_FAIL("_adcs_get_EnrollmentPolicyServer()", hr);

	hr = S_OK;

fail:

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

	CLSID	CLSID_CX509EnrollmentPolicyActiveDirectory = { 0x91f39027, 0x217f, 0x11DA, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	IID		IID_IX509EnrollmentPolicyServer = { 0x13b79026, 0x2181, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	SAFE_RELEASE(pEnrollmentPolicyServer);
	hr = OLE32$CoCreateInstance( &CLSID_CX509EnrollmentPolicyActiveDirectory, 0, CLSCTX_INPROC_SERVER, &IID_IX509EnrollmentPolicyServer, (LPVOID *)&(pEnrollmentPolicyServer));
	CHECK_RETURN_FAIL("CoCreateInstance()", hr);

	hr = pEnrollmentPolicyServer->lpVtbl->Initialize(pEnrollmentPolicyServer, bstrPolicyServerUrl, bstrPolicyServerId, X509AuthKerberos, TRUE, ContextUser);
	CHECK_RETURN_FAIL("pEnrollmentPolicyServer->lpVtbl->Initialize()", hr);

	hr = pEnrollmentPolicyServer->lpVtbl->LoadPolicy(pEnrollmentPolicyServer, LoadOptionReload);
	CHECK_RETURN_FAIL("pEnrollmentPolicyServer->lpVtbl->LoadPolicy()", hr);

	SAFE_RELEASE(pCAs);
	hr = pEnrollmentPolicyServer->lpVtbl->GetCAs(pEnrollmentPolicyServer, &pCAs);
	CHECK_RETURN_FAIL("pEnrollmentPolicyServer->lpVtbl->GetCAs()", hr);

	hr = pCAs->lpVtbl->get_Count(pCAs, &lCAsCount);
	CHECK_RETURN_FAIL("pCAs->lpVtbl->get_Count()", hr);
	internal_printf("\n[*] Found %ld CAs\n", lCAsCount);

	for(LONG lCAsIndex=0; lCAsIndex<lCAsCount; lCAsIndex++)
	{
		SAFE_RELEASE(pCertificateAuthority);
		hr = pCAs->lpVtbl->get_ItemByIndex(pCAs, lCAsIndex, &pCertificateAuthority);
		CHECK_RETURN_FAIL("pCAs->lpVtbl->get_ItemByIndex()", hr);

		hr = _adcs_get_CertificationAuthority(pCertificateAuthority);
		CHECK_RETURN_FAIL("_adcs_get_CertificationAuthority()", hr);
	} // end for loop through ICertificationAuthority

	hr = S_OK;

fail:

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

	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropCommonName, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropCommonName)", hr);
	internal_printf("\n[*] Listing info about the Enterprise CA '%S'\n", varProperty.bstrVal);
	internal_printf("    Enterprise CA Name       : %S\n", varProperty.bstrVal);

	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropDNSName, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropDNSName)", hr);
	internal_printf("    DNS Hostname             : %S\n", varProperty.bstrVal);

	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropDistinguishedName,	&varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropDistinguishedName)", hr);
	if (varProperty.pdispVal)
	{
		BSTR bstrName = NULL;
		IX500DistinguishedName * pDistinguishedName = (IX500DistinguishedName*)varProperty.pdispVal;
		hr = pDistinguishedName->lpVtbl->get_Name(pDistinguishedName, &bstrName);
		CHECK_RETURN_FAIL("pDistinguishedName->lpVtbl->get_Name()", hr);
		internal_printf("    Distinguished Name       : %S\n", bstrName);
	}

	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropCertificate, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropCertificate)", hr);
	internal_printf("    CA Certificate           :\n");
	hr = _adcs_get_Certificate(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_Certificate()", hr);
	
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropSecurity, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropSecurity)", hr);
	internal_printf("    CA Permissions           :\n");
	hr = _adcs_get_Security(varProperty.bstrVal);
	CHECK_RETURN_FAIL("_adcs_get_Security()", hr);

	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropWebServers, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropWebServers)", hr);
	internal_printf("    Web Servers              :\n");
	hr = _adcs_get_WebServers(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_WebServers()", hr);

	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropCertificateTypes, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropCertificateTypes)", hr);
	internal_printf("    Templates                :\n");
	hr = _adcs_get_CertificateTypes(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_CertificateTypes()", hr);

	hr = S_OK;

fail:

	OLEAUT32$VariantClear(&varProperty);

	return hr;
}


HRESULT _adcs_get_Certificate(VARIANT* lpvarCertifcate)
{
	HRESULT hr = S_OK;
	LPBYTE lpCertificate = NULL;
	ULONG ulCertificateSize = 0;
	PCCERT_CONTEXT  pCert = NULL; 
	BOOL bReturn = TRUE;
	DWORD dwStrType = CERT_X500_NAME_STR;
	LPWSTR swzNameString = NULL;
	DWORD cchNameString = 0;
	PBYTE lpThumbprint = NULL;
	DWORD cThumbprint = 0;
	SYSTEMTIME systemTime;
	CERT_CHAIN_PARA chainPara;
	PCCERT_CHAIN_CONTEXT pCertChainContext = NULL;

	// check buffer
	if (NULL == lpvarCertifcate->parray)
	{
		internal_printf("      %S\n", STR_NOT_AVAILALBE);
		goto fail;
	}
		
	// Get a certificate context
	ulCertificateSize = lpvarCertifcate->parray->rgsabound->cElements;
	hr = OLEAUT32$SafeArrayAccessData( lpvarCertifcate->parray, (void**)(&lpCertificate) );
	CHECK_RETURN_FAIL("OLEAUT32$SafeArrayAccessData", hr);
	pCert = CRYPT32$CertCreateCertificateContext( 1, lpCertificate, ulCertificateSize );
	hr = OLEAUT32$SafeArrayUnaccessData( lpvarCertifcate->parray );
	CHECK_RETURN_FAIL("OLEAUT32$SafeArrayUnaccessData", hr);
	CHECK_RETURN_NULL("CertCreateCertificateContext()", pCert, hr);
	
	// subject name
	cchNameString = CRYPT32$CertGetNameStringW( pCert, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString );
	swzNameString = intAlloc(cchNameString*sizeof(WCHAR));
	CHECK_RETURN_NULL("intAlloc()", swzNameString, hr);
	if (1 == CRYPT32$CertGetNameStringW( pCert, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString ))
	{
		hr = E_UNEXPECTED;
		BeaconPrintf(CALLBACK_ERROR, "CertGetNameStringW failed: 0x%08lx\n", hr);
		goto fail;
	}
	internal_printf("      Subject Name           : %S\n", swzNameString);
	SAFE_INT_FREE(swzNameString);

	// thumbprint
	CRYPT32$CertGetCertificateContextProperty( pCert, CERT_SHA1_HASH_PROP_ID, lpThumbprint, &cThumbprint );
	lpThumbprint = intAlloc(cThumbprint);
	CHECK_RETURN_NULL("intAlloc()", lpThumbprint, hr);
	bReturn = CRYPT32$CertGetCertificateContextProperty( pCert, CERT_SHA1_HASH_PROP_ID, lpThumbprint, &cThumbprint );
	CHECK_RETURN_FALSE("CertGetCertificateContextProperty(CERT_SHA1_HASH_PROP_ID)", bReturn, hr);
	internal_printf("      Thumbprint             : ");
	for(DWORD i=0; i<cThumbprint; i++)
	{
		internal_printf("%02x", lpThumbprint[i]);
	}
	internal_printf("\n");
	SAFE_INT_FREE(lpThumbprint);

	// serial number
	internal_printf("      Serial Number          : ");
	for(DWORD i=0; i<pCert->pCertInfo->SerialNumber.cbData; i++)
	{
		internal_printf("%02x", pCert->pCertInfo->SerialNumber.pbData[i]);
	}
	internal_printf("\n");

	// start date
	MSVCRT$memset(&systemTime, 0, sizeof(SYSTEMTIME));
	KERNEL32$FileTimeToSystemTime(&(pCert->pCertInfo->NotBefore), &systemTime);
	internal_printf("      Start Date             : %hu/%hu/%hu %02hu:%02hu:%02hu\n", systemTime.wMonth, systemTime.wDay, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

	// end date
	MSVCRT$memset(&systemTime, 0, sizeof(SYSTEMTIME));
	KERNEL32$FileTimeToSystemTime(&(pCert->pCertInfo->NotAfter), &systemTime);
	internal_printf("      End Date               : %hu/%hu/%hu %02hu:%02hu:%02hu\n", systemTime.wMonth, systemTime.wDay, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

	// chain
	chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	chainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
	chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;
	bReturn = CRYPT32$CertGetCertificateChain( NULL, pCert, NULL, NULL, &chainPara, 0, NULL, &pCertChainContext );
	CHECK_RETURN_FALSE("CertGetCertificateChain()", bReturn, hr);
	internal_printf("      Chain                  :");
	for(DWORD i=0; i<pCertChainContext->cChain; i++)
	{
		for(DWORD j=0; j<pCertChainContext->rgpChain[i]->cElement; j++)
		{
			PCCERT_CONTEXT pChainCertContext = pCertChainContext->rgpChain[i]->rgpElement[j]->pCertContext;

			// subject name
			cchNameString = CRYPT32$CertGetNameStringW( pChainCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString );
			swzNameString = intAlloc(cchNameString*sizeof(WCHAR));
			CHECK_RETURN_NULL("intAlloc()", swzNameString, hr);
			if (1 == CRYPT32$CertGetNameStringW( pChainCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, swzNameString, cchNameString ))
			{
				hr = E_UNEXPECTED;
				BeaconPrintf(CALLBACK_ERROR, "CertGetNameStringW failed: 0x%08lx\n", hr);
				goto fail;
			}
			if (j!=0) { internal_printf(" >>"); }
			internal_printf(" %S", swzNameString);
			SAFE_INT_FREE(swzNameString);
		} // end for loop through PCERT_CHAIN_ELEMENT
		internal_printf("\n");
	} // end for loop through PCERT_SIMPLE_CHAIN

	hr = S_OK;

fail:

	SAFE_CERTFREECERTIFICATECHAIN(pCertChainContext);

	SAFE_INT_FREE(swzNameString);

	SAFE_INT_FREE(lpThumbprint);

	if (pCert)
	{
		CRYPT32$CertFreeCertificateContext(pCert);
		pCert = NULL;
	}

	return hr;
}


HRESULT _adcs_get_WebServers(VARIANT* lpvarWebServers)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrWebServer = NULL;
	LPWSTR swzTokenize = NULL;

	if ( NULL == lpvarWebServers->parray)
	{
		internal_printf("      %S\n", STR_NOT_AVAILALBE);
		goto fail;
	}
	
	hr = OLEAUT32$SafeArrayGetElement(lpvarWebServers->parray, &lItemIdx, &bstrWebServer);
	while(SUCCEEDED(hr))
	{
		ULONG dwWebServerCount = 0;
		LPWSTR swzToken = NULL;
		LPWSTR swzNextToken = NULL;
		UINT dwTokenizeLength = OLEAUT32$SysStringLen(bstrWebServer);
		swzTokenize = (LPWSTR)intAlloc(sizeof(WCHAR)*(dwTokenizeLength+1));
		CHECK_RETURN_NULL("intAlloc()", swzTokenize, hr);
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
			internal_printf("      %S\n", swzToken);
			// Get the RenewalOnly flag
			swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
			if (NULL == swzToken) {	break; }
		}

		SAFE_INT_FREE(swzTokenize);

		++lItemIdx;
		hr = OLEAUT32$SafeArrayGetElement(lpvarWebServers->parray, &lItemIdx, &bstrWebServer);	
	}

	hr = S_OK;

fail:

	SAFE_INT_FREE(swzTokenize);

	return hr;
}


HRESULT _adcs_get_Security(BSTR bstrDacl)
{
	HRESULT hr = S_OK;
	BOOL bReturn = TRUE;
	PSID pOwner = NULL;
	BOOL bOwnerDefaulted = TRUE;
	LPWSTR swzStringSid = NULL;
	WCHAR swzName[MAX_PATH];
	DWORD cchName = MAX_PATH;
	WCHAR swzDomainName[MAX_PATH];
	DWORD cchDomainName = MAX_PATH;
	BOOL bDaclPresent = TRUE;
	PACL pDacl = NULL;
	BOOL bDaclDefaulted = TRUE;
	ACL_SIZE_INFORMATION aclSizeInformation;
	SID_NAME_USE sidNameUse;
	PSECURITY_DESCRIPTOR pSD = NULL;
	ULONG ulSDSize = 0;

	// Get the security descriptor
	if (NULL == bstrDacl)
	{
		internal_printf("      %S\n", STR_NOT_AVAILALBE);
		goto fail;
	}
	bReturn = ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(bstrDacl, SDDL_REVISION_1, (PSECURITY_DESCRIPTOR)(&pSD), &ulSDSize);
	CHECK_RETURN_FALSE("ConvertStringSecurityDescriptorToSecurityDescriptorW()", bReturn, hr);

	// Get the owner
	bReturn = ADVAPI32$GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorOwner()", bReturn, hr);
	internal_printf("      Owner                  : ");
	cchName = MAX_PATH;
	MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
	cchDomainName = MAX_PATH;
	MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
	if (ADVAPI32$LookupAccountSidW(	NULL, pOwner, swzName, &cchName, swzDomainName, &cchDomainName, &sidNameUse )) { internal_printf("%S\\%S", swzDomainName, swzName); }
	else { internal_printf("N/A"); }

	// Get the owner's SID
	if (ADVAPI32$ConvertSidToStringSidW(pOwner, &swzStringSid)) { internal_printf("\n                               %S\n", swzStringSid); }
	else { internal_printf("\n                               N/A\n"); }
	SAFE_LOCAL_FREE(swzStringSid);

	// Get the DACL
	bReturn = ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorDacl()", bReturn, hr);
	internal_printf("      Access Rights          :\n");
	if (FALSE == bDaclPresent) { internal_printf("          N/A\n"); goto fail; }

	// Loop through the ACEs in the ACL
	if ( ADVAPI32$GetAclInformation( pDacl, &aclSizeInformation, sizeof(aclSizeInformation), AclSizeInformation ) )
	{
		for(DWORD dwAceIndex=0; dwAceIndex<aclSizeInformation.AceCount; dwAceIndex++)
		{
			ACE_HEADER * pAceHeader = NULL;
			ACCESS_ALLOWED_ACE* pAce = NULL;
			ACCESS_ALLOWED_OBJECT_ACE* pAceObject = NULL;
			PSID pPrincipalSid = NULL;
			hr = E_UNEXPECTED;

			if ( ADVAPI32$GetAce( pDacl, dwAceIndex, (LPVOID)&pAceHeader ) )
			{
				pAceObject = (ACCESS_ALLOWED_OBJECT_ACE*)pAceHeader;
				pAce = (ACCESS_ALLOWED_ACE*)pAceHeader;

				if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType) { pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType)); }
				else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType) { pPrincipalSid = (PSID)(&(pAce->SidStart)); }
				else { continue; }

				// Get the principal
				cchName = MAX_PATH;
				MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == ADVAPI32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	)) { continue; }
				
				internal_printf("        Principal            : %S\\%S\n", swzDomainName, swzName);
				internal_printf("          Access mask        : %08X\n", pAceObject->Mask);
				internal_printf("          Flags              : %08X\n", pAceObject->Flags);
					
				// Get the extended rights
				if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask)
				{
					if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags)
					{
						OLECHAR szGuid[MAX_PATH];
						if ( OLE32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) )
						{
							internal_printf("          Extended right     : %S\n", szGuid);
						}
						if (
							IsEqualGUID(&CertificateEnrollment, &pAceObject->ObjectType) ||
							IsEqualGUID(&CertificateAutoEnrollment, &pAceObject->ObjectType) ||
							IsEqualGUID(&CertificateAll, &pAceObject->ObjectType)
							)
						{
							internal_printf("                               Enrollment Rights\n");
						}
					} // end if ACE_OBJECT_TYPE_PRESENT
				} // end if ADS_RIGHT_DS_CONTROL_ACCESS
			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)

		hr = S_OK;
	} // end else GetAclInformation was successful

	hr = S_OK;

fail:

	SAFE_LOCAL_FREE(swzStringSid);
	SAFE_LOCAL_FREE(pSD);

	return hr;
}


HRESULT _adcs_get_CertificateTypes(VARIANT* lpvarArray)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrItem = NULL;

	if (NULL == lpvarArray->parray)
	{
		internal_printf("      %S\n", STR_NOT_AVAILALBE);
		goto fail;
	}
	
	hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);
	while(SUCCEEDED(hr))
	{
		if (bstrItem) { internal_printf("      %S\n", bstrItem); }
		else { internal_printf("      %S\n", STR_NOT_AVAILALBE); }

		++lItemIdx;
		hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);	
	}

	hr = S_OK;

fail:

	return hr;
}


HRESULT adcs_enum_cas()
{
	HRESULT hr = S_OK;

	hr = OLE32$CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
	CHECK_RETURN_FAIL("CoInitializeEx", hr);
	
	hr = _adcs_get_PolicyServerListManager();
	CHECK_RETURN_FAIL("_adcs_get_PolicyServerListManager", hr);

	hr = S_OK;
	
fail:	
	
	OLE32$CoUninitialize();

	return hr;
}
