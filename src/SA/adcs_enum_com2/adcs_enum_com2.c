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
#include "adcs_enum_com2.h"


typedef HRESULT WINAPI (*CAEnumFirstCA_t)(IN LPCWSTR wszScope, IN DWORD dwFlags, OUT LPVOID * phCAInfo);
typedef HRESULT WINAPI (*CAEnumNextCA_t)(IN LPVOID hPrevCA, OUT LPVOID * phCAInfo);
typedef HRESULT WINAPI (*CACloseCA_t)(IN LPVOID hCA);
typedef DWORD WINAPI (*CACountCAs_t)(IN LPVOID hCAInfo);
typedef LPCWSTR WINAPI (*CAGetDN_t)(IN LPVOID hCAInfo);
typedef HRESULT WINAPI (*CAGetCAProperty_t)(IN LPVOID hCAInfo, IN LPCWSTR wszPropertyName, OUT PZPWSTR *pawszPropertyValue);
typedef HRESULT WINAPI (*CAFreeCAProperty_t)(IN LPVOID hCAInfo, IN PZPWSTR awszPropertyValue);
typedef HRESULT WINAPI (*CAGetCAFlags_t)(IN LPVOID hCAInfo, OUT DWORD  *pdwFlags);
typedef HRESULT WINAPI (*CAGetCACertificate_t)(IN LPVOID hCAInfo, OUT PCCERT_CONTEXT *ppCert);
typedef HRESULT WINAPI (*CAGetCAExpiration_t)(IN LPVOID hCAInfo, OUT DWORD * pdwExpiration, OUT DWORD * pdwUnits);
typedef HRESULT WINAPI (*CAGetCASecurity_t)(IN LPVOID hCAInfo, OUT PSECURITY_DESCRIPTOR * ppSD);
typedef HRESULT WINAPI (*CAGetAccessRights_t)(IN LPVOID hCAInfo, IN DWORD dwContext, OUT DWORD *pdwAccessRights);
typedef HRESULT WINAPI (*CAEnumCertTypesForCA_t)(IN LPVOID hCAInfo, IN DWORD dwFlags, OUT LPVOID * phCertType);
typedef HRESULT WINAPI (*CAEnumCertTypes_t)(IN DWORD dwFlags, OUT LPVOID * phCertType);
typedef HRESULT WINAPI (*CAEnumNextCertType_t)(IN LPVOID hPrevCertType, OUT LPVOID * phCertType);
typedef DWORD WINAPI (*CACountCertTypes_t)(IN LPVOID hCertType);
typedef HRESULT WINAPI (*CACloseCertType_t)(IN LPVOID hCertType);
typedef HRESULT WINAPI (*CAGetCertTypeProperty_t)(IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT PZPWSTR *pawszPropertyValue);
typedef HRESULT WINAPI (*CAGetCertTypePropertyEx_t)(IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT LPVOID *pPropertyValue);
typedef HRESULT WINAPI (*CAFreeCertTypeProperty_t)(IN LPVOID hCertType, IN PZPWSTR awszPropertyValue);
typedef HRESULT WINAPI (*CAGetCertTypeExtensionsEx_t)(IN LPVOID hCertType, IN DWORD dwFlags, IN LPVOID pParam, OUT PCERT_EXTENSIONS * ppCertExtensions);
typedef HRESULT WINAPI (*CAFreeCertTypeExtensions_t)(IN LPVOID hCertType, IN PCERT_EXTENSIONS pCertExtensions);
typedef HRESULT WINAPI (*CAGetCertTypeFlagsEx_t)(IN LPVOID hCertType, IN DWORD dwOption, OUT DWORD * pdwFlags);
typedef HRESULT WINAPI (*CAGetCertTypeExpiration_t)(IN LPVOID hCertType, OUT OPTIONAL FILETIME * pftExpiration, OUT OPTIONAL FILETIME * pftOverlap);
typedef HRESULT WINAPI (*CACertTypeGetSecurity_t)(IN LPVOID hCertType, OUT PSECURITY_DESCRIPTOR * ppSD);
typedef HRESULT WINAPI (*caTranslateFileTimePeriodToPeriodUnits_t)(IN FILETIME const *pftGMT, IN BOOL Flags, OUT DWORD *pcPeriodUnits, OUT LPVOID*prgPeriodUnits);
typedef HRESULT WINAPI (*CAGetCertTypeAccessRights_t)(IN LPVOID hCertType, IN DWORD dwContext, OUT DWORD *pdwAccessRights);

#define CERTCLI$CAEnumFirstCA ((CAEnumFirstCA_t)DynamicLoad("CERTCLI","CAEnumFirstCA"))
#define CERTCLI$CAEnumNextCA ((CAEnumNextCA_t)DynamicLoad("CERTCLI","CAEnumNextCA"))
#define CERTCLI$CACloseCA ((CACloseCA_t)DynamicLoad("CERTCLI","CACloseCA"))
#define CERTCLI$CACountCAs ((CACountCAs_t)DynamicLoad("CERTCLI","CACountCAs"))
#define CERTCLI$CAGetDN ((CAGetDN_t)DynamicLoad("CERTCLI","CAGetDN"))
#define CERTCLI$CAGetCAProperty ((CAGetCAProperty_t)DynamicLoad("CERTCLI","CAGetCAProperty"))
#define CERTCLI$CAFreeCAProperty ((CAFreeCAProperty_t)DynamicLoad("CERTCLI","CAFreeCAProperty"))
#define CERTCLI$CAGetCAFlags ((CAGetCAFlags_t)DynamicLoad("CERTCLI","CAGetCAFlags"))
#define CERTCLI$CAGetCACertificate ((CAGetCACertificate_t)DynamicLoad("CERTCLI","CAGetCACertificate"))
#define CERTCLI$CAGetCAExpiration ((CAGetCAExpiration_t)DynamicLoad("CERTCLI","CAGetCAExpiration"))
#define CERTCLI$CAGetCASecurity ((CAGetCASecurity_t)DynamicLoad("CERTCLI","CAGetCASecurity"))
#define CERTCLI$CAGetAccessRights ((CAGetAccessRights_t)DynamicLoad("CERTCLI","CAGetAccessRights"))
#define CERTCLI$CAEnumCertTypesForCA ((CAEnumCertTypesForCA_t)DynamicLoad("CERTCLI","CAEnumCertTypesForCA"))
#define CERTCLI$CAEnumCertTypes ((CAEnumCertTypes_t)DynamicLoad("CERTCLI","CAEnumCertTypes"))
#define CERTCLI$CAEnumNextCertType ((CAEnumNextCertType_t)DynamicLoad("CERTCLI","CAEnumNextCertType"))
#define CERTCLI$CACountCertTypes ((CACountCertTypes_t)DynamicLoad("CERTCLI","CACountCertTypes"))
#define CERTCLI$CACloseCertType ((CACloseCertType_t)DynamicLoad("CERTCLI","CACloseCertType"))
#define CERTCLI$CAGetCertTypeProperty ((CAGetCertTypeProperty_t)DynamicLoad("CERTCLI","CAGetCertTypeProperty"))
#define CERTCLI$CAGetCertTypePropertyEx ((CAGetCertTypePropertyEx_t)DynamicLoad("CERTCLI","CAGetCertTypePropertyEx"))
#define CERTCLI$CAFreeCertTypeProperty ((CAFreeCertTypeProperty_t)DynamicLoad("CERTCLI","CAFreeCertTypeProperty"))
#define CERTCLI$CAGetCertTypeExtensionsEx ((CAGetCertTypeExtensionsEx_t)DynamicLoad("CERTCLI","CAGetCertTypeExtensionsEx"))
#define CERTCLI$CAFreeCertTypeExtensions ((CAFreeCertTypeExtensions_t)DynamicLoad("CERTCLI","CAFreeCertTypeExtensions"))
#define CERTCLI$CAGetCertTypeFlagsEx ((CAGetCertTypeFlagsEx_t)DynamicLoad("CERTCLI","CAGetCertTypeFlagsEx"))
#define CERTCLI$CAGetCertTypeExpiration ((CAGetCertTypeExpiration_t)DynamicLoad("CERTCLI","CAGetCertTypeExpiration"))
#define CERTCLI$CACertTypeGetSecurity ((CACertTypeGetSecurity_t)DynamicLoad("CERTCLI","CACertTypeGetSecurity"))
#define CERTCLI$caTranslateFileTimePeriodToPeriodUnits ((caTranslateFileTimePeriodToPeriodUnits_t)DynamicLoad("CERTCLI","caTranslateFileTimePeriodToPeriodUnits"))
#define CERTCLI$CAGetCertTypeAccessRights ((CAGetCertTypeAccessRights_t)DynamicLoad("CERTCLI","CAGetCertTypeAccessRights"))


typedef PCCERT_CONTEXT WINAPI (*CertCreateCertificateContext_t)(DWORD dwCertEncodingType, const BYTE *pbCertEncoded, DWORD cbCertEncoded);
typedef DWORD WINAPI (*CertGetNameStringW_t)(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
typedef WINBOOL WINAPI (*CertGetCertificateContextProperty_t)(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData);
typedef WINBOOL WINAPI (*CertGetCertificateChain_t)(HCERTCHAINENGINE hChainEngine, PCCERT_CONTEXT pCertContext, LPFILETIME pTime, HCERTSTORE hAdditionalStore, PCERT_CHAIN_PARA pChainPara, DWORD dwFlags, LPVOID pvReserved, PCCERT_CHAIN_CONTEXT *ppChainContext);
typedef VOID WINAPI (*CertFreeCertificateChain_t)(PCCERT_CHAIN_CONTEXT pChainContext);

#define CRYPT32$CertCreateCertificateContext ((CertCreateCertificateContext_t)DynamicLoad("CRYPT32","CertCreateCertificateContext"))
#define CRYPT32$CertGetNameStringW ((CertGetNameStringW_t)DynamicLoad("CRYPT32","CertGetNameStringW"))
#define CRYPT32$CertGetCertificateContextProperty ((CertGetCertificateContextProperty_t)DynamicLoad("CRYPT32","CertGetCertificateContextProperty"))
#define CRYPT32$CertGetCertificateChain ((CertGetCertificateChain_t)DynamicLoad("CRYPT32","CertGetCertificateChain"))
#define CRYPT32$CertFreeCertificateChain ((CertFreeCertificateChain_t)DynamicLoad("CRYPT32","CertFreeCertificateChain"))


typedef BSTR WINAPI (*SysAllocString_t)(const OLECHAR *);
typedef UINT WINAPI (*SysStringLen_t)(BSTR);
typedef void WINAPI (*SysFreeString_t)(BSTR);
typedef void WINAPI (*SafeArrayDestroy_t)(SAFEARRAY *psa);
typedef void WINAPI (*VariantInit_t)(VARIANTARG *pvarg);
typedef void WINAPI (*VariantClear_t)(VARIANTARG *pvarg);

#define OLEAUT32$SysAllocString ((SysAllocString_t)DynamicLoad("OLEAUT32","SysAllocString"))
#define OLEAUT32$SysStringLen ((SysStringLen_t)DynamicLoad("OLEAUT32","SysStringLen"))
#define OLEAUT32$SysFreeString ((SysFreeString_t)DynamicLoad("OLEAUT32","SysFreeString"))
#define OLEAUT32$SafeArrayDestroy ((SafeArrayDestroy_t)DynamicLoad("OLEAUT32","SafeArrayDestroy"))
#define OLEAUT32$VariantInit ((VariantInit_t)DynamicLoad("OLEAUT32","VariantInit"))
#define OLEAUT32$VariantClear ((VariantClear_t)DynamicLoad("OLEAUT32","VariantClear"))


typedef HRESULT WINAPI (*CoInitializeEx_t)(LPVOID pvReserved, DWORD dwCoInit);
typedef HRESULT WINAPI (*CoUninitialize_t)(void);
typedef int WINAPI (*StringFromGUID2_t)(REFGUID rguid, LPOLESTR lpsz, int cchMax);

#define OLE32$CoInitializeEx ((CoInitializeEx_t)DynamicLoad("OLE32","CoInitializeEx"))
#define OLE32$CoUninitialize ((CoUninitialize_t)DynamicLoad("OLE32","CoUninitialize"))
#define OLE32$StringFromGUID2 ((StringFromGUID2_t)DynamicLoad("OLE32","StringFromGUID2"))


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
#define CHECK_RETURN_SOFT_FAIL( function, result ) \
	if (FAILED(result)) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "%s failed: 0x%08lx\n", function, result); \
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


#define DEFINE_MY_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
DEFINE_MY_GUID(CertificateEnrollment,0x0e10c968,0x78fb,0x11d2,0x90,0xd4,0x00,0xc0,0x4f,0x79,0xdc,0x55);
DEFINE_MY_GUID(CertificateAutoEnrollment,0xa05b8cc2,0x17bc,0x4802,0xa7,0x10,0xe7,0xc1,0x5a,0xb8,0x66,0xa2);
DEFINE_MY_GUID(CertificateAll,0x00000000,0x0000,0x0000,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
DEFINE_MY_GUID(ManageCA,0x05000000,0x0015,0x0000,0xf9,0xbf,0xaa,0x22,0x07,0x95,0x8d,0xdd);

HRESULT adcs_enum_com2()
{
	HRESULT hr = S_OK;

	hr = OLE32$CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
	CHECK_RETURN_FAIL("CoInitializeEx", hr);
	
	hr = _adcs_get_PolicyServerListManager();
	CHECK_RETURN_FAIL("_adcs_get_PolicyServerListManager", hr);

	hr = S_OK;

	//internal_printf("\n adcs_enum_com2 SUCCESS.\n");
	
fail:	
	
	OLE32$CoUninitialize();

	return hr;
} // end adcs_enum_com2

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
		CHECK_RETURN_SOFT_FAIL("[SOFT FAIL] _adcs_get_PolicyServerUrl()", hr);

		if (FAILED(hr)){
			internal_printf("    Failed to display information for the Policy Server \n");
		}
	} // end for loop through IX509PolicyServerUrl

	hr = S_OK;

	//internal_printf("\n _adcs_get_PolicyServerListManager SUCCESS.\n");

fail:

	SAFE_RELEASE(pPolicyServerUrl);
	SAFE_RELEASE(pPolicyServerListManager);

	return hr;
} // end _adcs_get_PolicyServerListManager


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

	//internal_printf("\n _adcs_get_PolicyServerUrl SUCCESS.\n");

fail:

	SAFE_FREE(bstrPolicyServerUrl);
	SAFE_FREE(bstrPolicyServerFriendlyName);
	SAFE_FREE(bstrPolicyServerId);

	return hr;
} // end _adcs_get_PolicyServerUrl


HRESULT _adcs_get_EnrollmentPolicyServer(BSTR bstrPolicyServerUrl, BSTR bstrPolicyServerId)
{
	HRESULT hr = S_OK;
	IX509EnrollmentPolicyServer * pEnrollmentPolicyServer = NULL;
	ICertificationAuthorities * pCAs = NULL;
	LONG lCAsCount = 0;
	ICertificationAuthority * pCertificateAuthority = NULL;
	IX509CertificateTemplates * pCertificateTemplates = NULL;
	LONG lCertificateTemplatesCount = 0;
	IX509CertificateTemplate * pCertificateTemplate = NULL;

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
		CHECK_RETURN_SOFT_FAIL("[SOFT FAIL] _adcs_get_CertificationAuthority()", hr);

		if (FAILED(hr)){
			internal_printf("    Failed to display information for the CertificationAuthority \n");
		}
	} // end for loop through ICertificationAuthority

	SAFE_RELEASE(pCertificateTemplates);
	hr = pEnrollmentPolicyServer->lpVtbl->GetTemplates(pEnrollmentPolicyServer,	&pCertificateTemplates);
	CHECK_RETURN_FAIL("pEnrollmentPolicyServer->lpVtbl->GetTemplates()", hr);

	hr = pCertificateTemplates->lpVtbl->get_Count(pCertificateTemplates, &lCertificateTemplatesCount);
	CHECK_RETURN_FAIL("pCertificateTemplates->lpVtbl->get_Count()", hr);
	internal_printf("\n[*] Found %ld templates\n", lCertificateTemplatesCount);

	for(LONG lCertificateTemplatesIndex=0; lCertificateTemplatesIndex<lCertificateTemplatesCount; lCertificateTemplatesIndex++)
	{
		SAFE_RELEASE(pCertificateTemplate);
		hr = pCertificateTemplates->lpVtbl->get_ItemByIndex(pCertificateTemplates, lCertificateTemplatesIndex, &pCertificateTemplate);
		CHECK_RETURN_FAIL("pCertificateTemplates->lpVtbl->get_ItemByIndex()", hr);

		hr = _adcs_get_CertificateTemplate(pCertificateTemplate);
		CHECK_RETURN_SOFT_FAIL("[SOFT FAIL] _adcs_get_CertificateTemplate()", hr);

		if (FAILED(hr)){
			internal_printf("    Failed to display information for the CertificateTemplate \n");
		}
	} // end for loop through ITemplates
	
	hr = S_OK;

	//internal_printf("\n _adcs_get_EnrollmentPolicyServer SUCCESS.\n");

fail:

	SAFE_RELEASE(pCertificateAuthority);
	SAFE_RELEASE(pCAs);
	SAFE_RELEASE(pEnrollmentPolicyServer);

	return hr;
} // end _adcs_get_EnrollmentPolicyServer


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
	hr = _adcs_get_CertificationAuthorityCertificate(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_CertificationAuthorityCertificate()", hr);
	
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropSecurity, &varProperty);
	CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropSecurity)", hr);
	internal_printf("    CA Permissions           :\n");
	hr = _adcs_get_CertificationAuthoritySecurity(varProperty.bstrVal);
	CHECK_RETURN_FAIL("_adcs_get_CertificationAuthoritySecurity()", hr);

	OLEAUT32$VariantClear(&varProperty);
	pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropWebServers, &varProperty);
	internal_printf("    Web Servers              :\n");
	hr = _adcs_get_CertificationAuthorityWebServers(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_CertificationAuthorityWebServers()", hr);

	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateAuthority->lpVtbl->get_Property(pCertificateAuthority, CAPropCertificateTypes, &varProperty);
	// CHECK_RETURN_FAIL("pCertificateAuthority->lpVtbl->get_Property(CAPropCertificateTypes)", hr);
	internal_printf("    Templates                :\n");
	hr = _adcs_get_CertificationAuthorityCertificateTypes(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_CertificationAuthorityCertificateTypes()", hr);

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertificationAuthority SUCCESS.\n");

fail:

	OLEAUT32$VariantClear(&varProperty);

	return hr;
} // end _adcs_get_CertificationAuthority


HRESULT _adcs_get_CertificationAuthorityCertificate(VARIANT* lpvarCertifcate)
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
		internal_printf("      N/A\n");
		goto fail;
	}
		
	// Get a certificate context
	ulCertificateSize = lpvarCertifcate->parray->rgsabound->cElements;
	hr = OLEAUT32$SafeArrayAccessData( lpvarCertifcate->parray, (void**)(&lpCertificate) );
	CHECK_RETURN_FAIL("SafeArrayAccessData", hr);
	pCert = CRYPT32$CertCreateCertificateContext( 1, lpCertificate, ulCertificateSize );
	hr = OLEAUT32$SafeArrayUnaccessData( lpvarCertifcate->parray );
	CHECK_RETURN_FAIL("SafeArrayUnaccessData", hr);
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

	//internal_printf("\n _adcs_get_CertificationAuthorityCertificate SUCCESS.\n");

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
} // end _adcs_get_CertificationAuthorityCertificate


HRESULT _adcs_get_CertificationAuthorityWebServers(VARIANT* lpvarWebServers)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrWebServer = NULL;
	LPWSTR swzTokenize = NULL;

	if ( NULL == lpvarWebServers->parray)
	{
		internal_printf("      N/A\n");
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

	//internal_printf("\n _adcs_get_CertificationAuthorityWebServers SUCCESS.\n");

fail:

	SAFE_INT_FREE(swzTokenize);

	return hr;
} // end _adcs_get_CertificationAuthorityWebServers


HRESULT _adcs_get_CertificationAuthoritySecurity(BSTR bstrDacl)
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
		internal_printf("      N/A\n");
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
				int format_ACCESS_ALLOWED_OBJECT_ACE = 0;

				if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType) {
					//internal_printf("        AceType: ACCESS_ALLOWED_OBJECT_ACE_TYPE\n");
					format_ACCESS_ALLOWED_OBJECT_ACE = 1;
					pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType)); 
				}
				else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType) { 
					//internal_printf("        AceType: ACCESS_ALLOWED_ACE_TYPE\n");
					pPrincipalSid = (PSID)(&(pAce->SidStart)); 
				}
				else { continue; }

				// Get the principal
				cchName = MAX_PATH;
				MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == ADVAPI32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	))
				{ continue; }

				swzStringSid = NULL;
				if (ADVAPI32$ConvertSidToStringSidW(pPrincipalSid, &swzStringSid)) { 
					internal_printf("        Principal           : %S\\%S (%S)\n", swzDomainName, swzName,swzStringSid); }
				else { 
					internal_printf("        Principal           : %S\\%S (N/A)\n", swzDomainName, swzName); }
				SAFE_LOCAL_FREE(swzStringSid);

				// pAceObject->Mask is always equal to pAce->Mask, not "perfect" but seems to work
				internal_printf("          Access mask       : %08X\n", pAceObject->Mask);
				internal_printf("          Flags             : %08X\n", pAceObject->Flags);
					
				if (format_ACCESS_ALLOWED_OBJECT_ACE) {
					// flags not defined in ACCESS_ALLOWED_ACE_TYPE
					internal_printf("          Flags             : %08X\n", pAceObject->Flags);

					// Check if Enrollment permission
					if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask)
					{
						if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags)
						{
							OLECHAR szGuid[MAX_PATH];
							if ( OLE32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) )
							{
								internal_printf("                              Extended right %S\n", szGuid);
							}
							if (
								(!MSVCRT$memcmp(&CertificateEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!MSVCRT$memcmp(&CertificateAutoEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!MSVCRT$memcmp(&CertificateAll, &pAceObject->ObjectType, sizeof (GUID)))
								)
							{
								internal_printf("                              Enrollment Rights\n");
							}
							else if (
								(!MSVCRT$memcmp(&ManageCA, &pAceObject->ObjectType, sizeof (GUID)))
								)
							{
								internal_printf("                              ManageCA Rights\n");
							}
						} // end if ACE_OBJECT_TYPE_PRESENT
					} // end if ADS_RIGHT_DS_CONTROL_ACCESS
				}
				
				// Check if ADS_RIGHT_GENERIC_ALL permission
				if (ADS_RIGHT_GENERIC_ALL & pAceObject->Mask)
				{
					internal_printf("                              Generic All Rights\n");
				} // end if ADS_RIGHT_GENERIC_ALL permission
				
				// Check if ADS_RIGHT_READ_CONTROL permission
				if ( 
					(ADS_RIGHT_READ_CONTROL & pAceObject->Mask)
				)
				{
					internal_printf("                              Read Rights\n");
				} // end if ADS_RIGHT_READ_CONTROL permission

				// Check if ADS_RIGHT_WRITE_OWNER permission
				if ( 
					(ADS_RIGHT_WRITE_OWNER & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteOwner Rights\n");
				} // end if ADS_RIGHT_WRITE_OWNER permission
				
				// Check if ADS_RIGHT_WRITE_DAC permission
				if ( 
					(ADS_RIGHT_WRITE_DAC & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteDacl Rights\n");
				} // end if ADS_RIGHT_WRITE_DAC permission
				
				// Check if ADS_RIGHT_GENERIC_WRITE permission
				if ( 
					(ADS_RIGHT_GENERIC_WRITE & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteProperty All Rights\n");
				} // end if ADS_RIGHT_GENERIC_WRITE permission

				// Check if ADS_RIGHT_DS_WRITE_PROP permission
				if ( 
					(ADS_RIGHT_DS_WRITE_PROP & pAceObject->Mask)
				)
				{
					if (format_ACCESS_ALLOWED_OBJECT_ACE) {

						internal_printf("                              WriteProperty Rights on ");
						OLECHAR szGuid[MAX_PATH];
						if ( OLE32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) )
						{
							internal_printf("%S\n", szGuid);
						}
						else
						{
							internal_printf("{ERROR}\n");
						}
					}
					else {
						// if ACCESS_OBJECT_ACE, there is no ACE_OBJECT_TYPE_PRESENT and ObjectType, so it's like a GENERIC_WRITE
						internal_printf("                              WriteProperty All Rights\n");
					}

				} // end if ADS_RIGHT_DS_WRITE_PROP permission

			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)
	} // end else GetAclInformation was successful

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertificationAuthoritySecurity SUCCESS.\n");

fail:

	SAFE_LOCAL_FREE(swzStringSid);
	SAFE_LOCAL_FREE(pSD);

	return hr;
} // end _adcs_get_CertificationAuthoritySecurity


HRESULT _adcs_get_CertificationAuthorityCertificateTypes(VARIANT* lpvarArray)
{
	HRESULT hr = S_OK;
	LONG lItemIdx = 0;
	BSTR bstrItem = NULL;

	if (NULL == lpvarArray->parray)
	{
		internal_printf("      N/A\n");
		goto fail;
	}
	
	hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);
	while(SUCCEEDED(hr))
	{
		if (bstrItem) { internal_printf("      %S\n", bstrItem); }
		else { internal_printf("      N/A\n"); }

		++lItemIdx;
		hr = OLEAUT32$SafeArrayGetElement(lpvarArray->parray, &lItemIdx, &bstrItem);	
	}

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertificationAuthorityCertificateTypes SUCCESS.\n");

fail:

	return hr;
} // end _adcs_get_CertificationAuthorityCertificateTypes


HRESULT _adcs_get_CertificateTemplate(IX509CertificateTemplate * pCertificateTemplate)
{
	HRESULT hr = S_OK;
	VARIANT varProperty;

	OLEAUT32$VariantInit(&varProperty);

	// Get the TemplatePropCommonName
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropCommonName, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropCommonName)", hr);
	internal_printf("\n[*] Listing info about the template '%S'\n", varProperty.bstrVal);
	internal_printf("    Template Name            : %S\n", varProperty.bstrVal);

	// Get the TemplatePropFriendlyName
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropFriendlyName, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropFriendlyName)", hr);
	internal_printf("    Template Friendly Name   : %S\n", varProperty.bstrVal);
	
	// Get the TemplatePropValidityPeriod
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropValidityPeriod, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropValidityPeriod)", hr);
	internal_printf("    Validity Period          : %ld years (%ld seconds)\n", varProperty.lVal/31536000, varProperty.lVal);

	// Get the TemplatePropRenewalPeriod
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropRenewalPeriod, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropRenewalPeriod)", hr);
	internal_printf("    Renewal Period           : %ld days (%ld seconds)\n", varProperty.lVal/86400, varProperty.lVal);

	// Get the TemplatePropSubjectNameFlags
	// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplatesubjectnameflag
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropSubjectNameFlags,	&varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropSubjectNameFlags)", hr);
	internal_printf("    Name Flags               :");
	if(SubjectNameEnrolleeSupplies & varProperty.intVal) { internal_printf(" SubjectNameEnrolleeSupplies"); }
	if(SubjectNameRequireDirectoryPath & varProperty.intVal) { internal_printf(" SubjectNameRequireDirectoryPath"); }
	if(SubjectNameRequireCommonName & varProperty.intVal) { internal_printf(" SubjectNameRequireCommonName"); }
	if(SubjectNameRequireEmail & varProperty.intVal) { internal_printf(" SubjectNameRequireEmail"); }
	if(SubjectNameRequireDNS & varProperty.intVal) { internal_printf(" SubjectNameRequireDNS"); }
	if(SubjectNameAndAlternativeNameOldCertSupplies & varProperty.intVal) { internal_printf(" SubjectNameAndAlternativeNameOldCertSupplies"); }
	if(SubjectAlternativeNameEnrolleeSupplies & varProperty.intVal) { internal_printf(" SubjectAlternativeNameEnrolleeSupplies"); }
	if(SubjectAlternativeNameRequireDirectoryGUID & varProperty.intVal) { internal_printf(" SubjectAlternativeNameRequireDirectoryGUID"); }
	if(SubjectAlternativeNameRequireUPN & varProperty.intVal) { internal_printf(" SubjectAlternativeNameRequireUPN"); }
	if(SubjectAlternativeNameRequireEmail & varProperty.intVal) { internal_printf(" SubjectAlternativeNameRequireEmail"); }
	if(SubjectAlternativeNameRequireSPN & varProperty.intVal) { internal_printf(" SubjectAlternativeNameRequireSPN"); }
	if(SubjectAlternativeNameRequireDNS & varProperty.intVal) { internal_printf(" SubjectAlternativeNameRequireDNS"); }
	if(SubjectAlternativeNameRequireDomainDNS & varProperty.intVal) { internal_printf(" SubjectAlternativeNameRequireDomainDNS"); }
	internal_printf("\n");	

	// Get the TemplatePropEnrollmentFlags
	// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplateenrollmentflag
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropEnrollmentFlags, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropEnrollmentFlags)", hr);
	internal_printf("    Enrollment Flags         :");
	if(EnrollmentIncludeSymmetricAlgorithms & varProperty.intVal) { internal_printf(" EnrollmentIncludeSymmetricAlgorithms"); }
	if(EnrollmentPendAllRequests & varProperty.intVal) { internal_printf(" EnrollmentPendAllRequests"); }
	if(EnrollmentPublishToKRAContainer & varProperty.intVal) { internal_printf(" EnrollmentPublishToKRAContainer"); }
	if(EnrollmentPublishToDS & varProperty.intVal) { internal_printf(" EnrollmentPublishToDS"); }
	if(EnrollmentAutoEnrollmentCheckUserDSCertificate & varProperty.intVal) { internal_printf(" EnrollmentAutoEnrollmentCheckUserDSCertificate"); }
	if(EnrollmentAutoEnrollment & varProperty.intVal) { internal_printf(" EnrollmentAutoEnrollment"); }
	if(EnrollmentDomainAuthenticationNotRequired & varProperty.intVal) { internal_printf(" EnrollmentDomainAuthenticationNotRequired"); }
	if(EnrollmentPreviousApprovalValidateReenrollment & varProperty.intVal) { internal_printf(" EnrollmentPreviousApprovalValidateReenrollment"); }
	if(EnrollmentUserInteractionRequired & varProperty.intVal) { internal_printf(" EnrollmentUserInteractionRequired"); }
	if(EnrollmentAddTemplateName & varProperty.intVal) { internal_printf(" EnrollmentAddTemplateName"); }
	if(EnrollmentRemoveInvalidCertificateFromPersonalStore & varProperty.intVal) { internal_printf(" EnrollmentRemoveInvalidCertificateFromPersonalStore"); }
	if(EnrollmentAllowEnrollOnBehalfOf & varProperty.intVal) { internal_printf(" EnrollmentAllowEnrollOnBehalfOf"); }
	if(EnrollmentAddOCSPNoCheck & varProperty.intVal) { internal_printf(" EnrollmentAddOCSPNoCheck"); }
	if(EnrollmentReuseKeyOnFullSmartCard & varProperty.intVal) { internal_printf(" EnrollmentReuseKeyOnFullSmartCard"); }
	if(EnrollmentNoRevocationInfoInCerts & varProperty.intVal) { internal_printf(" EnrollmentNoRevocationInfoInCerts"); }
	if(EnrollmentIncludeBasicConstraintsForEECerts & varProperty.intVal) { internal_printf(" EnrollmentIncludeBasicConstraintsForEECerts"); }
	internal_printf("\n");	

	// Get the TemplatePropRASignatureCount
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropRASignatureCount, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropRASignatureCount)", hr);
	internal_printf("    Signatures Required      : %d\n", varProperty.intVal);

	// Get the TemplatePropEKUs
	OLEAUT32$VariantClear(&varProperty);
	pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropEKUs, &varProperty);
	internal_printf("    Extended Key Usages      :\n");
	hr = _adcs_get_CertificateTemplateExtendedKeyUsages(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_CertificateTemplateExtendedKeyUsages", hr);
	
	// Get the TemplatePropKeySecurityDescriptor
	OLEAUT32$VariantClear(&varProperty);
	pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropSecurityDescriptor, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropSecurityDescriptor)", hr);
	internal_printf("    Permissions              :\n");
	hr = _adcs_get_CertificateTemplateSecurity(varProperty.bstrVal);
	CHECK_RETURN_FAIL("_adcs_get_CertificateTemplateSecurity", hr);
	
	hr = S_OK;

	//internal_printf("\n _adcs_get_CertificateTemplate SUCCESS.\n");

fail:

	OLEAUT32$VariantClear(&varProperty);

	return hr;
} // end _adcs_get_CertificateTemplate


HRESULT _adcs_get_CertificateTemplateExtendedKeyUsages(VARIANT* lpvarExtendedKeyUsages)
{
	HRESULT hr = S_OK;
	IObjectIds * pObjectIds = NULL;
	IEnumVARIANT *pEnum = NULL;
	LPUNKNOWN pUnk = NULL;
	VARIANT var;
	IDispatch *pDisp = NULL;
	ULONG lFetch = 0;
	IObjectId * pObjectId = NULL;
	BSTR bstFriendlyName = NULL;

	IID IID_IEnumVARIANT = { 0x00020404, 0x0000, 0x0000, {0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46} };
	IID IID_IObjectId = { 0x728ab300, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	
	OLEAUT32$VariantInit(&var);
	
	if (NULL == lpvarExtendedKeyUsages->pdispVal)
	{
		internal_printf("      N/A\n");
		goto fail;
	}
	pObjectIds = (IObjectIds*)lpvarExtendedKeyUsages->pdispVal;
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
				&bstFriendlyName
			);
			if (FAILED(hr))	{ internal_printf("      N/A\n"); }
			else { 
				internal_printf("      %S\n", bstFriendlyName); 
				SAFE_FREE(bstFriendlyName);
			}

			SAFE_RELEASE(pObjectId);
		}
		OLEAUT32$VariantClear(&var);

		hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &lFetch);
	} // end loop through IObjectIds via enumerator
	SAFE_RELEASE(pObjectId);

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertificateTemplateExtendedKeyUsages SUCCESS.\n");

fail:

	OLEAUT32$VariantClear(&var);

	return hr;
} // end _adcs_get_CertificateTemplateExtendedKeyUsages


HRESULT _adcs_get_CertificateTemplateSecurity(BSTR bstrDacl)
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
		internal_printf("      N/A\n");
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
	if (ADVAPI32$ConvertSidToStringSidW(pOwner, &swzStringSid)) { internal_printf("\n                              %S\n", swzStringSid); }
	else { internal_printf("\n                              N/A\n"); }
	SAFE_LOCAL_FREE(swzStringSid);

	// Get the DACL
	bReturn = ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorDacl()", bReturn, hr);
	internal_printf("      Access Rights         :\n");
	if (FALSE == bDaclPresent) { internal_printf("          N/A\n"); goto fail; }

	// Loop through ACEs in ACL
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
				int format_ACCESS_ALLOWED_OBJECT_ACE = 0;

				if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType) { 
					//internal_printf("        AceType: ACCESS_ALLOWED_OBJECT_ACE_TYPE\n");
					format_ACCESS_ALLOWED_OBJECT_ACE = 1;
					pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType)); 
				}
				else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType) { 
					//internal_printf("        AceType: ACCESS_ALLOWED_ACE_TYPE\n");
					pPrincipalSid = (PSID)(&(pAce->SidStart)); 
				}
				else { 
					continue; 
				}

				// Get the principal
				cchName = MAX_PATH;
				MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == ADVAPI32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	))
				{ continue; }

				swzStringSid = NULL;
				if (ADVAPI32$ConvertSidToStringSidW(pPrincipalSid, &swzStringSid)) { 
					internal_printf("        Principal           : %S\\%S (%S)\n", swzDomainName, swzName,swzStringSid); }
				else { 
					internal_printf("        Principal           : %S\\%S (N/A)\n", swzDomainName, swzName); }
				SAFE_LOCAL_FREE(swzStringSid);

				// pAceObject->Mask is always equal to pAce->Mask, not "perfect" but seems to work
				internal_printf("          Access mask       : %08X\n", pAceObject->Mask);

				if (format_ACCESS_ALLOWED_OBJECT_ACE) {
					// flags not defined in ACCESS_ALLOWED_ACE_TYPE
					internal_printf("          Flags             : %08X\n", pAceObject->Flags);

					// Check if Enrollment permission
					if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask)
					{
						if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags)
						{
							if (
								(!MSVCRT$memcmp(&CertificateEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!MSVCRT$memcmp(&CertificateAutoEnrollment, &pAceObject->ObjectType, sizeof (GUID))) ||
								(!MSVCRT$memcmp(&CertificateAll, &pAceObject->ObjectType, sizeof (GUID)))
								)
							{
								internal_printf("                              Enrollment Rights\n");
							}
						} // end if ACE_OBJECT_TYPE_PRESENT
					} // end if ADS_RIGHT_DS_CONTROL_ACCESS
				}
				
				// Check if ADS_RIGHT_GENERIC_ALL permission
				if (ADS_RIGHT_GENERIC_ALL & pAceObject->Mask)
				{
					internal_printf("                              All Rights\n");
				} // end if ADS_RIGHT_GENERIC_ALL permission
				
				// Check if ADS_RIGHT_WRITE_OWNER permission
				if ( 
					(ADS_RIGHT_WRITE_OWNER & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteOwner Rights\n");
				} // end if ADS_RIGHT_WRITE_OWNER permission
				
				// Check if ADS_RIGHT_WRITE_DAC permission
				if ( 
					(ADS_RIGHT_WRITE_DAC & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteDacl Rights\n");
				} // end if ADS_RIGHT_WRITE_DAC permission
				
				
				// Check if ADS_RIGHT_GENERIC_WRITE permission
				if ( 
					(ADS_RIGHT_GENERIC_WRITE & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteProperty Rights\n");
				} // end if ADS_RIGHT_GENERIC_WRITE permission

				// Check if ADS_RIGHT_DS_WRITE_PROP permission
				if ( 
					(ADS_RIGHT_DS_WRITE_PROP & pAceObject->Mask)
				)
				{
					if (format_ACCESS_ALLOWED_OBJECT_ACE) {

						internal_printf("                              WriteProperty Rights on ");
						OLECHAR szGuid[MAX_PATH];
						if ( OLE32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) )
						{
							internal_printf("%S\n", szGuid);
						}
						else
						{
							internal_printf("{ERROR}\n");
						}
					}
					else {
						// if ACCESS_OBJECT_ACE, there is no ACE_OBJECT_TYPE_PRESENT and ObjectType, so it's like a GENERIC_WRITE
						internal_printf("                              WriteProperty All Rights\n");
					}

				} // end if ADS_RIGHT_DS_WRITE_PROP permission

				
			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)

	} // end else GetAclInformation was successful

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertificateTemplateSecurity SUCCESS.\n");

fail:

	SAFE_LOCAL_FREE(swzStringSid);
	SAFE_LOCAL_FREE(pSD);

	return hr;
} // end _adcs_get_CertificateTemplateSecurity

