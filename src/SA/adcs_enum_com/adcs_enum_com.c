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
#include "certca.h"
#include "certenroll.h"
#include <certcli.h>
#include "adcs_enum_com.h"


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


#define PROPTYPE_INT 1
#define PROPTYPE_DATE 2
#define PROPTYPE_BINARY 3
#define PROPTYPE_STRING 4

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
#define SAFE_CERTFREECERTIFICATE( cert ) \
	if(cert) \
	{ \
		CRYPT32$CertFreeCertificateContext(cert); \
		cert = NULL; \
	}	

#define DEFINE_MY_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
DEFINE_MY_GUID(CertificateEnrollment,0x0e10c968,0x78fb,0x11d2,0x90,0xd4,0x00,0xc0,0x4f,0x79,0xdc,0x55);
DEFINE_MY_GUID(CertificateAutoEnrollment,0xa05b8cc2,0x17bc,0x4802,0xa7,0x10,0xe7,0xc1,0x5a,0xb8,0x66,0xa2);
DEFINE_MY_GUID(CertificateAll,0x00000000,0x0000,0x0000,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);


HRESULT adcs_enum_com()
{
	HRESULT	hr = S_OK;

	// Initialize COM
	hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	CHECK_RETURN_FAIL("CoInitializeEx", hr);
	
	hr = _adcs_get_CertConfig();
	CHECK_RETURN_FAIL("_adcs_get_CertConfig()", hr);

	hr = S_OK;

	//internal_printf("\n adcs_enum_com SUCCESS.\n");
	
fail:	
	
	OLE32$CoUninitialize();

	return hr;
} // end adcs_enum_com


HRESULT _adcs_get_CertConfig()
{
	HRESULT	hr = S_OK;
	ICertConfig2 * pCertConfig = NULL;
	LONG lConfigCount = 0;
	BSTR bstrFieldConfig = NULL;
	BSTR bstrFieldWebEnrollmentServers = NULL;
	BSTR bstrConfig = NULL;
	BSTR bstrWebEnrollmentServers = NULL;

	CLSID	CLSID_CCertConfig = { 0x372fce38, 0x4324, 0x11D0, {0x88, 0x10, 0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C} };
	IID		IID_ICertConfig2 = { 0x7a18edde, 0x7e78, 0x4163, {0x8d, 0xed, 0x78, 0xe2, 0xc9, 0xce, 0xe9, 0x24} };

	// Create an instance of the CertConfig class with the ICertConfig2 interface
	SAFE_RELEASE(pCertConfig);
	hr = OLE32$CoCreateInstance(&CLSID_CCertConfig, 0, CLSCTX_INPROC_SERVER, &IID_ICertConfig2,	(LPVOID *)&(pCertConfig));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCertConfig)", hr);

	bstrFieldConfig = OLEAUT32$SysAllocString(L"Config");
	bstrFieldWebEnrollmentServers = OLEAUT32$SysAllocString(L"WebEnrollmentServers");

	// Retrieve the number of Certificate Services Servers in the enterprise
    hr = pCertConfig->lpVtbl->Reset(pCertConfig, 0, &lConfigCount);
    CHECK_RETURN_FAIL("pCertConfig->lpVtbl->Reset()", hr);
	internal_printf("\n[*] Found %ld certificate services server configurations\n", lConfigCount);

	// Loop through all the Certificate Services Servers in the enterprise
	for(LONG lConfigIndex = 0; lConfigIndex < lConfigCount; lConfigIndex++)
	{
		LONG lNextIndex = 0;
		
		// Retrieve the Config field for the current configuration
    	hr = pCertConfig->lpVtbl->GetField(pCertConfig, bstrFieldConfig, &bstrConfig);
		CHECK_RETURN_FAIL("pCertConfig->lpVtbl->GetField(bstrFieldConfig)", hr);
		internal_printf("\n[*] Listing info about the configuration '%S'\n", bstrConfig);
		hr = _adcs_get_CertRequest(bstrConfig);
		CHECK_RETURN_SOFT_FAIL("[SOFT FAIL] _adcs_get_CertRequest()", hr);
		SAFE_FREE(bstrConfig);

		if (!FAILED(hr)){
			// Retrieve the WebEnrollmentServers field for the current configuration
			hr = pCertConfig->lpVtbl->GetField(pCertConfig, bstrFieldWebEnrollmentServers, &bstrWebEnrollmentServers);
			internal_printf("    Web Servers              :\n");
			if (S_OK == hr)
			{
				hr = _adcs_get_WebEnrollmentServers(bstrWebEnrollmentServers);
				CHECK_RETURN_FAIL("_adcs_get_WebEnrollmentServers()", hr);
			}
			else
			{
				internal_printf("      N/A\n");
				hr = S_OK;
			}
		}
		else{
			internal_printf("      Failed to retrive information about the Certificate Service\n");
			if(hr == CERTSRV_E_ENROLL_DENIED){
				internal_printf("      Error 0x80094011: The permissions on this certification authority do not allow the current user to enroll for certificates, and so not to enumerate the templates using adcs_enum_com.\n");
			}
		}

		// Retrieve the next available Certificate Services
    	hr = pCertConfig->lpVtbl->Next(pCertConfig,	&lNextIndex);
		CHECK_RETURN_FAIL("pCertConfig->lpVtbl->Next()", hr);

	} // end for loop through the configurations

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertConfig SUCCESS.\n");

fail:

	SAFE_FREE(bstrFieldConfig);
	SAFE_FREE(bstrFieldWebEnrollmentServers);
	SAFE_FREE(bstrConfig);
	SAFE_FREE(bstrWebEnrollmentServers);
	SAFE_RELEASE(pCertConfig);
	
	return hr;
} // end _adcs_get_CertConfig


HRESULT _adcs_get_CertRequest(BSTR bstrConfig)
{
	HRESULT	hr = S_OK;
	ICertRequest2 * pCertRequest = NULL;
	VARIANT varProperty;
	BSTR bstrCertificate = NULL;

	CLSID	CLSID_CCertRequest = { 0x98AFF3F0, 0x5524, 0x11D0, {0x88, 0x12, 0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C} };
	IID		IID_ICertRequest2 = { 0xA4772988, 0x4A85, 0x4FA9, {0x82, 0x4E, 0xB5, 0xCF, 0x5C, 0x16, 0x40, 0x5A} };

	OLEAUT32$VariantInit(&varProperty);

	SAFE_RELEASE(pCertRequest);
	hr = OLE32$CoCreateInstance(&CLSID_CCertRequest, 0, CLSCTX_INPROC_SERVER, &IID_ICertRequest2, (LPVOID *)&(pCertRequest));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CCertRequest)", hr);

	hr = pCertRequest->lpVtbl->GetCAProperty(pCertRequest, bstrConfig, CR_PROP_CANAME, 0, PROPTYPE_STRING, 0, &varProperty);
	CHECK_RETURN_FAIL("pCertRequest->lpVtbl->GetCAProperty(CR_PROP_CANAME)", hr);
	internal_printf("    Enterprise CA Name       : %S\n", varProperty.bstrVal);
	OLEAUT32$VariantClear(&varProperty);

	hr = pCertRequest->lpVtbl->GetCAProperty(pCertRequest, bstrConfig, CR_PROP_DNSNAME, 0, PROPTYPE_STRING, 0, &varProperty);
	CHECK_RETURN_FAIL("pCertRequest->lpVtbl->GetCAProperty(CR_PROP_DNSNAME)", hr);
	internal_printf("    DNS Hostname             : %S\n", varProperty.bstrVal);
	OLEAUT32$VariantClear(&varProperty);
	internal_printf("    FullName                 : %S\n", bstrConfig);

	hr = pCertRequest->lpVtbl->GetCACertificate(pCertRequest, FALSE, bstrConfig, CR_OUT_BINARY,	&bstrCertificate );
	CHECK_RETURN_FAIL("pCertRequest->lpVtbl->GetCACertificate())", hr);
	internal_printf("    CA Certificate           :\n");
	hr = _adcs_get_Certificate(bstrCertificate);
	CHECK_RETURN_FAIL("_adcs_get_Certificate()", hr);
	SAFE_FREE(bstrCertificate);


	hr = pCertRequest->lpVtbl->GetCAProperty(pCertRequest, bstrConfig, CR_PROP_TEMPLATES, 0, PROPTYPE_STRING, 0, &varProperty);
	CHECK_RETURN_FAIL("pCertRequest->lpVtbl->GetCAProperty(CR_PROP_TEMPLATES)", hr);
	hr = _adcs_get_Templates(varProperty.bstrVal);
	CHECK_RETURN_FAIL("_adcs_get_Templates()", hr);
	OLEAUT32$VariantClear(&varProperty);

	hr = S_OK;

	//internal_printf("\n _adcs_get_CertRequest SUCCESS.\n");

fail:

	SAFE_FREE(bstrCertificate);
	OLEAUT32$VariantClear(&varProperty);
	SAFE_RELEASE(pCertRequest);
	
	return hr;
} // end _adcs_get_CertRequest


HRESULT _adcs_get_Certificate(BSTR bstrCertificate)
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


	lpCertificate = (LPBYTE)bstrCertificate;
	ulCertificateSize = OLEAUT32$SysStringLen(bstrCertificate) * sizeof(OLECHAR) + 1;
	pCert = CRYPT32$CertCreateCertificateContext( 1, lpCertificate, ulCertificateSize );
	if(NULL == pCert)
	{
		hr = E_INVALIDARG;
		BeaconPrintf(CALLBACK_ERROR, "CertCreateCertificateContext failed: pCert is NULL\n");
		goto fail;
	}

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

	//internal_printf("\n _adcs_get_Certificate SUCCESS.\n");

fail:
	SAFE_CERTFREECERTIFICATE (pCert);
	SAFE_CERTFREECERTIFICATECHAIN (pCertChainContext);
	SAFE_INT_FREE(lpThumbprint);
	SAFE_INT_FREE(swzNameString);

	return hr;
} // end _adcs_get_Certificate


HRESULT _adcs_get_WebEnrollmentServers(BSTR bstrWebEnrollmentServers)
{
	HRESULT hr = S_OK;
	ULONG dwWebServerCount = 0;
	LPWSTR swzTokenize = NULL;
	LPWSTR swzToken = NULL;
	LPWSTR swzNextToken = NULL;
	UINT dwTokenizeLength = 0;
	
	dwTokenizeLength = OLEAUT32$SysStringLen(bstrWebEnrollmentServers);
	swzTokenize = (LPWSTR)intAlloc(sizeof(WCHAR)*(dwTokenizeLength+1));
	CHECK_RETURN_NULL("intAlloc()", swzTokenize, hr);
	MSVCRT$wcscpy(swzTokenize, bstrWebEnrollmentServers);

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

	hr = S_OK;

	//internal_printf("\n _adcs_get_WebEnrollmentServers SUCCESS.\n");

fail:

	SAFE_INT_FREE(swzTokenize);

	return hr;
} // end _adcs_get_WebEnrollmentServers


HRESULT _adcs_get_Templates(BSTR bstrTemplates)
{
	HRESULT hr = S_OK;
	DWORD dwTemplateCount = 0;
	LPWSTR swzTokenize = NULL;
	LPWSTR swzToken = NULL;
	LPWSTR swzNextToken = NULL;
	BSTR bstrOID = NULL;
	UINT dwTokenizeLength = OLEAUT32$SysStringLen(bstrTemplates);
	swzTokenize = (LPWSTR)intAlloc(sizeof(WCHAR)*(dwTokenizeLength+1));
	CHECK_RETURN_NULL("intAlloc()", swzTokenize, hr);
	MSVCRT$wcscpy(swzTokenize, bstrTemplates);
	
	// Get the number of entries in the array
	swzToken = swzTokenize;
	for (dwTemplateCount=0; swzToken[dwTemplateCount]; swzToken[dwTemplateCount]==L'\n' ? dwTemplateCount++ : *swzToken++);
	dwTemplateCount = dwTemplateCount/2;
	internal_printf("\n[*] Found %ld templates on the CA\n", dwTemplateCount);

	if (0 == dwTemplateCount)
	{
		internal_printf("    Nothing to list, %ld template on the CA \n", dwTemplateCount);
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
	for(ULONG dwTemplateIndex=0; dwTemplateIndex<dwTemplateCount; dwTemplateIndex++)
	{
		// Get the name
		internal_printf("\n[*] Listing info about the template '%S' (%d of %d)\n", swzToken, dwTemplateIndex, dwTemplateCount);

		// Get the OID
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
		SAFE_FREE(bstrOID);
		bstrOID = OLEAUT32$SysAllocString(swzToken);
		CHECK_RETURN_NULL("SysAllocString", bstrOID, hr);
		internal_printf("    Template OID             : %S\n", bstrOID);

		// Display information for the current template
		hr = _adcs_get_Template(bstrOID);
		CHECK_RETURN_SOFT_FAIL("[SOFT FAIL] _adcs_get_Template()", hr);
		
		if (FAILED(hr)){
			internal_printf("    Failed to display information for the template \n");
		}

		// Get the next template
		swzToken = MSVCRT$wcstok_s(NULL, L"\n", &swzNextToken);
		if(NULL == swzToken) { break; }
	} // end loop through and parse the Template entries

	hr = S_OK;

	//internal_printf("\n _adcs_get_Templates SUCCESS.\n");

fail:
	
	SAFE_FREE(bstrOID);
	SAFE_INT_FREE(swzTokenize);
	
	return hr;
} // end _adcs_get_Templates


HRESULT _adcs_get_Template(BSTR bstrOID)
{
	HRESULT hr = S_OK;
	IX509CertificateRequestPkcs7V2 * pPkcs = NULL;
	IX509CertificateTemplate * pTemplate = NULL;
	VARIANT varProperty;
	DWORD dwFlags = 0;

	//{884E2044-217D-11DA-B2A4-000E7BBB2B09}
	CLSID	CLSID_CX509CertificateRequestPkcs7 = { 0x884E2044, 0x217D, 0x11DA, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	//{728ab35c-217d-11da-b2a4-000e7bbb2b09}
	IID		IID_IX509CertificateRequestPkcs7V2 = { 0x728ab35c, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };

	OLEAUT32$VariantInit(&varProperty);

	// Create an instance of the X509CertificateRequestPkcs7 class with the IX509CertificateRequestPkcs7 interface
	SAFE_RELEASE(pPkcs);
	hr = OLE32$CoCreateInstance(&CLSID_CX509CertificateRequestPkcs7, 0, CLSCTX_INPROC_SERVER, &IID_IX509CertificateRequestPkcs7V2, (LPVOID *)&(pPkcs));
	CHECK_RETURN_FAIL("CoCreateInstance(CLSID_CX509CertificateRequestPkcs7)", hr);

	// Initializes the certificate request by using the template name
	hr = pPkcs->lpVtbl->InitializeFromTemplateName(pPkcs, ContextUser, bstrOID);
	CHECK_RETURN_FAIL("pPkcs->lpVtbl->InitializeFromTemplateName()", hr);

	// Get the template
	SAFE_RELEASE(pTemplate);
	hr = pPkcs->lpVtbl->get_Template(pPkcs,	&pTemplate);
	CHECK_RETURN_FAIL("pPkcs->lpVtbl->get_Template()", hr);

	// Get the TemplatePropFriendlyName
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropFriendlyName, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropFriendlyName)", hr);
	internal_printf("    Template Friendly Name   : %S\n", varProperty.bstrVal);
	OLEAUT32$VariantClear(&varProperty);

	// Get the TemplatePropValidityPeriod
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropValidityPeriod, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropValidityPeriod)", hr);
	internal_printf("    Template Validity Period : %ld years (%ld seconds)\n", varProperty.lVal/31536000, varProperty.lVal);
	OLEAUT32$VariantClear(&varProperty);
		
	// Get the TemplatePropRenewalPeriod
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropRenewalPeriod, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropRenewalPeriod)", hr);
	internal_printf("    Template Validity Period : %ld years (%ld seconds)\n", varProperty.lVal/86400, varProperty.lVal);
	OLEAUT32$VariantClear(&varProperty);

	// Get the TemplatePropEnrollmentFlags
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropEnrollmentFlags, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropEnrollmentFlags)", hr);
	dwFlags = varProperty.intVal;
	internal_printf("    Enrollment Flags         :");
	if(EnrollmentIncludeSymmetricAlgorithms & dwFlags) { internal_printf(" EnrollmentIncludeSymmetricAlgorithms"); }
	if(EnrollmentPendAllRequests & dwFlags) { internal_printf(" EnrollmentPendAllRequests"); }
	if(EnrollmentPublishToKRAContainer & dwFlags) { internal_printf(" EnrollmentPublishToKRAContainer"); }
	if(EnrollmentPublishToDS & dwFlags) { internal_printf(" EnrollmentPublishToDS"); }
	if(EnrollmentAutoEnrollmentCheckUserDSCertificate & dwFlags) { internal_printf(" EnrollmentAutoEnrollmentCheckUserDSCertificate"); }
	if(EnrollmentAutoEnrollment & dwFlags) { internal_printf(" EnrollmentAutoEnrollment"); }
	if(EnrollmentDomainAuthenticationNotRequired & dwFlags) { internal_printf(" EnrollmentDomainAuthenticationNotRequired"); }
	if(EnrollmentPreviousApprovalValidateReenrollment & dwFlags) { internal_printf(" EnrollmentPreviousApprovalValidateReenrollment"); }
	if(EnrollmentUserInteractionRequired & dwFlags) { internal_printf(" EnrollmentUserInteractionRequired"); }
	if(EnrollmentAddTemplateName & dwFlags) { internal_printf(" EnrollmentAddTemplateName"); }
	if(EnrollmentRemoveInvalidCertificateFromPersonalStore & dwFlags) { internal_printf(" EnrollmentRemoveInvalidCertificateFromPersonalStore"); }
	if(EnrollmentAllowEnrollOnBehalfOf & dwFlags) { internal_printf(" EnrollmentAllowEnrollOnBehalfOf"); }
	if(EnrollmentAddOCSPNoCheck & dwFlags) { internal_printf(" EnrollmentAddOCSPNoCheck"); }
	if(EnrollmentReuseKeyOnFullSmartCard & dwFlags) { internal_printf(" EnrollmentReuseKeyOnFullSmartCard"); }
	if(EnrollmentNoRevocationInfoInCerts & dwFlags) { internal_printf(" EnrollmentNoRevocationInfoInCerts"); }
	if(EnrollmentIncludeBasicConstraintsForEECerts & dwFlags) { internal_printf(" EnrollmentIncludeBasicConstraintsForEECerts"); }
	internal_printf("\n");	
	OLEAUT32$VariantClear(&varProperty);

	// Get the TemplatePropSubjectNameFlags
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropSubjectNameFlags, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropSubjectNameFlags)", hr);
	dwFlags = varProperty.intVal;
	internal_printf("    Name Flags               :");
	if(SubjectNameEnrolleeSupplies & dwFlags) { internal_printf(" SubjectNameEnrolleeSupplies"); }
	if(SubjectNameRequireDirectoryPath & dwFlags) { internal_printf(" SubjectNameRequireDirectoryPath"); }
	if(SubjectNameRequireCommonName & dwFlags) { internal_printf(" SubjectNameRequireCommonName"); }
	if(SubjectNameRequireEmail & dwFlags) { internal_printf(" SubjectNameRequireEmail"); }
	if(SubjectNameRequireDNS & dwFlags) { internal_printf(" SubjectNameRequireDNS"); }
	if(SubjectNameAndAlternativeNameOldCertSupplies & dwFlags) { internal_printf(" SubjectNameAndAlternativeNameOldCertSupplies"); }
	if(SubjectAlternativeNameEnrolleeSupplies & dwFlags) { internal_printf(" SubjectAlternativeNameEnrolleeSupplies"); }
	if(SubjectAlternativeNameRequireDirectoryGUID & dwFlags) { internal_printf(" SubjectAlternativeNameRequireDirectoryGUID"); }
	if(SubjectAlternativeNameRequireUPN & dwFlags) { internal_printf(" SubjectAlternativeNameRequireUPN"); }
	if(SubjectAlternativeNameRequireEmail & dwFlags) { internal_printf(" SubjectAlternativeNameRequireEmail"); }
	if(SubjectAlternativeNameRequireSPN & dwFlags) { internal_printf(" SubjectAlternativeNameRequireSPN"); }
	if(SubjectAlternativeNameRequireDNS & dwFlags) { internal_printf(" SubjectAlternativeNameRequireDNS"); }
	if(SubjectAlternativeNameRequireDomainDNS & dwFlags) { internal_printf(" SubjectAlternativeNameRequireDomainDNS"); }
	internal_printf("\n");
	OLEAUT32$VariantClear(&varProperty);

	// Get the TemplatePropRASignatureCount
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropRASignatureCount, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropRASignatureCount)", hr);
	internal_printf("    Signatures Requred       : %d\n", varProperty.intVal);
	OLEAUT32$VariantClear(&varProperty);

	// Get the TemplatePropEKUs
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropEKUs, &varProperty);
	internal_printf("    Extended Key Usages      :\n");
	hr = _adcs_get_TemplateExtendedKeyUsages(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_TemplateExtendedKeyUsages", hr);
	OLEAUT32$VariantClear(&varProperty);

	// Get the TemplatePropSecurityDescriptor
	hr = pTemplate->lpVtbl->get_Property(pTemplate,	TemplatePropSecurityDescriptor, &varProperty);
	CHECK_RETURN_FAIL("pTemplate->lpVtbl->get_Property(TemplatePropSecurityDescriptor)", hr);
	internal_printf("    Permissions              :\n");
	hr = _adcs_get_TemplateSecurity(varProperty.bstrVal);
	CHECK_RETURN_FAIL("_adcs_get_TemplateSecurity", hr);

	hr = S_OK;

	//internal_printf("\n _adcs_get_Template SUCCESS.\n");

fail:

	OLEAUT32$VariantClear(&varProperty);
	SAFE_RELEASE(pTemplate);
	SAFE_RELEASE(pPkcs);

	return hr;
} // end _adcs_get_Template


HRESULT _adcs_get_TemplateExtendedKeyUsages(VARIANT* lpvarExtendedKeyUsages)
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

	//internal_printf("\n _adcs_get_TemplateExtendedKeyUsages SUCCESS.\n");

fail:

	OLEAUT32$VariantClear(&var);

	return hr;
} // end _adcs_get_TemplateExtendedKeyUsages


HRESULT _adcs_get_TemplateSecurity(BSTR bstrDacl)
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

	//internal_printf("\n _adcs_get_TemplateSecurity SUCCESS.\n");

fail:

	SAFE_LOCAL_FREE(swzStringSid);
	SAFE_LOCAL_FREE(pSD);

	return hr;
} // end _adcs_get_TemplateSecurity


