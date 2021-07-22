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
#include <wincrypt.h>
#include "certca.h"
#include "beacon.h"
#include "bofdefs.h"
#include "adcs_enum.h"


#ifndef BOF
FARPROC DynamicLoad(const char* szBOFfunc)
{
    FARPROC fp = NULL;
    CHAR szLibrary[MAX_PATH];
    CHAR szFunction[MAX_PATH];
    CHAR * pchDivide = NULL;
    HMODULE hLibrary = NULL;

    MSVCRT$memset(szLibrary,0,MAX_PATH);
    MSVCRT$memset(szFunction,0,MAX_PATH);
    MSVCRT$strcpy(szLibrary,szBOFfunc);
    pchDivide = MSVCRT$strchr(szLibrary, '$');
    pchDivide[0] = '\0';
    pchDivide = MSVCRT$strchr(szBOFfunc, '$');
    pchDivide++;
    MSVCRT$strcpy(szFunction, pchDivide);
    hLibrary = KERNEL32$LoadLibraryA(szLibrary);
    if (hLibrary)
    {
        fp = KERNEL32$GetProcAddress(hLibrary,szFunction);
        KERNEL32$FreeLibrary(hLibrary);
    }
    return fp;
}
typedef HRESULT WINAPI (*caTranslateFileTimePeriodToPeriodUnits_t)(IN FILETIME const *pftGMT, IN BOOL Flags, OUT DWORD *pcPeriodUnits, OUT LPVOID*prgPeriodUnits);
#define CERTCLI$caTranslateFileTimePeriodToPeriodUnits ((caTranslateFileTimePeriodToPeriodUnits_t)DynamicLoad("CERTCLI$caTranslateFileTimePeriodToPeriodUnits"))
#endif




#define CHECK_RETURN_FAIL( function, result ) \
	if (FAILED(result)) \
	{ \
		BeaconPrintf(CALLBACK_ERROR, "%S failed: 0x%08lx\n", function, result); \
		goto fail; \
	}
#define SAFE_CAFREECAPROPERTY( handle_ca, pointer_capropertyvaluearray ) \
	if (pointer_capropertyvaluearray) \
	{ \
		CERTCLI$CAFreeCAProperty(handle_ca, pointer_capropertyvaluearray); \
		pointer_capropertyvaluearray = NULL; \
	}
#define SAFE_CACLOSECA( handle_ca ) \
	if (handle_ca) \
	{ \
		CERTCLI$CACloseCA(handle_ca); \
		handle_ca = NULL; \
	}	
#define SAFE_CAFREECERTTYPEPROPERTY( handle_certtype, pointer_ctpropertyvaluearray ) \
	if (pointer_ctpropertyvaluearray) \
	{ \
		CERTCLI$CAFreeCertTypeProperty(handle_certtype, pointer_ctpropertyvaluearray); \
		pointer_ctpropertyvaluearray = NULL; \
	}
#define SAFE_CACLOSECERTTYPE( handle_certtype ) \
	if (handle_certtype) \
	{ \
		CERTCLI$CACloseCertType(handle_certtype); \
		handle_certtype = NULL; \
	}



HRESULT adcs_enum()
{
	HRESULT	hr = S_OK;

	HCAINFO hCAInfo = NULL;
	HCAINFO hCAInfoNext = NULL;

	// get the first CA in the domain
	hr = CERTCLI$CAEnumFirstCA( 
		NULL, 
		CA_FIND_INCLUDE_UNTRUSTED|CA_FIND_LOCAL_SYSTEM,
		&hCAInfoNext
	);
	CHECK_RETURN_FAIL(L"CAEnumFirstCA", hr)

	// CountCAs
	if (NULL == hCAInfoNext)
	{
		internal_printf("\n[*] Found 0 CAs in the domain\n");
		goto fail;
	}
	internal_printf("\n[*] Found %lu CAs in the domain\n", CERTCLI$CACountCAs(hCAInfoNext));

	// loop through CAs in the domain
	while (hCAInfoNext)
	{
		// free previous CA
		SAFE_CACLOSECA( hCAInfo );
		hCAInfo = hCAInfoNext;
		hCAInfoNext = NULL;

		// distinguished name
		internal_printf("\n[*] Listing info for %S\n", CERTCLI$CAGetDN(hCAInfo));

		// list info for current CA
		hr = adcs_enum_ca(hCAInfo);
		CHECK_RETURN_FAIL(L"adcs_enum_ca", hr)

		// get the next CA in the domain
		hr = CERTCLI$CAEnumNextCA(hCAInfo, &hCAInfoNext);
		CHECK_RETURN_FAIL(L"CAEnumNextCA", hr)
	} // end loop through CAs in the domain
	
	hr = S_OK;

fail:

	// free CA
	SAFE_CACLOSECA( hCAInfo )
	SAFE_CACLOSECA( hCAInfoNext )

	return hr;
}


HRESULT adcs_enum_ca(HCAINFO hCAInfo)
{
	HRESULT hr = S_OK;
	PZPWSTR awszPropertyValue = NULL;
	DWORD dwPropertyValueIndex = 0;
	DWORD dwFlags = 0;
	DWORD dwExpiration = 0;
	DWORD dwUnits = 0;
	PCCERT_CONTEXT pCert = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	HCERTTYPE hCertType = NULL;
	HCERTTYPE hCertTypeNext = NULL;

	// simple name of the CA
	hr = CERTCLI$CAGetCAProperty(
		hCAInfo,
		CA_PROP_NAME,
		&awszPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCAProperty(CA_PROP_NAME)", hr)
	internal_printf("  Enterprise CA Name        : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	dwPropertyValueIndex = 0;

	// dns name of the machine
	hr = CERTCLI$CAGetCAProperty(
		hCAInfo,
		CA_PROP_DNSNAME,
		&awszPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCAProperty(CA_PROP_DNSNAME)", hr);
	internal_printf("  DNS Hostname              : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	dwPropertyValueIndex = 0;

	// flags
	hr = CERTCLI$CAGetCAFlags(
		hCAInfo,
		&dwFlags
	);
	CHECK_RETURN_FAIL(L"CAGetCAFlags", hr)
	internal_printf("  Flags                     :");
	if(CA_FLAG_NO_TEMPLATE_SUPPORT & dwFlags) { internal_printf(" NO_TEMPLATE_SUPPORT"); }
	if(CA_FLAG_SUPPORTS_NT_AUTHENTICATION & dwFlags) { internal_printf(" SUPPORTS_NT_AUTHENTICATION"); }
	if(CA_FLAG_CA_SUPPORTS_MANUAL_AUTHENTICATION & dwFlags) { internal_printf(" CA_SUPPORTS_MANUAL_AUTHENTICATION"); }
	if(CA_FLAG_CA_SERVERTYPE_ADVANCED & dwFlags) { internal_printf(" CA_SERVERTYPE_ADVANCED"); }
	internal_printf("\n");

	// expiration
	hr = CERTCLI$CAGetCAExpiration(
		hCAInfo,
		&dwExpiration,
		&dwUnits
	);
	CHECK_RETURN_FAIL(L"CAGetCAExpiration", hr)
	internal_printf("  Expiration                : %lu", dwExpiration);
	if (CA_UNITS_DAYS == dwUnits) { internal_printf(" days\n"); }
	else if (CA_UNITS_WEEKS == dwUnits) { internal_printf(" weeks\n"); }
	else if (CA_UNITS_MONTHS == dwUnits) { internal_printf(" months\n"); }
	else if (CA_UNITS_YEARS == dwUnits) { internal_printf(" years\n"); }


	// certificate
	hr = CERTCLI$CAGetCACertificate(
		hCAInfo,
		&pCert
	);
	CHECK_RETURN_FAIL(L"CAGetCACertificate", hr);
	internal_printf("  CA Cert                   :\n");
	hr = adcs_enum_cert(pCert);
	CHECK_RETURN_FAIL(L"adcs_enum_cert", hr);


	// permissions
	hr = CERTCLI$CAGetCASecurity(
		hCAInfo,
		&pSD
	);
	CHECK_RETURN_FAIL(L"CAGetCASecurity", hr);
	internal_printf("  Permissions               :\n");
	hr = adcs_enum_cert_permissions(pSD);
	CHECK_RETURN_FAIL(L"adcs_enum_cert_permissions", hr);

	// get the first template on the CA
	hr = CERTCLI$CAEnumCertTypesForCA( 
		hCAInfo, 
		CT_ENUM_MACHINE_TYPES|CT_ENUM_USER_TYPES|CT_FLAG_NO_CACHE_LOOKUP,
		&hCertTypeNext
	);
	CHECK_RETURN_FAIL(L"CAEnumCertTypesForCA", hr)

	// CountCertTypes
	if (NULL == hCertTypeNext)
	{
		internal_printf("\n  [*] Found 0 templates on the ca\n");
		goto fail;
	}
	internal_printf("\n  [*] Found %lu templates on the ca\n\n", CERTCLI$CACountCertTypes(hCertTypeNext));

	// loop through templates on the CA
	while (hCertTypeNext)
	{
		// free previous template
		SAFE_CACLOSECERTTYPE( hCertType );
		hCertType = hCertTypeNext;
		hCertTypeNext = NULL;

		// list info for current template
		hr = adcs_enum_cert_type(hCertType);
		CHECK_RETURN_FAIL(L"adcs_enum_cert_type", hr);

		// get the next template on the CA
		hr = CERTCLI$CAEnumNextCertType(hCertType, &hCertTypeNext);
		CHECK_RETURN_FAIL(L"CAEnumNextCertType", hr);
	} // end loop through templates on the CA
	

fail:


	// free CA property
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )

	// free certificate
	if (pCert)
	{
		CRYPT32$CertFreeCertificateContext(pCert);
		pCert = NULL;
	}

	// free security descriptor
	if (pSD)
	{
		KERNEL32$LocalFree(pSD);
		pSD = NULL;
	}

	// free CertTypes
	SAFE_CACLOSECERTTYPE( hCertType )
	SAFE_CACLOSECERTTYPE( hCertTypeNext )

	return hr;
}


HRESULT adcs_enum_cert(PCCERT_CONTEXT pCert)
{
	HRESULT hr = S_OK;
	DWORD dwStrType = CERT_X500_NAME_STR;
	LPWSTR swzNameString = NULL;
	DWORD cchNameString = 0;
	PBYTE lpThumbprint = NULL;
	DWORD cThumbprint = 0;
	SYSTEMTIME systemTime;
	CERT_CHAIN_PARA chainPara;
	PCCERT_CHAIN_CONTEXT pCertChainContext = NULL;


	// subject name
	cchNameString = CRYPT32$CertGetNameStringW(
		pCert,
		CERT_NAME_RDN_TYPE,
		0,
		&dwStrType,
		swzNameString,
		cchNameString
	);
	swzNameString = intAlloc(cchNameString*sizeof(WCHAR));
	if ( NULL == swzNameString )
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "intAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}
	if (1 == CRYPT32$CertGetNameStringW(
		pCert,
		CERT_NAME_RDN_TYPE,
		0,
		&dwStrType,
		swzNameString,
		cchNameString
		)
	)
	{
		hr = E_UNEXPECTED;
		BeaconPrintf(CALLBACK_ERROR, "CertGetNameStringW failed: 0x%08lx\n", hr);
		goto fail;
	}
	internal_printf("    Subject Name            : %S\n", swzNameString);
	if (swzNameString)
	{
		intFree(swzNameString);
		swzNameString = NULL;
	}

	// thumbprint
	CRYPT32$CertGetCertificateContextProperty(
		pCert,
		CERT_SHA1_HASH_PROP_ID,
		lpThumbprint,
		&cThumbprint
	);
	lpThumbprint = intAlloc(cThumbprint);
	if ( NULL == lpThumbprint )
	{
		hr = E_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "intAlloc failed: 0x%08lx\n", hr);
		goto fail;
	}
	if (FALSE == CRYPT32$CertGetCertificateContextProperty(
		pCert,
		CERT_SHA1_HASH_PROP_ID,
		lpThumbprint,
		&cThumbprint
		)
	)
	{
		hr = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "CertGetCertificateContextProperty(CERT_SHA1_HASH_PROP_ID) failed: 0x%08lx\n", hr);
		goto fail;
	}
	internal_printf("    Thumbprint              : ");
	for(DWORD i=0; i<cThumbprint; i++)
	{
		internal_printf("%02x", lpThumbprint[i]);
	}
	internal_printf("\n");
	if (lpThumbprint)
	{
		intFree(lpThumbprint);
		lpThumbprint = NULL;
	}

	// serial number
	internal_printf("    Serial Number           : ");
	for(DWORD i=0; i<pCert->pCertInfo->SerialNumber.cbData; i++)
	{
		internal_printf("%02x", pCert->pCertInfo->SerialNumber.pbData[i]);
	}
	internal_printf("\n");

	// start date
	MSVCRT$memset(&systemTime, 0, sizeof(SYSTEMTIME));
	KERNEL32$FileTimeToSystemTime(&(pCert->pCertInfo->NotBefore), &systemTime);
	internal_printf("    Start Date              : %hu/%hu/%hu %02hu:%02hu:%02hu\n", systemTime.wMonth, systemTime.wDay, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

	// end date
	MSVCRT$memset(&systemTime, 0, sizeof(SYSTEMTIME));
	KERNEL32$FileTimeToSystemTime(&(pCert->pCertInfo->NotAfter), &systemTime);
	internal_printf("    End Date                : %hu/%hu/%hu %02hu:%02hu:%02hu\n", systemTime.wMonth, systemTime.wDay, systemTime.wYear, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

	// chain
	chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	chainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
	chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;
	if (FALSE == CRYPT32$CertGetCertificateChain(
			NULL,
			pCert,
			NULL,
			NULL,
			&chainPara,
			0,
			NULL,
			&pCertChainContext
		) 
	)
	{
		hr = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "CertGetCertificateChain() failed: 0x%08lx\n", hr);
		goto fail;
	}
	internal_printf("    Chain                   :");
	for(DWORD i=0; i<pCertChainContext->cChain; i++)
	{
		for(DWORD j=0; j<pCertChainContext->rgpChain[i]->cElement; j++)
		{
			PCCERT_CONTEXT pChainCertContext = pCertChainContext->rgpChain[i]->rgpElement[j]->pCertContext;
			// subject name
			cchNameString = CRYPT32$CertGetNameStringW(
				pChainCertContext,
				CERT_NAME_RDN_TYPE,
				0,
				&dwStrType,
				swzNameString,
				cchNameString
			);
			swzNameString = intAlloc(cchNameString*sizeof(WCHAR));
			if ( NULL == swzNameString )
			{
				hr = E_OUTOFMEMORY;
				BeaconPrintf(CALLBACK_ERROR, "intAlloc failed: 0x%08lx\n", hr);
				goto fail;
			}
			if (1 == CRYPT32$CertGetNameStringW(
				pChainCertContext,
				CERT_NAME_RDN_TYPE,
				0,
				&dwStrType,
				swzNameString,
				cchNameString
				)
			)
			{
				hr = E_UNEXPECTED;
				BeaconPrintf(CALLBACK_ERROR, "CertGetNameStringW failed: 0x%08lx\n", hr);
				goto fail;
			}
			if (j!=0) { internal_printf(" >>"); }
			internal_printf(" %S", swzNameString);
			if (swzNameString)
			{
				intFree(swzNameString);
				swzNameString = NULL;
			}
		} // end for loop through PCERT_CHAIN_ELEMENT
		internal_printf("\n");
	} // end for loop through PCERT_SIMPLE_CHAIN
	if(pCertChainContext)
	{
		CRYPT32$CertFreeCertificateChain(pCertChainContext);
		pCertChainContext = NULL;
	}

fail:

	if(pCertChainContext)
	{
		CRYPT32$CertFreeCertificateChain(pCertChainContext);
		pCertChainContext = NULL;
	}

	if (swzNameString)
	{
		intFree(swzNameString);
		swzNameString = NULL;
	}

	if (lpThumbprint)
	{
		intFree(lpThumbprint);
		lpThumbprint = NULL;
	}

	return hr;
}


HRESULT adcs_enum_cert_permissions(PSECURITY_DESCRIPTOR pSD)
{
	HRESULT hr = S_OK;

	// TODO: display permissions
	internal_printf("    Owner                   : TODO\n");

	internal_printf("    Access Rights           :\n");
	internal_printf("      ****************TODO******************\n");

fail:

	return hr;
}

HRESULT adcs_enum_cert_type(HCERTTYPE hCertType)
{
	HRESULT hr = S_OK;
	PZPWSTR awszPropertyValue = NULL;
	DWORD dwPropertyValue = 0;
	DWORD dwPropertyValueIndex = 0;
	FILETIME ftExpiration;
	FILETIME ftOverlap;
	DWORD cPeriodUnits = 0;
	PERIODUNITS * prgPeriodUnits = NULL;

	// Common name of the certificate type
	hr = CERTCLI$CAGetCertTypeProperty(
		hCertType,
		CERTTYPE_PROP_CN,
		&awszPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeProperty(CERTTYPE_PROP_CN)", hr);
	internal_printf("    Template Name           : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// The display name of a cert type retrieved from Crypt32 ( this accounts for the locale specific display names stored in OIDs)
	hr = CERTCLI$CAGetCertTypeProperty(
		hCertType,
		CERTTYPE_PROP_FRIENDLY_NAME,
		&awszPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeProperty(CERTTYPE_PROP_FRIENDLY_NAME)", hr);
	internal_printf("    Friendly Name           : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// The OID of this template
	hr = CERTCLI$CAGetCertTypeProperty(
		hCertType,
		CERTTYPE_PROP_OID,
		&awszPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeProperty(CERTTYPE_PROP_OID)", hr);
	internal_printf("    Template OID            : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// Validity Period
	MSVCRT$memset(&ftExpiration, 0, sizeof(ftExpiration));
	MSVCRT$memset(&ftOverlap, 0, sizeof(ftOverlap));
	hr = CERTCLI$CAGetCertTypeExpiration(
		hCertType,
		&ftExpiration,
		&ftOverlap
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeExpiration()", hr);
	hr = CERTCLI$caTranslateFileTimePeriodToPeriodUnits(
		&ftExpiration,
		TRUE,
		&cPeriodUnits,
		(LPVOID*)(&prgPeriodUnits)
	);
	CHECK_RETURN_FAIL(L"caTranslateFileTimePeriodToPeriodUnits()", hr);
	internal_printf("    Validity Period         : %ld ", prgPeriodUnits->lCount);
	if (ENUM_PERIOD_SECONDS == prgPeriodUnits->enumPeriod) { internal_printf("seconds"); }
	else if (ENUM_PERIOD_MINUTES == prgPeriodUnits->enumPeriod) { internal_printf("minutes"); }
	else if (ENUM_PERIOD_HOURS == prgPeriodUnits->enumPeriod) { internal_printf("hours"); }
	else if (ENUM_PERIOD_DAYS == prgPeriodUnits->enumPeriod) { internal_printf("days"); }
	else if (ENUM_PERIOD_WEEKS == prgPeriodUnits->enumPeriod) { internal_printf("weeks"); }
	else if (ENUM_PERIOD_MONTHS == prgPeriodUnits->enumPeriod) { internal_printf("months"); }
	else if (ENUM_PERIOD_YEARS == prgPeriodUnits->enumPeriod) { internal_printf("years"); }
	internal_printf("\n");
	cPeriodUnits = 0;
	prgPeriodUnits = NULL;
	hr = CERTCLI$caTranslateFileTimePeriodToPeriodUnits(
		&ftOverlap,
		TRUE,
		&cPeriodUnits,
		(LPVOID*)(&prgPeriodUnits)
	);
	CHECK_RETURN_FAIL(L"caTranslateFileTimePeriodToPeriodUnits()", hr);
	internal_printf("    Renewal Period          : %ld ", prgPeriodUnits->lCount);
	if (ENUM_PERIOD_SECONDS == prgPeriodUnits->enumPeriod) { internal_printf("seconds"); }
	else if (ENUM_PERIOD_MINUTES == prgPeriodUnits->enumPeriod) { internal_printf("minutes"); }
	else if (ENUM_PERIOD_HOURS == prgPeriodUnits->enumPeriod) { internal_printf("hours"); }
	else if (ENUM_PERIOD_DAYS == prgPeriodUnits->enumPeriod) { internal_printf("days"); }
	else if (ENUM_PERIOD_WEEKS == prgPeriodUnits->enumPeriod) { internal_printf("weeks"); }
	else if (ENUM_PERIOD_MONTHS == prgPeriodUnits->enumPeriod) { internal_printf("months"); }
	else if (ENUM_PERIOD_YEARS == prgPeriodUnits->enumPeriod) { internal_printf("years"); }
	internal_printf("\n");

	// Enrollment Flags
	hr = CERTCLI$CAGetCertTypeFlagsEx(
		hCertType,
		CERTTYPE_SUBJECT_NAME_FLAG,
		&dwPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeFlagsEx(CERTTYPE_SUBJECT_NAME_FLAG)", hr);
	internal_printf("    Name Flags              :");
	if(CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT & dwPropertyValue) { internal_printf(" ENROLLEE_SUPPLIES_SUBJECT"); }
	if(CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME & dwPropertyValue) { internal_printf(" ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"); }
	if(CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH & dwPropertyValue) { internal_printf(" SUBJECT_REQUIRE_DIRECTORY_PATH"); }
	if(CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME & dwPropertyValue) { internal_printf(" SUBJECT_REQUIRE_COMMON_NAME"); }
	if(CT_FLAG_SUBJECT_REQUIRE_EMAIL & dwPropertyValue) { internal_printf(" SUBJECT_REQUIRE_EMAIL"); }
	if(CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN & dwPropertyValue) { internal_printf(" SUBJECT_REQUIRE_DNS_AS_CN"); }
	if(CT_FLAG_SUBJECT_ALT_REQUIRE_DNS & dwPropertyValue) { internal_printf(" SUBJECT_ALT_REQUIRE_DNS"); }
	if(CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL & dwPropertyValue) { internal_printf(" SUBJECT_ALT_REQUIRE_EMAIL"); }
	if(CT_FLAG_SUBJECT_ALT_REQUIRE_UPN & dwPropertyValue) { internal_printf(" SUBJECT_ALT_REQUIRE_UPN"); }
	if(CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID & dwPropertyValue) { internal_printf(" SUBJECT_ALT_REQUIRE_DIRECTORY_GUID"); }
	if(CT_FLAG_SUBJECT_ALT_REQUIRE_SPN & dwPropertyValue) { internal_printf(" SUBJECT_ALT_REQUIRE_SPN"); }
	if(CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS & dwPropertyValue) { internal_printf(" SUBJECT_ALT_REQUIRE_DOMAIN_DNS"); }
	if(CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME & dwPropertyValue) { internal_printf(" OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"); }
	internal_printf("\n");	
	dwPropertyValue = 0;

	// Enrollment Flags
	hr = CERTCLI$CAGetCertTypeFlagsEx(
		hCertType,
		CERTTYPE_ENROLLMENT_FLAG,
		&dwPropertyValue
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeFlagsEx(CERTTYPE_ENROLLMENT_FLAG)", hr);
	internal_printf("    Enrollment Flags        :");
	if(CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS & dwPropertyValue) { internal_printf(" INCLUDE_SYMMETRIC_ALGORITHMS"); }
	if(CT_FLAG_PEND_ALL_REQUESTS & dwPropertyValue) { internal_printf(" PEND_ALL_REQUESTS"); }
	if(CT_FLAG_PUBLISH_TO_KRA_CONTAINER & dwPropertyValue) { internal_printf(" PUBLISH_TO_KRA_CONTAINER"); }
	if(CT_FLAG_PUBLISH_TO_DS & dwPropertyValue) { internal_printf(" PUBLISH_TO_DS"); }
	if(CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE & dwPropertyValue) { internal_printf(" AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"); }
	if(CT_FLAG_AUTO_ENROLLMENT & dwPropertyValue) { internal_printf(" AUTO_ENROLLMENT"); }
	if(CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT & dwPropertyValue) { internal_printf(" PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"); }
	if(CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED & dwPropertyValue) { internal_printf(" DOMAIN_AUTHENTICATION_NOT_REQUIRED"); }
	if(CT_FLAG_USER_INTERACTION_REQUIRED & dwPropertyValue) { internal_printf(" USER_INTERACTION_REQUIRED"); }
	if(CT_FLAG_ADD_TEMPLATE_NAME & dwPropertyValue) { internal_printf(" ADD_TEMPLATE_NAME"); }
	if(CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE & dwPropertyValue) { internal_printf(" REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"); }
	if(CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF & dwPropertyValue) { internal_printf(" ALLOW_ENROLL_ON_BEHALF_OF"); }
	if(CT_FLAG_ADD_OCSP_NOCHECK & dwPropertyValue) { internal_printf(" ADD_OCSP_NOCHECK"); }
	if(CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL & dwPropertyValue) { internal_printf(" ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"); }
	if(CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS & dwPropertyValue) { internal_printf(" NOREVOCATIONINFOINISSUEDCERTS"); }
	if(CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS & dwPropertyValue) { internal_printf(" INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"); }
	if(CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT & dwPropertyValue) { internal_printf(" ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"); }
	if(CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST & dwPropertyValue) { internal_printf(" ISSUANCE_POLICIES_FROM_REQUEST"); }
	if(CT_FLAG_SKIP_AUTO_RENEWAL & dwPropertyValue) { internal_printf(" SKIP_AUTO_RENEWAL"); }
	internal_printf("\n");	
	dwPropertyValue = 0;	

	// The number of RA signatures required on a request referencing this template
	hr = CERTCLI$CAGetCertTypePropertyEx(
		hCertType,
		CERTTYPE_PROP_RA_SIGNATURE,
		(LPVOID)(&dwPropertyValue)
	);
	CHECK_RETURN_FAIL(L"CAGetCertTypeProperty(CERTTYPE_PROP_RA_SIGNATURE)", hr)
	internal_printf("    Signatures Required     : %lu\n", dwPropertyValue);
	dwPropertyValue = 0;

	// An array of extended key usage OIDs for a cert type
	hr = CERTCLI$CAGetCertTypeProperty(
		hCertType,
		CERTTYPE_PROP_EXTENDED_KEY_USAGE,
		&awszPropertyValue
	);
	if (FAILED(hr))
	{
		if (CRYPT_E_NOT_FOUND != hr)
		{
			BeaconPrintf(CALLBACK_ERROR, "CAGetCertTypeProperty(CERTTYPE_PROP_EXTENDED_KEY_USAGE) failed: 0x%08lx\n", hr);
			goto fail;
		}
		else { hr = S_OK; }
	}
	internal_printf("    Extended Key Usage      :");
	if (   (NULL == awszPropertyValue)
	    || (NULL == awszPropertyValue[dwPropertyValueIndex])
	)
	{
		internal_printf(" N/A");
	}
	else
	{
		while(awszPropertyValue[dwPropertyValueIndex])
			internal_printf(" %S", awszPropertyValue[dwPropertyValueIndex++]);
	}
	internal_printf("\n");
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// TODO: display cert type permissions
	internal_printf("    Permissions             :\n");
	internal_printf("      ************ TODO ************\n");

	internal_printf("\n");

fail:

	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)

	return hr;
}
