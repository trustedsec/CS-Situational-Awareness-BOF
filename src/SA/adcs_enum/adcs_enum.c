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
typedef HRESULT WINAPI (*CAGetCertTypeAccessRights_t)(IN LPVOID hCertType, IN DWORD dwContext, OUT DWORD *pdwAccessRights);
#define CERTCLI$CAGetCertTypeAccessRights ((CAGetCertTypeAccessRights_t)DynamicLoad("CERTCLI$CAGetCertTypeAccessRights"))
typedef HRESULT WINAPI (*CAGetAccessRights_t)(IN LPVOID hCAInfo, IN DWORD dwContext, OUT DWORD *pdwAccessRights);
#define CERTCLI$CAGetAccessRights ((CAGetAccessRights_t)DynamicLoad("CERTCLI$CAGetAccessRights"))

#endif



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
#define SAFE_CERTFREECERTIFICATECHAIN( cert_chain_context ) \
	if(cert_chain_context) \
	{ \
		CRYPT32$CertFreeCertificateChain(cert_chain_context); \
		cert_chain_context = NULL; \
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

#define DEFINE_MY_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }

DEFINE_MY_GUID(CertificateEnrollment,0x0e10c968,0x78fb,0x11d2,0x90,0xd4,0x00,0xc0,0x4f,0x79,0xdc,0x55);
DEFINE_MY_GUID(CertificateAutoEnrollment,0xa05b8cc2,0x17bc,0x4802,0xa7,0x10,0xe7,0xc1,0x5a,0xb8,0x66,0xa2);
DEFINE_MY_GUID(CertificateAll,0x00000000,0x0000,0x0000,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
DEFINE_MY_GUID(ManageCA,0x05000000,0x0015,0x0000,0xf9,0xbf,0xaa,0x22,0x07,0x95,0x8d,0xdd);


HRESULT adcs_enum()
{
	HRESULT	hr = S_OK;

	HCAINFO hCAInfo = NULL;
	HCAINFO hCAInfoNext = NULL;

	// get the first CA in the domain
	//hr = CERTCLI$CAEnumFirstCA( NULL, CA_FIND_INCLUDE_UNTRUSTED|CA_FIND_LOCAL_SYSTEM, &hCAInfoNext );
	hr = CERTCLI$CAEnumFirstCA( NULL, 0, &hCAInfoNext );
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
		internal_printf("\n[*] Listing info for %S\n\n", CERTCLI$CAGetDN(hCAInfo));

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
	hr = CERTCLI$CAGetCAProperty( hCAInfo, CA_PROP_NAME, &awszPropertyValue );
	CHECK_RETURN_FAIL(L"CAGetCAProperty(CA_PROP_NAME)", hr)
	internal_printf("  Enterprise CA Name        : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	dwPropertyValueIndex = 0;

	// dns name of the machine
	hr = CERTCLI$CAGetCAProperty( hCAInfo, CA_PROP_DNSNAME, &awszPropertyValue );
	CHECK_RETURN_FAIL(L"CAGetCAProperty(CA_PROP_DNSNAME)", hr);
	internal_printf("  DNS Hostname              : %S\n", awszPropertyValue[dwPropertyValueIndex]);
	SAFE_CAFREECAPROPERTY( hCAInfo, awszPropertyValue )
	dwPropertyValueIndex = 0;

	// flags
	hr = CERTCLI$CAGetCAFlags( hCAInfo, &dwFlags );
	CHECK_RETURN_FAIL(L"CAGetCAFlags", hr)
	internal_printf("  Flags                     :");
	if(CA_FLAG_NO_TEMPLATE_SUPPORT & dwFlags) { internal_printf(" NO_TEMPLATE_SUPPORT"); }
	if(CA_FLAG_SUPPORTS_NT_AUTHENTICATION & dwFlags) { internal_printf(" SUPPORTS_NT_AUTHENTICATION"); }
	if(CA_FLAG_CA_SUPPORTS_MANUAL_AUTHENTICATION & dwFlags) { internal_printf(" CA_SUPPORTS_MANUAL_AUTHENTICATION"); }
	if(CA_FLAG_CA_SERVERTYPE_ADVANCED & dwFlags) { internal_printf(" CA_SERVERTYPE_ADVANCED"); }
	internal_printf("\n");

	// expiration
	hr = CERTCLI$CAGetCAExpiration( hCAInfo, &dwExpiration, &dwUnits );
	CHECK_RETURN_FAIL(L"CAGetCAExpiration", hr)
	internal_printf("  Expiration                : %lu", dwExpiration);
	if (CA_UNITS_DAYS == dwUnits) { internal_printf(" days\n"); }
	else if (CA_UNITS_WEEKS == dwUnits) { internal_printf(" weeks\n"); }
	else if (CA_UNITS_MONTHS == dwUnits) { internal_printf(" months\n"); }
	else if (CA_UNITS_YEARS == dwUnits) { internal_printf(" years\n"); }

	// certificate
	hr = CERTCLI$CAGetCACertificate( hCAInfo, &pCert );
	CHECK_RETURN_FAIL(L"CAGetCACertificate", hr);
	internal_printf("  CA Cert                   :\n");
	hr = adcs_enum_cert(pCert);
	CHECK_RETURN_FAIL(L"adcs_enum_cert", hr);

	// permissions
	hr = CERTCLI$CAGetCASecurity( hCAInfo, &pSD );
	CHECK_RETURN_FAIL(L"CAGetCASecurity", hr);
	internal_printf("  Permissions               :\n");
	hr = adcs_enum_ca_permissions(pSD);
	CHECK_RETURN_FAIL(L"adcs_enum_ca_permissions", hr);

	// get the first template on the CA
	hr = CERTCLI$CAEnumCertTypesForCA(hCAInfo, CT_ENUM_MACHINE_TYPES|CT_ENUM_USER_TYPES|CT_FLAG_NO_CACHE_LOOKUP, &hCertTypeNext);
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
	SAFE_LOCAL_FREE(pSD);

	// free CertTypes
	SAFE_CACLOSECERTTYPE( hCertType )
	SAFE_CACLOSECERTTYPE( hCertTypeNext )

	return hr;
}


HRESULT adcs_enum_cert(PCCERT_CONTEXT pCert)
{
	HRESULT hr = S_OK;
	BOOL bReturn = TRUE;
	DWORD dwStrType = CERT_X500_NAME_STR;
	LPWSTR swzNameString = NULL;
	DWORD cchNameString = 0;
	PBYTE lpThumbprint = NULL;
	DWORD cThumbprint = 0;
	SYSTEMTIME systemTime;
	CERT_CHAIN_PARA chainPara;
	PCCERT_CHAIN_CONTEXT pCertChainContext = NULL;

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
	internal_printf("    Subject Name            : %S\n", swzNameString);
	SAFE_INT_FREE(swzNameString);

	// thumbprint
	CRYPT32$CertGetCertificateContextProperty( pCert, CERT_SHA1_HASH_PROP_ID, lpThumbprint, &cThumbprint );
	lpThumbprint = intAlloc(cThumbprint);
	CHECK_RETURN_NULL("intAlloc()", lpThumbprint, hr);
	bReturn = CRYPT32$CertGetCertificateContextProperty( pCert, CERT_SHA1_HASH_PROP_ID, lpThumbprint, &cThumbprint );
	CHECK_RETURN_FALSE("CertGetCertificateContextProperty(CERT_SHA1_HASH_PROP_ID)", bReturn, hr);
	internal_printf("    Thumbprint              : ");
	for(DWORD i=0; i<cThumbprint; i++)
	{
		internal_printf("%02x", lpThumbprint[i]);
	}
	internal_printf("\n");
	SAFE_INT_FREE(lpThumbprint);

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
	bReturn = CRYPT32$CertGetCertificateChain( NULL, pCert, NULL, NULL, &chainPara, 0, NULL, &pCertChainContext );
	CHECK_RETURN_FALSE("CertGetCertificateChain()", bReturn, hr);
	internal_printf("    Chain                   :");
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

fail:

	SAFE_CERTFREECERTIFICATECHAIN(pCertChainContext);
	SAFE_INT_FREE(swzNameString);
	SAFE_INT_FREE(lpThumbprint);

	return hr;
}


HRESULT adcs_enum_ca_permissions(PSECURITY_DESCRIPTOR pSD)
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

	// Get the owner
	bReturn = ADVAPI32$GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted);
	CHECK_RETURN_FALSE("GetSecurityDescriptorOwner()", bReturn, hr);
	internal_printf("    Owner                   : ");
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
				if (FALSE == ADVAPI32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	))
				{ continue; }

				internal_printf("        Principal           : %S\\%S\n", swzDomainName, swzName);
				internal_printf("          Access mask       : %08X\n", pAceObject->Mask);
				internal_printf("          Flags             : %08X\n", pAceObject->Flags);
					
				// Check if Enrollment permission
				if (ADS_RIGHT_DS_CONTROL_ACCESS & pAceObject->Mask)
				{
					if (ACE_OBJECT_TYPE_PRESENT & pAceObject->Flags)
					{
						OLECHAR szGuid[MAX_PATH];
						if ( OLE32$StringFromGUID2(&pAceObject->ObjectType, szGuid, MAX_PATH) )
						{
							internal_printf("          Extended right    : %S\n", szGuid);
						}
						if (
							IsEqualGUID(&CertificateEnrollment, &pAceObject->ObjectType) ||
							IsEqualGUID(&CertificateAutoEnrollment, &pAceObject->ObjectType) ||
							IsEqualGUID(&CertificateAll, &pAceObject->ObjectType)
							)
						{
							internal_printf("                              Enrollment Rights\n");
						}
						else if (
							IsEqualGUID(&ManageCA, &pAceObject->ObjectType)
							)
						{
							internal_printf("                              ManageCA Rights\n");
						}
					} // end if ACE_OBJECT_TYPE_PRESENT
				} // end if ADS_RIGHT_DS_CONTROL_ACCESS
				
				// Check if ADS_RIGHT_GENERIC_ALL permission
				if (ADS_RIGHT_GENERIC_ALL & pAceObject->Mask)
				{
					internal_printf("                              All Rights\n");
				} // end if ADS_RIGHT_GENERIC_ALL permission
				
				// Check if ADS_RIGHT_READ_CONTROL permission
				if ( 
					(ADS_RIGHT_READ_CONTROL & pAceObject->Mask)
				)
				{
					internal_printf("                              Read Rights\n");
				} // end if ADS_RIGHT_READ_CONTROL permission
				

			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)

		hr = S_OK;
	} // end else GetAclInformation was successful


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
	PSECURITY_DESCRIPTOR pSD = NULL;
	CHAR szEKU[MAX_PATH];
	

	// Common name of the certificate type
	hr = CERTCLI$CAGetCertTypeProperty( hCertType, CERTTYPE_PROP_CN, &awszPropertyValue );
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
	hr = CERTCLI$CAGetCertTypeExpiration( hCertType, &ftExpiration, &ftOverlap );
	CHECK_RETURN_FAIL(L"CAGetCertTypeExpiration()", hr);
	hr = CERTCLI$caTranslateFileTimePeriodToPeriodUnits( &ftExpiration, TRUE, &cPeriodUnits, (LPVOID*)(&prgPeriodUnits) );
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
	hr = CERTCLI$caTranslateFileTimePeriodToPeriodUnits( &ftOverlap, TRUE, &cPeriodUnits, (LPVOID*)(&prgPeriodUnits) );
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

	// Name Flags
	hr = CERTCLI$CAGetCertTypeFlagsEx( hCertType, CERTTYPE_SUBJECT_NAME_FLAG, &dwPropertyValue );
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
	hr = CERTCLI$CAGetCertTypeFlagsEx( hCertType, CERTTYPE_ENROLLMENT_FLAG, &dwPropertyValue );
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
	hr = CERTCLI$CAGetCertTypePropertyEx( hCertType, CERTTYPE_PROP_RA_SIGNATURE, (LPVOID)(&dwPropertyValue) );
	CHECK_RETURN_FAIL(L"CAGetCertTypeProperty(CERTTYPE_PROP_RA_SIGNATURE)", hr)
	internal_printf("    Signatures Required     : %lu\n", dwPropertyValue);
	dwPropertyValue = 0;

	// An array of extended key usage OIDs for a cert type
	hr = CERTCLI$CAGetCertTypeProperty( hCertType, CERTTYPE_PROP_EXTENDED_KEY_USAGE, &awszPropertyValue );
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
	if ( (NULL == awszPropertyValue) || (NULL == awszPropertyValue[dwPropertyValueIndex]) ) 
	{ 
		internal_printf(" N/A"); 
	}
	else
	{
		while(awszPropertyValue[dwPropertyValueIndex])
		{
			MSVCRT$memset(szEKU, 0, MAX_PATH);
			MSVCRT$sprintf(szEKU, "%S", awszPropertyValue[dwPropertyValueIndex]);
			PCCRYPT_OID_INFO pCryptOidInfo = CRYPT32$CryptFindOIDInfo( CRYPT_OID_INFO_OID_KEY, szEKU, 0 );
			if (0!=dwPropertyValueIndex) { internal_printf(","); }
			if (pCryptOidInfo) { internal_printf(" %S", pCryptOidInfo->pwszName); }
			else { internal_printf(" %S", awszPropertyValue[dwPropertyValueIndex]); }
			dwPropertyValueIndex++;
		}
	}
	internal_printf("\n");
	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)
	dwPropertyValueIndex = 0;

	// permissions
	hr = CERTCLI$CACertTypeGetSecurity( hCertType, &pSD );
	CHECK_RETURN_FAIL(L"CACertTypeGetSecurity", hr);
	internal_printf("    Permissions             :\n");
	hr = adcs_enum_cert_type_permissions(pSD);
	CHECK_RETURN_FAIL(L"adcs_enum_cert_type_permissions", hr);

	internal_printf("\n");

fail:

	// free security descriptor
	SAFE_LOCAL_FREE(pSD);

	SAFE_CAFREECERTTYPEPROPERTY(hCertType, awszPropertyValue)

	return hr;
}

HRESULT adcs_enum_cert_type_permissions(PSECURITY_DESCRIPTOR pSD)
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


	// Get the owner
	bReturn = ADVAPI32$GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted);
	CHECK_RETURN_FALSE("CertGetCertificateChain()", bReturn, hr);
	internal_printf("      Owner                 : ");
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

				if (ACCESS_ALLOWED_OBJECT_ACE_TYPE == pAceHeader->AceType) { pPrincipalSid = (PSID)(&(pAceObject->InheritedObjectType)); }
				else if (ACCESS_ALLOWED_ACE_TYPE == pAceHeader->AceType) { pPrincipalSid = (PSID)(&(pAce->SidStart)); }
				else { continue; }

				// Get the principal
				cchName = MAX_PATH;
				MSVCRT$memset(swzName, 0, cchName*sizeof(WCHAR));
				cchDomainName = MAX_PATH;
				MSVCRT$memset(swzDomainName, 0, cchDomainName*sizeof(WCHAR));
				if (FALSE == ADVAPI32$LookupAccountSidW( NULL, pPrincipalSid, swzName, &cchName, swzDomainName,	&cchDomainName,	&sidNameUse	))
				{ continue; }
				
				internal_printf("        Principal           : %S\\%S\n", swzDomainName, swzName);
				internal_printf("          Access mask       : %08X\n", pAceObject->Mask);
				internal_printf("          Flags             : %08X\n", pAceObject->Flags);
					
				// Check if Enrollment permission
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
							internal_printf("                              Enrollment Rights\n");
						}
					} // end if ACE_OBJECT_TYPE_PRESENT
				} // end if ADS_RIGHT_DS_CONTROL_ACCESS
				
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
				
				// Check if ADS_RIGHT_DS_WRITE_PROP permission
				if ( 
					(ADS_RIGHT_GENERIC_WRITE & pAceObject->Mask) ||
					(ADS_RIGHT_DS_WRITE_PROP & pAceObject->Mask)
				)
				{
					internal_printf("                              WriteProperty Rights\n");
				} // end if ADS_RIGHT_DS_WRITE_PROP permission
				
			} // end if GetAce was successful
		} // end for loop through ACEs (AceCount)

		hr = S_OK;
	} // end else GetAclInformation was successful

	
fail:

	return hr;
}