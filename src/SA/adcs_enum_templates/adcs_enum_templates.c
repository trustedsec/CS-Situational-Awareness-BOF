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
#include "adcs_enum_templates.h"

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
		CHECK_RETURN_FAIL("_adcs_get_CertificateTemplate()", hr);
	} // end for loop through ITemplates

	hr = S_OK;

fail:

	SAFE_RELEASE(pCertificateTemplate);
	SAFE_RELEASE(pCertificateTemplates);
	SAFE_RELEASE(pEnrollmentPolicyServer);

	return hr;
}


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
	hr = _adcs_get_ExtendedKeyUsages(&varProperty);
	CHECK_RETURN_FAIL("_adcs_get_ExtendedKeyUsages", hr);
	
	// Get the TemplatePropKeySecurityDescriptor
	OLEAUT32$VariantClear(&varProperty);
	pCertificateTemplate->lpVtbl->get_Property(pCertificateTemplate, TemplatePropKeySecurityDescriptor, &varProperty);
	CHECK_RETURN_FAIL("pCertificateTemplate->lpVtbl->get_Property(TemplatePropKeySecurityDescriptor)", hr);
	internal_printf("    Permissions              :\n");
	hr = _adcs_get_Security(varProperty.bstrVal);
	CHECK_RETURN_FAIL("_adcs_get_Security", hr);
	
	hr = S_OK;

fail:

	OLEAUT32$VariantClear(&varProperty);

	return hr;
}


HRESULT _adcs_get_ExtendedKeyUsages(VARIANT* lpvarExtendedKeyUsages)
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
	
	if (NULL == lpvarExtendedKeyUsages->pdispVal)
	{
		internal_printf("      %S\n", STR_NOT_AVAILALBE);
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
			if (FAILED(hr))	{ internal_printf("      %S\n", STR_NOT_AVAILALBE); }
			else { internal_printf("      %S\n", bstFriendlyName); }

			SAFE_RELEASE(pObjectId);
		}
		OLEAUT32$VariantClear(&var);

		hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &lFetch);
	} // end loop through IObjectIds via enumerator
	SAFE_RELEASE(pObjectId);

	hr = S_OK;

fail:

	OLEAUT32$VariantClear(&var);

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


HRESULT adcs_enum_templates()
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
