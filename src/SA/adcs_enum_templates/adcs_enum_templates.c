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
	IX509CertificateTemplates * pCertificateTemplates = NULL;
	LONG lCertificateTemplatesCount = 0;
	IX509CertificateTemplate * pCertificateTemplate = NULL;

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

	SAFE_RELEASE(pCertificateTemplates);
	//internal_printf( "GetTemplates()\n");
	hr = pEnrollmentPolicyServer->lpVtbl->GetTemplates(
		pEnrollmentPolicyServer,
		&pCertificateTemplates
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "GetTemplates() failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}

	//internal_printf( "pCertificateTemplates->lpVtbl->get_Count()\n");
	hr = pCertificateTemplates->lpVtbl->get_Count(
		pCertificateTemplates,
		&lCertificateTemplatesCount
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplates->lpVtbl->get_Count() failed: 0x%08lx\n", hr);
		goto EnrollmentPolicyServer_fail;
	}
	//internal_printf( "lCertificateTemplatesCount: %ld\n", lCertificateTemplatesCount);
	internal_printf( "Found %ld templates\n", lCertificateTemplatesCount);

	for(LONG lCertificateTemplatesIndex=0; lCertificateTemplatesIndex<lCertificateTemplatesCount; lCertificateTemplatesIndex++)
	{
		SAFE_RELEASE(pCertificateTemplate);
		//internal_printf( "pCertificateTemplates->lpVtbl->get_ItemByIndex()\n");
		hr = pCertificateTemplates->lpVtbl->get_ItemByIndex(
			pCertificateTemplates,
			lCertificateTemplatesIndex,
			&pCertificateTemplate
		);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplates->lpVtbl->get_ItemByIndex() failed: 0x%08lx\n", hr);
			goto EnrollmentPolicyServer_fail;
		}

		hr = _adcs_get_CertificateTemplate(pCertificateTemplate);
		if (FAILED(hr))
		{
			BeaconPrintf(CALLBACK_ERROR, "_adcs_get_CertificateTemplate(pCertificateTemplate) failed: 0x%08lx\n", hr);
			goto EnrollmentPolicyServer_fail;
		}
	} // end for loop through ITemplates

	hr = S_OK;

EnrollmentPolicyServer_fail:

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
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropCommonName,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropCommonName) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Template Name: %S\n", varProperty.bstrVal);


	// Get the TemplatePropFriendlyName
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropFriendlyName,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropFriendlyName) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Template Friendly Name: %S\n", varProperty.bstrVal);
	

	// Get the TemplatePropValidityPeriod
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropValidityPeriod,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropValidityPeriod) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Validity Period: %ld years (%ld seconds)\n", varProperty.lVal/31536000, varProperty.lVal);


	// Get the TemplatePropRenewalPeriod
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropRenewalPeriod,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropValidityPeriod) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Renewal Period: %ld days (%ld seconds)\n", varProperty.lVal/86400, varProperty.lVal);


	// Get the TemplatePropSubjectNameFlags
	// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplatesubjectnameflag
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropSubjectNameFlags,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropSubjectNameFlags) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Certificate Name Flags: %08x\n", varProperty.intVal);


	// Get the TemplatePropEnrollmentFlags
	// See https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509certificatetemplateenrollmentflag
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropEnrollmentFlags,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropEnrollmentFlags) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Enrollment Flags: %08x\n", varProperty.intVal);


	// Get the TemplatePropRASignatureCount
	OLEAUT32$VariantClear(&varProperty);
	hr = pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropRASignatureCount,
		&varProperty
	);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "pCertificateTemplate->lpVtbl->get_Property(TemplatePropRASignatureCount) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	internal_printf( "Authorized Signature Required: %08x\n", varProperty.intVal);


	// Get the TemplatePropEKUs
	OLEAUT32$VariantClear(&varProperty);
	pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropEKUs,
		&varProperty
	);
	internal_printf( "Extended Key Usages:");
	hr = _adcs_get_ExtendedKeyUsages(&varProperty);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_ExtendedKeyUsages(&varProperty) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}


	
	// Get the TemplatePropKeySecurityDescriptor
	OLEAUT32$VariantClear(&varProperty);
	pCertificateTemplate->lpVtbl->get_Property(
		pCertificateTemplate,
		TemplatePropKeySecurityDescriptor,
		&varProperty
	);
	internal_printf( "TemplatePropKeySecurityDescriptor: %S\n", varProperty.bstrVal);
	internal_printf( "Permissions:\n");
	hr = _adcs_get_Security(varProperty.bstrVal);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "_adcs_get_Security(varProperty.bstrVal) failed: 0x%08lx\n", hr);
		goto CertificateTemplate_fail;
	}
	
	
	hr = S_OK;

CertificateTemplate_fail:

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
	ULONG ulUsageCount = 0;

	IID IID_IEnumVARIANT = { 0x00020404, 0x0000, 0x0000, {0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46} };
	IID IID_IObjectId = { 0x728ab300, 0x217d, 0x11da, {0XB2, 0XA4, 0x00, 0x0E, 0x7B, 0xBB, 0x2B, 0x09} };
	
	if (lpvarExtendedKeyUsages->pdispVal)
	{
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

				if (ulUsageCount++)
				{
					internal_printf( "," );
				}

				hr = pObjectId->lpVtbl->get_FriendlyName(
					pObjectId, 
					&bstFriendlyName
				);
				if (FAILED(hr))
				{
					internal_printf( " %S", STR_NOT_AVAILALBE);
				}
				else
				{
					internal_printf( " %S", bstFriendlyName);
				}
				//SAFE_FREE(bstFriendlyName);

				SAFE_RELEASE(pObjectId);
			}

			OLEAUT32$VariantClear(&var);

			hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &lFetch);
		} // end loop through IObjectIds via enumerator

		internal_printf( "\n" );

		SAFE_RELEASE(pObjectId);
	}
	else
	{
		internal_printf( " %S\n", STR_NOT_AVAILALBE);
	}

	hr = S_OK;

ExtendedKeyUsage_fail:

	OLEAUT32$VariantClear(&var);
	//SAFE_FREE(bstFriendlyName);
	//SAFE_RELEASE(pDisp);
	//SAFE_RELEASE(pEnum);
	//SAFE_RELEASE(pUnk);
	//SAFE_RELEASE(pObjectId);
	//SAFE_RELEASE(pObjectIds);

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



HRESULT adcs_enum_templates()
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
