#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>
#include <certcli.h>
//#include <certsrv.h>
#include "certenroll.h"
#include <stdint.h>

typedef struct _WebEnrollmentServer {
	BSTR bstrUri;
	BSTR bstrAuthentication;
	BSTR bstrPriority;
	BSTR bstrRenewalOnly;
} WebEnrollmentServer;

typedef struct _Templates {
	BSTR bstrOID;
	BSTR bstrName;
	BSTR bstrFriendlyName;
	LONG lValidityPeriod;
	LONG lRenewalPeriod;
	UINT dwEnrollmentFlags;
	UINT dwSubjectNameFlags;
	//UINT dwPrivateKeyFlags;
	//UINT dwGeneralFlags;
	UINT dwSignatureCount;
	ULONG ulUsagesCount;
	BSTR * lpbstrUsages;
	BSTR bstrOwner;
	BSTR bstrOwnerSid;
	ULONG dwEnrollmentPrincipalsCount;
	BSTR * lpbstrEnrollmentPrincipals;
	ULONG dwWriteOwnerPrincipalsCount;
	BSTR * lpbstrWriteOwnerPrincipals;
	ULONG dwWriteDaclPrinciaplsCount;
	BSTR * lpbstrWriteDaclPrincipals;
	ULONG dwWritePropertyPrincipalsCount;
	BSTR * lpbstrWritePropertyPrincipals;
} Template;

typedef struct _CertificateServicesServer {
	BSTR bstrFullName;
	BSTR bstrCAName;
	ULONG ulWebEnrollmentServerCount;
	WebEnrollmentServer * lpWebEnrollmentServers;
	BSTR bstrCADNSName;
	BSTR bstrCAShareFolder;
	BSTR bstrCAType;
	ULONG ulTemplateCount;
	Template * lpTemplates;
} CertificateServicesServer;

typedef struct _ADCS {
	ICertConfig2 * pConfig;
	ICertRequest2 * pRequest;
	ULONG ulCertificateServicesServerCount;
	CertificateServicesServer * lpCertificateServicesServers;
} ADCS;



HRESULT adcs_com_Initialize(
	ADCS* pADCS
);

HRESULT adcs_com_Connect(
	ADCS* pADCS	
);

HRESULT adcs_com_GetCertificateServices(
	ADCS* pADCS
);

HRESULT adcs_com_GetCertificateServicesServer(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_GetCACertificate(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_GetWebEnrollmentServers(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_GetTemplates(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_PrintInfo(
	ADCS* pADCS
);

void adcs_com_Finalize(
	ADCS* pADCS
);

void print_guid(GUID guid) {
    internal_printf(
		"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}", 
      	guid.Data1, 
		guid.Data2, 
		guid.Data3, 
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]
		);
}

DWORD _bstr_list_insert(ULONG * lpdwCount, BSTR ** lppBstrList, BSTR bstrInsert) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	BSTR* lpNewList = NULL;
	// Check to see if the list is empty
	if ( ( 0 != *lpdwCount ) && ( NULL != *lppBstrList ) )
	{
		// Check to see if it is already in the list
		for( ULONG i=0; i<*lpdwCount; i++)
		{
			if ( 0 == MSVCRT$wcscmp( (*lppBstrList)[i], bstrInsert ) )
			{
				dwErrorCode = ERROR_ALREADY_EXISTS;
				goto end;
			}
		}
	}
	// Not in the list, so insert it
	// Check to see if list is already allocated
	if ( NULL == *lppBstrList )
	{
		*lpdwCount = 0;
		lpNewList = (BSTR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (*lpdwCount + 1)*sizeof(BSTR));
		if ( NULL == lpNewList )
		{
			dwErrorCode = ERROR_OUTOFMEMORY;
			BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapAlloc failed\n");
			goto end;
		}
	}
	else
	{
		lpNewList = (BSTR*)KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (LPVOID)(*lppBstrList), (*lpdwCount + 1)*sizeof(BSTR));
		if ( NULL == lpNewList )
		{
			dwErrorCode = ERROR_OUTOFMEMORY;
			BeaconPrintf(CALLBACK_ERROR, "KERNEL32$HeapReAlloc failed\n");
			goto end;
		}
	}
	// Insert into new list
	lpNewList[(*lpdwCount)] = bstrInsert;
	(*lppBstrList) = lpNewList;
	// Update count
	*lpdwCount = *lpdwCount + 1;
end:
	return dwErrorCode;
}