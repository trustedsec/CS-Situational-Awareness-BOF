#pragma once

#include <windows.h>
#include <certcli.h>
#include <stdint.h>

typedef struct _WebEnrollmentServer {
	BSTR bstrUri;
	BSTR bstrAuthentication;
	BSTR bstrPriority;
	BSTR bstrRenewalOnly;
} WebEnrollmentServer;

typedef struct _Templates {
	BSTR bstrName;
	BSTR bstrOID;
} Template;

typedef struct _CertificateServicesServer {
	BSTR bstrConfigName;
	ULONG ulWebEnrollmentServerCount;
	WebEnrollmentServer * lpWebEnrollmentServers;
	BSTR bstrCADNSName;
	BSTR bstrCAShareFolder;
	BSTR bstrCAType;
	ULONG ulTemplateCount;
	Template * lpTemplates;
	BSTR bstrTemplates;
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

HRESULT adcs_com_GetWebEnrollmentServers(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_GetTemplates(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_GetCertificateServicesServer(
	ADCS* pADCS,
	ULONG ulCurrentConfigIndex
);

HRESULT adcs_com_GetCertificateServices(
	ADCS* pADCS
);

HRESULT adcs_com_PrintInfo(
	ADCS* pADCS
);

void adcs_com_Finalize(
	ADCS* pADCS
);
