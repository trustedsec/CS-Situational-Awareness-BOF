#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>
#include <certcli.h>
#include "certenroll.h"
#include <stdint.h>


HRESULT _adcs_get_PolicyServerListManager();
HRESULT _adcs_get_PolicyServerUrl(IX509PolicyServerUrl * pPolicyServerUrl);
HRESULT _adcs_get_EnrollmentPolicyServer(BSTR bstrPolicyServerUrl, BSTR bstrPolicyServerId);
HRESULT _adcs_get_CertificationAuthority(ICertificationAuthority * pCertificateAuthority);
HRESULT _adcs_get_CertificationAuthorityCertificate(VARIANT* lpvarCertifcate);
HRESULT _adcs_get_CertificationAuthorityWebServers(VARIANT* lpvarWebServers);
HRESULT _adcs_get_CertificationAuthorityCertificateTypes(VARIANT* lpvarArray);
HRESULT _adcs_get_CertificationAuthoritySecurity(BSTR bstrDacl);
HRESULT _adcs_get_CertificateTemplate(IX509CertificateTemplate * pCertificateTemplate);
HRESULT _adcs_get_CertificateTemplateExtendedKeyUsages(VARIANT* lpvarExtendedKeyUsages);
HRESULT _adcs_get_CertificateTemplateSecurity(BSTR bstrDacl);

HRESULT adcs_enum_com2();

