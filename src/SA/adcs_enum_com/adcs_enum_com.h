#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>


HRESULT _adcs_get_CertConfig();
HRESULT _adcs_get_CertRequest(BSTR bstrConfig);
HRESULT _adcs_get_Certificate(BSTR bstrCertificate);
HRESULT _adcs_get_WebEnrollmentServers(BSTR bstrWebEnrollmentServers);
HRESULT _adcs_get_Templates(BSTR bstrTemplates);
HRESULT _adcs_get_Template(BSTR bstrOID);
HRESULT _adcs_get_TemplateExtendedKeyUsages(VARIANT* lpvarExtendedKeyUsages);
HRESULT _adcs_get_TemplateSecurity(BSTR bstrDacl);

HRESULT adcs_enum_com();

