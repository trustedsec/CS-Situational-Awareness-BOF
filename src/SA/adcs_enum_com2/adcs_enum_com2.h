#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>
#include <certcli.h>
#include "certenroll.h"
#include <stdint.h>


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

#define CERTCLI$CAEnumFirstCA ((CAEnumFirstCA_t)DynamicLoad("CERTCLI$CAEnumFirstCA"))
#define CERTCLI$CAEnumNextCA ((CAEnumNextCA_t)DynamicLoad("CERTCLI$CAEnumNextCA"))
#define CERTCLI$CACloseCA ((CACloseCA_t)DynamicLoad("CERTCLI$CACloseCA"))
#define CERTCLI$CACountCAs ((CACountCAs_t)DynamicLoad("CERTCLI$CACountCAs"))
#define CERTCLI$CAGetDN ((CAGetDN_t)DynamicLoad("CERTCLI$CAGetDN"))
#define CERTCLI$CAGetCAProperty ((CAGetCAProperty_t)DynamicLoad("CERTCLI$CAGetCAProperty"))
#define CERTCLI$CAFreeCAProperty ((CAFreeCAProperty_t)DynamicLoad("CERTCLI$CAFreeCAProperty"))
#define CERTCLI$CAGetCAFlags ((CAGetCAFlags_t)DynamicLoad("CERTCLI$CAGetCAFlags"))
#define CERTCLI$CAGetCACertificate ((CAGetCACertificate_t)DynamicLoad("CERTCLI$CAGetCACertificate"))
#define CERTCLI$CAGetCAExpiration ((CAGetCAExpiration_t)DynamicLoad("CERTCLI$CAGetCAExpiration"))
#define CERTCLI$CAGetCASecurity ((CAGetCASecurity_t)DynamicLoad("CERTCLI$CAGetCASecurity"))
#define CERTCLI$CAGetAccessRights ((CAGetAccessRights_t)DynamicLoad("CERTCLI$CAGetAccessRights"))
#define CERTCLI$CAEnumCertTypesForCA ((CAEnumCertTypesForCA_t)DynamicLoad("CERTCLI$CAEnumCertTypesForCA"))
#define CERTCLI$CAEnumCertTypes ((CAEnumCertTypes_t)DynamicLoad("CERTCLI$CAEnumCertTypes"))
#define CERTCLI$CAEnumNextCertType ((CAEnumNextCertType_t)DynamicLoad("CERTCLI$CAEnumNextCertType"))
#define CERTCLI$CACountCertTypes ((CACountCertTypes_t)DynamicLoad("CERTCLI$CACountCertTypes"))
#define CERTCLI$CACloseCertType ((CACloseCertType_t)DynamicLoad("CERTCLI$CACloseCertType"))
#define CERTCLI$CAGetCertTypeProperty ((CAGetCertTypeProperty_t)DynamicLoad("CERTCLI$CAGetCertTypeProperty"))
#define CERTCLI$CAGetCertTypePropertyEx ((CAGetCertTypePropertyEx_t)DynamicLoad("CERTCLI$CAGetCertTypePropertyEx"))
#define CERTCLI$CAFreeCertTypeProperty ((CAFreeCertTypeProperty_t)DynamicLoad("CERTCLI$CAFreeCertTypeProperty"))
#define CERTCLI$CAGetCertTypeExtensionsEx ((CAGetCertTypeExtensionsEx_t)DynamicLoad("CERTCLI$CAGetCertTypeExtensionsEx"))
#define CERTCLI$CAFreeCertTypeExtensions ((CAFreeCertTypeExtensions_t)DynamicLoad("CERTCLI$CAFreeCertTypeExtensions"))
#define CERTCLI$CAGetCertTypeFlagsEx ((CAGetCertTypeFlagsEx_t)DynamicLoad("CERTCLI$CAGetCertTypeFlagsEx"))
#define CERTCLI$CAGetCertTypeExpiration ((CAGetCertTypeExpiration_t)DynamicLoad("CERTCLI$CAGetCertTypeExpiration"))
#define CERTCLI$CACertTypeGetSecurity ((CACertTypeGetSecurity_t)DynamicLoad("CERTCLI$CACertTypeGetSecurity"))
#define CERTCLI$caTranslateFileTimePeriodToPeriodUnits ((caTranslateFileTimePeriodToPeriodUnits_t)DynamicLoad("CERTCLI$caTranslateFileTimePeriodToPeriodUnits"))
#define CERTCLI$CAGetCertTypeAccessRights ((CAGetCertTypeAccessRights_t)DynamicLoad("CERTCLI$CAGetCertTypeAccessRights"))


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

