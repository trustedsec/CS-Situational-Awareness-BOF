#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>
#include <certcli.h>
#include "certca.h"
#include <stdint.h>


HRESULT _adcs_enum_ca(HCAINFO hCAInfo);
HRESULT _adcs_enum_cert(PCCERT_CONTEXT pCert);
HRESULT _adcs_enum_ca_permissions(PSECURITY_DESCRIPTOR pSD);
HRESULT _adcs_enum_cert_type(HCERTTYPE hCertType);
HRESULT _adcs_enum_cert_type_permissions(PSECURITY_DESCRIPTOR pSD);

HRESULT adcs_enum();

