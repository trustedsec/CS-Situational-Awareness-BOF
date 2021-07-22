#pragma once
#define WIN32_WINNT 0x0601
#include <windows.h>
#include <certcli.h>
#include "certca.h"
#include <stdint.h>


HRESULT adcs_enum();

HRESULT adcs_enum_ca(HCAINFO hCAInfo);

HRESULT adcs_enum_cert(PCCERT_CONTEXT pCert);

HRESULT adcs_enum_cert_permissions(PSECURITY_DESCRIPTOR pSD);

HRESULT adcs_enum_cert_type(HCERTTYPE hCertType);