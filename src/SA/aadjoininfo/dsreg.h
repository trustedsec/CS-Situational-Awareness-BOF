//
// Hacky header with the structs required for 
// NETAPI32$NetGetAadJoinInformation and NETAPI32$NetFreeAadJoinInformation
// since the headers shipping with mingw32 do not contain them in lmjoin.h
//

#pragma once
#include <windows.h>

typedef enum _DSREG_JOIN_TYPE{
    DSREG_UNKNOWN_JOIN = 0,
    DSREG_DEVICE_JOIN = 1,
    DSREG_WORKPLACE_JOIN = 2
} DSREG_JOIN_TYPE, *PDSREG_JOIN_TYPE;

typedef struct _DSREG_USER_INFO
{
    LPWSTR pszUserEmail;
    LPWSTR pszUserKeyId;
    LPWSTR pszUserKeyName;

} DSREG_USER_INFO, *PDSREG_USER_INFO;

typedef struct _DSREG_JOIN_INFO
{
    DSREG_JOIN_TYPE joinType;

    PCCERT_CONTEXT pJoinCertificate;
    LPWSTR pszDeviceId;
    
    LPWSTR pszIdpDomain;
    LPWSTR pszTenantId;
    LPWSTR pszJoinUserEmail;

    LPWSTR pszTenantDisplayName;

    LPWSTR pszMdmEnrollmentUrl;
    LPWSTR pszMdmTermsOfUseUrl;
    LPWSTR pszMdmComplianceUrl;

    LPWSTR pszUserSettingSyncUrl;

    DSREG_USER_INFO *pUserInfo;

} DSREG_JOIN_INFO, *PDSREG_JOIN_INFO;