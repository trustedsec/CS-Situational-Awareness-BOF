//+--------------------------------------------------------------------------
//
// Microsoft Windows
// Copyright (C) Microsoft Corporation, 1996 - 2000
//
// File:        certca.h
//
// Contents:    Definition of the CA Info API
//
// History:     12-dec-97       petesk  created
//              28-Jan-2000     xiaohs  updated
//
//---------------------------------------------------------------------------


#ifndef __CERTCA_H__
#define __CERTCA_H__


#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C"{
#endif


#include <wincrypt.h>


typedef VOID *  HCAINFO;

typedef VOID *  HCERTTYPE;

typedef VOID *  HCERTTYPEQUERY;

//*****************************************************************************
//
// Flags used by CAFindByName, CAFindByCertType, CAFindByIssuerDN and
// CAEnumFirstCA
//
// See comments on each API for a list of applicable flags
//
//*****************************************************************************
//the wszScope supplied is a domain location in the DNS format
#define CA_FLAG_SCOPE_DNS               0x00000001

// include untrusted CA
#define CA_FIND_INCLUDE_UNTRUSTED       0x00000010

// running as local system.  Used to verify CA certificate chain
#define CA_FIND_LOCAL_SYSTEM            0x00000020

// Include CAs that do not support templates
#define CA_FIND_INCLUDE_NON_TEMPLATE_CA 0x00000040

// The value passed in for scope is the LDAP binding handle to use during finds
#define CA_FLAG_SCOPE_IS_LDAP_HANDLE    0x00000800

// Return CAs from local machine context
#define CA_ENUM_ADMINISTRATOR_FORCE_MACHINE    0x00001000

// Enumerate all Types which are present on the CA object 
#define CA_ENUM_INCLUDE_INVALID_TYPES    0x00004000



//*****************************************************************************
//
// Flags used by CAEnumCertTypesForCA, CAEnumCertTypes,
// CAFindCertTypeByName, CAEnumCertTypesForCAEx, and CAEnumCertTypesEx.
//
// See comments on each API for a list of applicable flags
//
//*****************************************************************************
//  Instead of enumerating the certificate types supported by the CA, enumerate
// ALL certificate types which the CA may choose to support.
#define CA_FLAG_ENUM_ALL_TYPES          0x00000004

// running as local system.  Used to find cached information in the registry.
#define CT_FIND_LOCAL_SYSTEM            CA_FIND_LOCAL_SYSTEM

// Return machine types, as opposed to user types
#define CT_ENUM_MACHINE_TYPES           0x00000040

// Return user types, as opposed to user types
#define CT_ENUM_USER_TYPES              0x00000080

// Find the certificate type by its OID, instead of its name
#define CT_FIND_BY_OID                  0x00000200

// Disable the cache expiration check
#define CT_FLAG_NO_CACHE_LOOKUP         0x00000400

// The value passed in for scope is the LDAP binding handle to use during finds
#define CT_FLAG_SCOPE_IS_LDAP_HANDLE    CA_FLAG_SCOPE_IS_LDAP_HANDLE

// Return the cert types from the local machine context
#define CT_ENUM_ADMINISTRATOR_FORCE_MACHINE    CA_ENUM_ADMINISTRATOR_FORCE_MACHINE

// For perf issue, do not cache registry for admin machine context
#define CT_ENUM_NO_CACHE_TO_REGISTRY    0x00002000

// Enumerate all Types which are present on the CA object 
#define CT_FLAG_ENUM_INCLUDE_INVALID_TYPES     CA_ENUM_INCLUDE_INVALID_TYPES


//*****************************************************************************
//
// Certification Authority manipulation APIs
//
//*****************************************************************************


// CAFindByName
//
// Given the Name of a CA (CN), find the CA within the given domain and return
// the given phCAInfo structure.
//
// wszCAName    - Common name of the CA
//
// wszScope     - The distinguished name (DN) of the entry at which to start
//		  the search.  Equivalent of the "base" parameter of the
//		  ldap_search_sxxx APIs.
//                NULL if use the current domain.
//                If CA_FLAG_SCOPE_DNS is set, wszScope is in the DNS format.
//                If CA_FLAG_SCOPE_IS_LDAP_HANDLE is set, wszScope is the LDAP
//		  binding handle to use during finds.
//
// dwFlags      - Oring of the following flags:
//                CA_FLAG_SCOPE_DNS
//                CA_FIND_INCLUDE_UNTRUSTED
//                CA_FIND_LOCAL_SYSTEM
//                CA_FIND_INCLUDE_NON_TEMPLATE_CA
//                CA_FLAG_SCOPE_IS_LDAP_HANDLE
//
// phCAInfo     - Handle to the returned CA.
//
// Return:        Returns S_OK if CA was found.
//

HRESULT
WINAPI
CAFindByName(
    IN  LPCWSTR     wszCAName,
    IN  LPCWSTR     wszScope,
    IN  DWORD       dwFlags,
    OUT HCAINFO *   phCAInfo
    );

//
// CAFindByCertType
//
// Given the Name of a Cert Type, find all the CAs within the given domain and
// return the given phCAInfo structure.
//
// wszCertType  - Common Name of the cert type
//
// wszScope     - The distinguished name (DN) of the entry at which to start
//		  the search.  Equivalent of the "base" parameter of the
//		  ldap_search_sxxx APIs.
//                NULL if use the current domain.
//                If CA_FLAG_SCOPE_DNS is set, wszScope is in the DNS format.
//                If CA_FLAG_SCOPE_IS_LDAP_HANDLE is set, wszScope is the LDAP
//		  binding handle to use during finds.
//
// dwFlags      - Oring of the following flags:
//                CA_FLAG_SCOPE_DNS
//                CA_FIND_INCLUDE_UNTRUSTED
//                CA_FIND_LOCAL_SYSTEM
//                CA_FIND_INCLUDE_NON_TEMPLATE_CA
//                CA_FLAG_SCOPE_IS_LDAP_HANDLE
//
// phCAInfo     - Handle to enumeration of CAs supporting the specified cert
//		  type.
//
// Return:        Returns S_OK on success.
//                Will return S_OK if none are found.
//                *phCAInfo will contain NULL
//

HRESULT
WINAPI
CAFindByCertType(
    IN  LPCWSTR     wszCertType,
    IN  LPCWSTR     wszScope,
    IN  DWORD       dwFlags,
    OUT HCAINFO *   phCAInfo
    );


//
// CAFindByIssuerDN
// Given the DN of a CA, find the CA within the given domain and return the
// given phCAInfo handle.
//
// pIssuerDN    - a cert name blob from the CA's certificate.
//
// wszScope     - The distinguished name (DN) of the entry at which to start
//		  the search.  Equivalent of the "base" parameter of the
//		  ldap_search_sxxx APIs.
//                NULL if use the current domain.
//                If CA_FLAG_SCOPE_DNS is set, wszScope is in the DNS format.
//                If CA_FLAG_SCOPE_IS_LDAP_HANDLE is set, wszScope is the LDAP
//		  binding handle to use during finds.
//
// dwFlags      - Oring of the following flags:
//                CA_FLAG_SCOPE_DNS
//                CA_FIND_INCLUDE_UNTRUSTED
//                CA_FIND_LOCAL_SYSTEM
//                CA_FIND_INCLUDE_NON_TEMPLATE_CA
//                CA_FLAG_SCOPE_IS_LDAP_HANDLE 
//
//
// Return:      Returns S_OK if CA was found.
//


HRESULT
WINAPI
CAFindByIssuerDN(
    IN  CERT_NAME_BLOB const *  pIssuerDN,
    IN  LPCWSTR                 wszScope,
    IN  DWORD                   dwFlags,
    OUT HCAINFO *               phCAInfo
    );


//
// CAEnumFirstCA
// Enumerate the CAs in a scope
//
// wszScope     - The distinguished name (DN) of the entry at which to start
//		  the search.  Equivalent of the "base" parameter of the
//		  ldap_search_sxxx APIs.
//                NULL if use the current domain. 
//                If CA_FLAG_SCOPE_DNS is set, wszScope is in the DNS format.
//                If CA_FLAG_SCOPE_IS_LDAP_HANDLE is set, wszScope is the LDAP
//		  binding handle to use during finds.
//
// dwFlags      - Oring of the following flags:
//                CA_FLAG_SCOPE_DNS
//                CA_FIND_INCLUDE_UNTRUSTED
//                CA_FIND_LOCAL_SYSTEM
//                CA_FIND_INCLUDE_NON_TEMPLATE_CA
//                CA_FLAG_SCOPE_IS_LDAP_HANDLE 
//                CA_ENUM_ADMINISTRATOR_FORCE_MACHINE
//
// phCAInfo     - Handle to enumeration of CAs supporting the specified cert
//		  type.
//
//
// Return:        Returns S_OK on success.
//                Will return S_OK if none are found.
//                *phCAInfo will contain NULL
//

HRESULT
WINAPI
CAEnumFirstCA(
    IN  LPCWSTR          wszScope,
    IN  DWORD            dwFlags,
    OUT HCAINFO *        phCAInfo
    );


//
// CAEnumNextCA
// Find the Next CA in an enumeration.
//
// hPrevCA      - Current CA in an enumeration.
//
// phCAInfo     - next CA in an enumeration.
//
// Return:        Returns S_OK on success.
//                Will return S_OK if none are found.
//                *phCAInfo will contain NULL
//

HRESULT
WINAPI
CAEnumNextCA(
    IN  HCAINFO          hPrevCA,
    OUT HCAINFO *        phCAInfo
    );

//
// CACreateNewCA
// Create a new CA of given name.
//
// wszCAName    - Common name of the CA
//
// wszScope     - The distinguished name (DN) of the entry at which to create
//		  the CA object.  We will add the "CN=...,..,CN=Services" after
//		  the DN.
//                NULL if use the current domain. 
//                If CA_FLAG_SCOPE_DNS is set, wszScope is in the DNS format.
//
// dwFlags      - Oring of the following flags:
//                CA_FLAG_SCOPE_DNS
//
// phCAInfo     - Handle to the returned CA.
//
// See above for other parameter definitions
//
// Return:        Returns S_OK if CA was created.
//
// NOTE:  Actual updates to the CA object may not occur until CAUpdateCA is
//	  called.  In order to successfully update a created CA, the
//	  Certificate must be set, as well as the Certificate Types property.
//

HRESULT
WINAPI
CACreateNewCA(
    IN  LPCWSTR     wszCAName,
    IN  LPCWSTR     wszScope,
    IN  DWORD       dwFlags,
    OUT HCAINFO *   phCAInfo
    );

//
// CAUpdateCA
// Write any changes made to the CA back to the CA object.
//
// hCAInfo      - Handle to an open CA object.
//

HRESULT
WINAPI
CAUpdateCA(
    IN HCAINFO    hCAInfo
    );

//
// CAUpdateCAEx
// Write any changes made to the CA back to the CA object.
//
// hCAInfo      - Handle to an open CA object.
//
//
// lpPara       - If CA_FLAG_SCOPE_IS_LDAP_HANDLE is set, lpPara is the LDAP
//		  binding handle to use during update.
// dwFlags      - Oring of the following flags:
//                  CA_FLAG_SCOPE_IS_LDAP_HANDLE
//
// Return:        Returns S_OK on success.
//
HRESULT
WINAPI
CAUpdateCAEx(
    IN LPVOID   lpPara,
    IN DWORD    dwFlags,
    IN HCAINFO  hCAInfo
    );

//
// CADeleteCA
// Delete the CA object from the DS.
//
// hCAInfo      - Handle to an open CA object.
//

HRESULT
WINAPI
CADeleteCA(
    IN HCAINFO    hCAInfo
    );

//
// CADeleteCAEx
// Delete the CA object from the DS.
//
// hCAInfo      - Handle to an open CA object.
//
//
// lpPara       - If CA_FLAG_SCOPE_IS_LDAP_HANDLE is set, lpPara is the LDAP
//		  binding handle to use during update.
// dwFlags      - Oring of the following flags:
//                  CA_FLAG_SCOPE_IS_LDAP_HANDLE
//
// Return:        Returns S_OK on success.

HRESULT
WINAPI
CADeleteCAEx(
    IN LPVOID   lpPara,
    IN DWORD    dwFlags,
    IN HCAINFO  hCAInfo
    );

//
// CACountCAs
// return the number of CAs in this enumeration
//

DWORD
WINAPI
CACountCAs(
    IN  HCAINFO  hCAInfo
    );

//
// CAGetDN
// returns the DN of the associated DS object
//

LPCWSTR
WINAPI
CAGetDN(
    IN HCAINFO hCAInfo
    );


//
// CACloseCA
// Close an open CA handle
//
// hCAInfo      - Handle to an open CA object.
//

HRESULT
WINAPI
CACloseCA(
    IN HCAINFO hCA
    );



//
// CAGetCAProperty - Given a property name, retrieve a
// property from a CAInfo.
//
// hCAInfo              - Handle to an open CA object.
//
// wszPropertyName      - Name of the CA property
//
// pawszPropertyValue   - A pointer into which an array of WCHAR strings is
//			  written, containing the values of the property.  The
//			  last element of the array points to NULL.
//                        If the property is single valued, then the array
//			  returned contains 2 elements, the first pointing to
//			  the value, the second pointing to NULL.  This pointer
//			  must be freed by CAFreeCAProperty.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CAGetCAProperty(
    IN  HCAINFO     hCAInfo,
    IN  LPCWSTR     wszPropertyName,
    _Out_ PZPWSTR  *pawszPropertyValue
    );


//
// CAFreeProperty
// Frees a previously retrieved property value.
//
// hCAInfo              - Handle to an open CA object.
//
// awszPropertyValue    - pointer to the previously retrieved property value.
//

HRESULT
WINAPI
CAFreeCAProperty(
    _In_ HCAINFO hCAInfo,
    _In_ PZPWSTR awszPropertyValue
    );


//
// CASetCAProperty - Given a property name, set its value.
//
// hCAInfo              - Handle to an open CA object.
//
// wszPropertyName      - Name of the CA property
//
// awszPropertyValue    - An array of values to set for this property.  The
//			  last element of this - array should be NULL.
//                        For single valued properties, the values beyond the
//                        first will be ignored upon update.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CASetCAProperty(
    IN HCAINFO      hCAInfo,
    IN LPCWSTR      wszPropertyName,
    _In_ PZPWSTR awszPropertyValue
    );


//*****************************************************************************
///
// CA Properties
//
//*****************************************************************************

// simple name of the CA
#define CA_PROP_NAME                    L"cn"

// display name of the CA object
#define CA_PROP_DISPLAY_NAME            L"displayName"

// dns name of the machine
#define CA_PROP_DNSNAME                 L"dNSHostName"

// DS Location of CA object (DN)
#define CA_PROP_DSLOCATION              L"distinguishedName"

// Supported cert types
#define CA_PROP_CERT_TYPES              L"certificateTemplates"

// Supported signature algs
#define CA_PROP_SIGNATURE_ALGS          L"signatureAlgorithms"

// DN of the CA's cert
#define CA_PROP_CERT_DN                 L"cACertificateDN"

#define CA_PROP_ENROLLMENT_PROVIDERS    L"enrollmentProviders"

// CA's description
#define CA_PROP_DESCRIPTION	        L"Description"

// CA's URL
#define CA_PROP_WEB_SERVERS	        L"msPKI-Enrollment-Servers"

// CA's Site Name
#define CA_PROP_SITENAME	        L"msPKI-Site-Name"

//
// CAGetCACertificate - Return the current certificate for
// this CA.
//
// hCAInfo      - Handle to an open CA object.
//
// ppCert       - Pointer into which a certificate is written.  This
//		  certificate must be freed via CertFreeCertificateContext.
//                This value will be NULL if no certificate is set for this CA.
//

HRESULT
WINAPI
CAGetCAFlags(
    IN HCAINFO  hCAInfo,
    OUT DWORD  *pdwFlags
    );

//*****************************************************************************
//
// CA Flags
//
//*****************************************************************************

// The CA supports certificate templates
#define CA_FLAG_NO_TEMPLATE_SUPPORT                 0x00000001

// The CA supports NT authentication for requests
#define CA_FLAG_SUPPORTS_NT_AUTHENTICATION          0x00000002

// The cert requests may be pended
#define CA_FLAG_CA_SUPPORTS_MANUAL_AUTHENTICATION   0x00000004

// The cert requests may be pended
#define CA_FLAG_CA_SERVERTYPE_ADVANCED              0x00000008

#define CA_MASK_SETTABLE_FLAGS                      0x0000ffff


//
// CASetCAFlags
// Sets the Flags of a cert type
//
// hCertType    - handle to the CertType
//
// dwFlags      - Flags to be set
//

HRESULT
WINAPI
CASetCAFlags(
    IN HCAINFO             hCAInfo,
    IN DWORD               dwFlags
    );

HRESULT
WINAPI
CAGetCACertificate(
    IN  HCAINFO     hCAInfo,
    OUT PCCERT_CONTEXT *ppCert
    );


//
// CASetCACertificate - Set the certificate for a CA this CA.
//
// hCAInfo      - Handle to an open CA object.
//
// pCert        - Pointer to a certificate to set as the CA's certificate.
//

HRESULT
WINAPI
CASetCACertificate(
    IN  HCAINFO     hCAInfo,
    IN PCCERT_CONTEXT pCert
    );


//
// CAGetCAExpiration
// Get the expirations period for a CA.
//
// hCAInfo              - Handle to an open CA handle.
//
// pdwExpiration        - expiration period in dwUnits time
//
// pdwUnits             - Units identifier
//

HRESULT
WINAPI
CAGetCAExpiration(
    HCAINFO hCAInfo,
    DWORD * pdwExpiration,
    DWORD * pdwUnits
    );

#define CA_UNITS_DAYS   1
#define CA_UNITS_WEEKS  2
#define CA_UNITS_MONTHS 3
#define CA_UNITS_YEARS  4


//
// CASetCAExpiration
// Set the expirations period for a CA.
//
// hCAInfo              - Handle to an open CA handle.
//
// dwExpiration         - expiration period in dwUnits time
//
// dwUnits              - Units identifier
//

HRESULT
WINAPI
CASetCAExpiration(
    HCAINFO hCAInfo,
    DWORD dwExpiration,
    DWORD dwUnits
    );

//
// CASetCASecurity
// Set the list of Users, Groups, and Machines allowed to access this CA.
//
// hCAInfo      - Handle to an open CA handle.
//
// pSD          - Security descriptor for this CA
//

HRESULT
WINAPI
CASetCASecurity(
    IN HCAINFO                 hCAInfo,
    IN PSECURITY_DESCRIPTOR    pSD
    );

//
// CAGetCASecurity
// Get the list of Users, Groups, and Machines allowed to access this CA.
//
// hCAInfo      - Handle to an open CA handle.
//
// ppSD         - Pointer to a location receiving the pointer to the security
//		  descriptor.  Free via LocalFree.
//

HRESULT
WINAPI
CAGetCASecurity(
    IN  HCAINFO                    hCAInfo,
    OUT PSECURITY_DESCRIPTOR *     ppSD
    );

//
// CAAccessCheck
// Determine whether the principal specified by
// ClientToken can get a cert from the CA.
//
// hCAInfo      - Handle to the CA
//
// ClientToken  - Handle to an impersonation token that represents the client
//		  attempting request this cert type.  The handle must have
//		  TOKEN_QUERY access to the token; otherwise, the function
//		  fails with ERROR_ACCESS_DENIED.
//
// Return: S_OK on success
//

HRESULT
WINAPI
CAAccessCheck(
    IN HCAINFO      hCAInfo,
    IN HANDLE       ClientToken
    );

//
// CAAccessCheckEx
// Determine whether the principal specified by
// ClientToken can get a cert from the CA.
//
// hCAInfo      - Handle to the CA
//
// ClientToken  - Handle to an impersonation token that represents the client
//		  attempting request this cert type.  The handle must have
//		  TOKEN_QUERY access to the token; otherwise, the function
//		  fails with ERROR_ACCESS_DENIED.
//
// dwOption     - Can be one of the following:
//                        CERTTYPE_ACCESS_CHECK_ENROLL

//                  dwOption can be CERTTYPE_ACCESS_CHECK_NO_MAPPING to 
//                  disallow default mapping of client token

//
// Return: S_OK on success
//

HRESULT
WINAPI
CAAccessCheckEx(
    IN HCAINFO      hCAInfo,
    IN HANDLE       ClientToken,
    IN DWORD        dwOption
    );


// Used for certenroll.idl:
// certenroll_begin -- CA_ACCESS_RIGHT_XXX

//
// Access Rights for HCAINFO and HCERTTYPE
//

#define CA_ACCESS_RIGHT_READ                          0x01
 
#define CA_ACCESS_RIGHT_ENROLL                        0x02

#define CA_ACCESS_RIGHT_AUTO_ENROLL                   0x04

// certenroll_end


//
// dwContext for access right
//
#define CA_CONTEXT_CURRENT                            0x01
 
#define CA_CONTEXT_ADMINISTRATOR_FORCE_MACHINE        0x02

//
// CAGetAccessRights
//
// Determine the access rights of the HCAInfo based on the current context
//
// hCAInfo      - Handle to the CA
//
// dwContext    - Can be one of the following:
//                 CA_CONTEXT_CURREN 
//                 CA_CONTEXT_ADMINISTRATOR_FORCE_MACHINE
//
// pdwAccessRight- Oring of the following flags:
//                 CA_ACCESS_RIGHT_READ
//                 CA_ACCESS_RIGH_ENROLL
//
//
// Return: S_OK on success
//
HRESULT
WINAPI
CAGetAccessRights(
    IN  HCAINFO      hCAInfo,
    IN  DWORD        dwContext,
    OUT DWORD        *pdwAccessRights 
    );


// CAIsValid
//
// Determine if the HCAINFO has full properties and readable
// from the current context.  For CAs that is not readable from
// current context, only CA_PROP_NAME and CA_PROP_DNSNAME are present.
//
// hCAInfo      - Handle to the CA
//
// pValid       - TRUE is the CA is readable
//
// Return: S_OK on success
//
HRESULT
WINAPI
CAIsValid(
    IN  HCAINFO     hCAInfo,
    OUT BOOL        *pValid
    );

//
// CAEnumCertTypesForCA - Given a HCAINFO, retrieve handle to the cert types
// supported or known by this CA.  CAEnumNextCertType can be used to enumerate
// through the cert types.
//
// hCAInfo      - Handle to an open CA handle or NULL if CT_FLAG_ENUM_ALL_TYPES
//		  is set in dwFlags.
//
// dwFlags      - The following flags may be or'd together
//                CA_FLAG_ENUM_ALL_TYPES 
//                CT_FIND_LOCAL_SYSTEM
//                CT_ENUM_MACHINE_TYPES
//                CT_ENUM_USER_TYPES
//                CT_FLAG_NO_CACHE_LOOKUP  
//
// phCertType   - Enumeration of certificate types.
//


HRESULT
WINAPI
CAEnumCertTypesForCA(
    IN  HCAINFO     hCAInfo,
    IN  DWORD       dwFlags,
    OUT HCERTTYPE * phCertType
    );

//
// CAEnumCertTypesForCAEx - Given a HCAINFO, retrieve handle to the cert types
// supported or known by this CA.  CAEnumNextCertTypeEx can be used to enumerate
// through the cert types.  It optional takes a LDAP handle.
//
// hCAInfo      - Handle to an open CA handle or NULL if CT_FLAG_ENUM_ALL_TYPES
//		          is set in dwFlags.
//
// wszScope     - NULL if use the current domain.
//                      If CT_FLAG_SCOPE_IS_LDAP_HANDLE is set, wszScope is the LDAP
//		                binding handle to use during finds.
//
// dwFlags      - The following flags may be or'd together
//                CA_FLAG_ENUM_ALL_TYPES 
//                CT_FIND_LOCAL_SYSTEM
//                CT_ENUM_MACHINE_TYPES
//                CT_ENUM_USER_TYPES
//                CT_FLAG_NO_CACHE_LOOKUP  
//                CT_FLAG_SCOPE_IS_LDAP_HANDLE 
// 
// phCertType   - Enumeration of certificate types.
//


HRESULT
WINAPI
CAEnumCertTypesForCAEx(
    IN  HCAINFO     hCAInfo,
    IN  LPCWSTR     wszScope,
    IN  DWORD       dwFlags,
    OUT HCERTTYPE * phCertType
    );


//
// CAAddCACertificateType
// Add a certificate type to a CA.  If the cert type has already been added to
// the CA, it will not be added again. 
//
// hCAInfo      - Handle to an open CA.
//
// hCertType    - Handle to the CertType
//


HRESULT
WINAPI
CAAddCACertificateType(
    HCAINFO hCAInfo,
    HCERTTYPE hCertType);


//
// CARemoveCACertificateType
// Remove a certificate type from a CA.  If the CA does not include this cert
// type, this call does nothing. 
//
// hCAInfo      - Handle to an open CA.
//
// hCertType    - Handle to the CertType
//


HRESULT
WINAPI
CARemoveCACertificateType(
    HCAINFO hCAInfo,
    HCERTTYPE hCertType);

//
// CAAddCACertificateTypeEx
// Add a certificate type to a CA.  If the cert type has already been added to
// the CA, it will not be added again. Either the hCertType Handle
// or the CN of the CertType must not be Null.
//
// hCAInfo      - Handle to an open CA.
//
// hCertType    - Handle to the CertType
//
// pwcszCertTypeName    - CN of the Cert Type
//

HRESULT
WINAPI
CAAddCACertificateTypeEx(
    _In_ HCAINFO hCAInfo,
    _In_opt_ HCERTTYPE hCertType,
    _In_opt_ LPWSTR pwszCertTypeName
    );


//
// CARemoveCACertificateType
// Remove a certificate type from a CA.  If the CA does not include this cert
// type, this call does nothing. Either the hCertType Handle
// or the CN of the CertType must not be Null.
//
// hCAInfo      - Handle to an open CA.
//
// hCertType    - Handle to the CertType
//
// pwcszCertTypeName    - CN of the Cert Type
//

HRESULT
WINAPI
CARemoveCACertificateTypeEx(
    _In_ HCAINFO hCAInfo,
    _In_opt_ HCERTTYPE hCertType,
    _In_opt_ LPWSTR pwszCertTypeName
    );




//*****************************************************************************
//
// Certificate Type APIs
//
//*****************************************************************************

//
// CAEnumCertTypes - Retrieve a handle to all known cert types
// CAEnumNextCertType can be used to enumerate through the cert types.
//
// dwFlags              - an oring of the following:
//                        CT_FIND_LOCAL_SYSTEM
//                        CT_ENUM_MACHINE_TYPES
//                        CT_ENUM_USER_TYPES
//                        CT_FLAG_NO_CACHE_LOOKUP
//                        CT_ENUM_ADMINISTRATOR_FORCE_MACHINE
//                        CT_ENUM_NO_CACHE_TO_REGISTRY
//
// phCertType           - Enumeration of certificate types.
//


HRESULT
WINAPI
CAEnumCertTypes(
    IN  DWORD       dwFlags,
    OUT HCERTTYPE * phCertType
    );


//
// CAEnumCertTypesEx - Retrieve a handle to all known cert types
// CAEnumNextCertType can be used to enumerate through the cert types.
//
// wszScope            - NULL if use the current domain.
//                        If CT_FLAG_SCOPE_IS_LDAP_HANDLE is set, wszScope is the LDAP
//		                  binding handle to use during finds.
//
// dwFlags              - an oring of the following:
//                        CT_FIND_LOCAL_SYSTEM
//                        CT_ENUM_MACHINE_TYPES
//                        CT_ENUM_USER_TYPES
//                        CT_FLAG_NO_CACHE_LOOKUP
//                        CT_FLAG_SCOPE_IS_LDAP_HANDLE 
//                        CT_ENUM_ADMINISTRATOR_FORCE_MACHINE
//                        CT_ENUM_NO_CACHE_TO_REGISTRY
//
// phCertType           - Enumeration of certificate types.
//

HRESULT
WINAPI
CAEnumCertTypesEx(
    IN  LPCWSTR     wszScope,
    IN  DWORD       dwFlags,
    OUT HCERTTYPE * phCertType
    );


//
// CAEnumCertTypesEx2 - Retrieve a handle to all known cert types
//
// Same as CAEnumCertTypesEx, except:
// CAEnumCertTypesEx now filters out templates whose minimum client OS version
// is greater than the current OS version.
//
// CAEnumCertTypesEx2 allows the caller to specify whether to filter against
// dwClientVersion and/or dwServerVersion.
//
// dwClientVersion	- TEMPLATE_CLIENT_VER_NONE doesn't filter on client OS
//
// dwServerVersion	- TEMPLATE_SERVER_VER_NONE doesn't filter on server OS
//

HRESULT
WINAPI
CAEnumCertTypesEx2(
    IN  LPCWSTR     wszScope,
    IN  DWORD       dwFlags,
    IN  DWORD       dwClientVersion,	// TEMPLATE_CLIENT_VER_*
    IN  DWORD       dwServerVersion,	// TEMPLATE_SERVER_VER_*
    OUT HCERTTYPE * phCertType
    );


//
// CAFindCertTypeByName - Find a cert type given a Name.
//
// wszCertType  - Name of the cert type if CT_FIND_BY_OID is not set in dwFlags
//                The OID of the cert type if CT_FIND_BY_OID is set in dwFlags
//
// hCAInfo      - NULL unless CT_FLAG_SCOPE_IS_LDAP_HANDLE is set in dwFlags
//
// dwFlags      - an oring of the following
//                CT_FIND_LOCAL_SYSTEM
//                CT_ENUM_MACHINE_TYPES
//                CT_ENUM_USER_TYPES
//                CT_FLAG_NO_CACHE_LOOKUP  
//                CT_FIND_BY_OID
//                CT_FLAG_SCOPE_IS_LDAP_HANDLE -- If this flag is set, hCAInfo
//						  is the LDAP handle to use
//						  during finds.
// phCertType   - Pointer to a cert type in which result is returned.
//

HRESULT
WINAPI
CAFindCertTypeByName(
    IN  LPCWSTR     wszCertType,
    IN  HCAINFO     hCAInfo,
    IN  DWORD       dwFlags,
    OUT HCERTTYPE * phCertType
    );


//
// CAFindCertTypeByName2 - Find a cert type given a Name.
//
// Same as CAFindCertTypeByName, except:
// CAFindCertTypeByName now filters out templates whose minimum client OS
// version is greater than the current OS version.
//
// CAFindCertTypeByName2 allows the caller to specify whether to filter against
// dwClientVersion and/or dwServerVersion.
//
// dwClientVersion	- TEMPLATE_CLIENT_VER_NONE doesn't filter on client OS
//
// dwServerVersion	- TEMPLATE_SERVER_VER_NONE doesn't filter on server OS
//

HRESULT
WINAPI
CAFindCertTypeByName2(
    IN  LPCWSTR     wszCertType,
    IN  HCAINFO     hCAInfo,
    IN  DWORD       dwFlags,
    IN  DWORD       dwClientVersion,	// TEMPLATE_CLIENT_VER_*
    IN  DWORD       dwServerVersion,	// TEMPLATE_SERVER_VER_*
    OUT HCERTTYPE * phCertType
    );


//*****************************************************************************
//
// Default cert type names
//
//*****************************************************************************

#define wszCERTTYPE_USER                    L"User"
#define wszCERTTYPE_USER_SIGNATURE          L"UserSignature"
#define wszCERTTYPE_SMARTCARD_USER          L"SmartcardUser"
#define wszCERTTYPE_USER_AS                 L"ClientAuth"
#define wszCERTTYPE_USER_SMARTCARD_LOGON    L"SmartcardLogon"
#define wszCERTTYPE_EFS                     L"EFS"
#define wszCERTTYPE_ADMIN                   L"Administrator"
#define wszCERTTYPE_EFS_RECOVERY            L"EFSRecovery"
#define wszCERTTYPE_CODE_SIGNING            L"CodeSigning"
#define wszCERTTYPE_CTL_SIGNING             L"CTLSigning"
#define wszCERTTYPE_ENROLLMENT_AGENT        L"EnrollmentAgent"


#define wszCERTTYPE_MACHINE                 L"Machine"
#define wszCERTTYPE_WORKSTATION             L"Workstation"
#define wszCERTTYPE_DC                      L"DomainController"
#define wszCERTTYPE_RASIASSERVER            L"RASAndIASServer"
#define wszCERTTYPE_WEBSERVER               L"WebServer"
#define wszCERTTYPE_KDC                     L"KDC"
#define wszCERTTYPE_CA                      L"CA"
#define wszCERTTYPE_SUBORDINATE_CA          L"SubCA"
#define wszCERTTYPE_CROSS_CA				L"CrossCA"
#define wszCERTTYPE_KEY_RECOVERY_AGENT      L"KeyRecoveryAgent"
#define wszCERTTYPE_CA_EXCHANGE             L"CAExchange"
#define wszCERTTYPE_DC_AUTH                 L"DomainControllerAuthentication"
#define wszCERTTYPE_DS_EMAIL_REPLICATION    L"DirectoryEmailReplication"
#define wszCERTTYPE_OCSPRESPONSESIGNING	    L"OCSPResponseSigning"
#define wszCERTTYPE_KERB_AUTHENTICATION     L"KerberosAuthentication"


#define wszCERTTYPE_IPSEC_ENDENTITY_ONLINE      L"IPSECEndEntityOnline"
#define wszCERTTYPE_IPSEC_ENDENTITY_OFFLINE     L"IPSECEndEntityOffline"
#define wszCERTTYPE_IPSEC_INTERMEDIATE_ONLINE   L"IPSECIntermediateOnline"
#define wszCERTTYPE_IPSEC_INTERMEDIATE_OFFLINE  L"IPSECIntermediateOffline"

#define wszCERTTYPE_ROUTER_OFFLINE              L"OfflineRouter"
#define wszCERTTYPE_ENROLLMENT_AGENT_OFFLINE    L"EnrollmentAgentOffline"
#define wszCERTTYPE_EXCHANGE_USER               L"ExchangeUser"
#define wszCERTTYPE_EXCHANGE_USER_SIGNATURE     L"ExchangeUserSignature"
#define wszCERTTYPE_MACHINE_ENROLLMENT_AGENT    L"MachineEnrollmentAgent"
#define wszCERTTYPE_CEP_ENCRYPTION              L"CEPEncryption"


//
// CAUpdateCertType
// Write any changes made to the cert type back to the type store
//
HRESULT
WINAPI
CAUpdateCertType(
    IN HCERTTYPE           hCertType
    );

//
// CAUpdateCertType
// Write any changes made to the cert type back to the type store
//
// lpPara:-              is a pointer to an LDAP handle
//                           if dwFlags has CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                           and is NULL otherwise
// dwFlags:-                 CT_FLAG_SCOPE_IS_LDAP_HANDLE ,
//                                 0
//
HRESULT
WINAPI
CAUpdateCertTypeEx(
    IN  LPVOID     lpPara,
    IN  DWORD       dwFlags,
    IN HCERTTYPE           hCertType
    );



//
// CADeleteCertType
// Delete a CertType
//
// hCertType    - Cert type to delete.
//
// NOTE:  If this is called for a default cert type, it will revert back to its
// default attributes (if it has been modified)
//
HRESULT
WINAPI
CADeleteCertType(
    IN HCERTTYPE            hCertType
    );


//
// CADeleteCertType
// Delete a CertType
//
// hCertType    - Cert type to delete.
// lpPara:-              is a pointer to an LDAP handle
//                           if dwFlags has CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                           and is NULL otherwise
// dwFlags:-                 CT_FLAG_SCOPE_IS_LDAP_HANDLE ,
//                                 0
//
// NOTE:  If this is called for a default cert type, it will revert back to its
// default attributes (if it has been modified)
//
HRESULT
WINAPI
CADeleteCertTypeEx(
    IN  LPVOID     lpPara,
    IN  DWORD       dwFlags,
    IN HCERTTYPE            hCertType
    );



//
// CACloneCertType
//
// Clone a certificate type.  The returned certificate type is a clone of the 
// input certificate type, with the new cert type name and display name.  By default,
// if the input template is a template for machines, all 
// CT_FLAG_SUBJECT_REQUIRE_XXXX bits in the subject name flag are turned off.  
//                                   
// hCertType        - Cert type to be cloned.
// wszCertType      - Name of the new cert type.
// wszFriendlyName  - Friendly name of the new cert type.  Could be NULL.
// pvldap           - The LDAP handle (LDAP *) to the directory.  Could be NULL.
// dwFlags          - Can be an ORing of the following flags:
//
//                      CT_CLONE_KEEP_AUTOENROLLMENT_SETTING
//                      CT_CLONE_KEEP_SUBJECT_NAME_SETTING
//
HRESULT
WINAPI
CACloneCertType(
    IN  HCERTTYPE            hCertType,
    IN  LPCWSTR              wszCertType,
    IN  LPCWSTR              wszFriendlyName,
    IN  LPVOID               pvldap,
    IN  DWORD                dwFlags,
    OUT HCERTTYPE *          phCertType
    );


#define  CT_CLONE_KEEP_AUTOENROLLMENT_SETTING       0x01
#define  CT_CLONE_KEEP_SUBJECT_NAME_SETTING         0x02  


//
// CACreateCertType
// Create a new cert type
//
// wszCertType  - Name of the cert type
//
// pvPara     - If set is the LDAP handle to the DC.
//
// dwFlags      - reserved.  Must set to NULL.
//
// phCertType   - returned cert type
//
HRESULT
WINAPI
CACreateCertType(
    IN  LPCWSTR             wszCertType,
    IN  LPVOID                pvPara,
    IN  DWORD               dwFlags,
    OUT HCERTTYPE *         phCertType
    );


//
// CAEnumNextCertType
// Find the Next Cert Type in an enumeration.
//
// hPrevCertType        - Previous cert type in enumeration
//
// phCertType           - Pointer to a handle into which result is placed.
//			  NULL if there are no more cert types in enumeration.
//

HRESULT
WINAPI
CAEnumNextCertType(
    IN  HCERTTYPE          hPrevCertType,
    OUT HCERTTYPE *        phCertType
    );


//
// CACountCertTypes
// return the number of cert types in this enumeration
//

DWORD
WINAPI
CACountCertTypes(
    IN  HCERTTYPE  hCertType
    );


//
// CACloseCertType
// Close an open CertType handle
//

HRESULT
WINAPI
CACloseCertType(
    IN HCERTTYPE hCertType
    );


//
// CAGetCertTypeProperty
// Retrieve a property from a certificate type.   This function is obsolete.
// Caller should use CAGetCertTypePropertyEx instead
//
// hCertType            - Handle to an open CertType object.
//
// wszPropertyName      - Name of the CertType property.
//
// pawszPropertyValue   - A pointer into which an array of WCHAR strings is
//			  written, containing the values of the property.  The
//			  last element of the array points to NULL.  If the
//			  property is single valued, then the array returned
//			  contains 2 elements, the first pointing to the value,
//			  the second pointing to NULL.  This pointer must be
//                        freed by CAFreeCertTypeProperty.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CAGetCertTypeProperty(
    IN  HCERTTYPE   hCertType,
    IN  LPCWSTR     wszPropertyName,
    _Out_ PZPWSTR  *pawszPropertyValue);

//
// CAGetCertTypePropertyEx
// Retrieve a property from a certificate type.
//
// hCertType            - Handle to an open CertType object.
//
// wszPropertyName      - Name of the CertType property
//
// pPropertyValue       - Depending on the value of wszPropertyName,
//			  pPropertyValue is either DWORD * or LPWSTR **.  
// 
//                        It is a DWORD * for:
//                          CERTTYPE_PROP_REVISION              
//                          CERTTYPE_PROP_SCHEMA_VERSION		
//                          CERTTYPE_PROP_MINOR_REVISION        
//                          CERTTYPE_PROP_RA_SIGNATURE			
//                          CERTTYPE_PROP_MIN_KEY_SIZE	
//                          CERTTYPE_PROP_SYM_KEY_LENGTH
//		
//                        It is a LPWSTR ** for:
//                          CERTTYPE_PROP_CN                    
//                          CERTTYPE_PROP_DN                    
//                          CERTTYPE_PROP_FRIENDLY_NAME         
//                          CERTTYPE_PROP_EXTENDED_KEY_USAGE    
//                          CERTTYPE_PROP_CSP_LIST              
//                          CERTTYPE_PROP_CRITICAL_EXTENSIONS   
//                          CERTTYPE_PROP_OID					
//                          CERTTYPE_PROP_SUPERSEDE				
//                          CERTTYPE_PROP_RA_POLICY				
//                          CERTTYPE_PROP_POLICY
//                          CERTTYPE_PROP_DESCRIPTION
//                          CERTTYPE_PROP_ASYM_ALG
//                          CERTTYPE_PROP_SYM_ALG
//                          CERTTYPE_PROP_HASH_ALG
//				
//                        A pointer into which an array of WCHAR strings is
//			  written, containing the values of the property.  The
//			  last element of the array points to NULL.  If the
// 			  property is single valued, then the array returned
//			  contains 2 elements, the first pointing to the value,
//			  the second pointing to NULL. This pointer must be
//                        freed by CAFreeCertTypeProperty.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CAGetCertTypePropertyEx(
    IN  HCERTTYPE   hCertType,
    IN  LPCWSTR     wszPropertyName,
    OUT LPVOID      pPropertyValue);


//*****************************************************************************
//
// Certificate Type properties
// 
//*****************************************************************************

//*****************************************************************************
//
//  The schema version one properties
//
//*****************************************************************************

// Common name of the certificate type
#define CERTTYPE_PROP_CN                    L"cn"

// The common name of the certificate type.  Same as CERTTYPE_PROP_CN
// This property is not settable.
#define CERTTYPE_PROP_DN                    L"distinguishedName"

// The display name of a cert type retrieved from Crypt32 ( this accounts for the locale specific display names stored in OIDs)
#define CERTTYPE_PROP_FRIENDLY_NAME         L"displayName"

// The display name of the cert type stored in the template object in DS
#define CERTTYPE_PROP_DS_DISPLAY_NAME L"dsDisplayName"

// An array of extended key usage OIDs for a cert type
// NOTE: This property can also be set by setting
// the Extended Key Usage extension.
#define CERTTYPE_PROP_EXTENDED_KEY_USAGE    L"pKIExtendedKeyUsage"

// The list of default CSPs for this cert type.
#define CERTTYPE_PROP_CSP_LIST              L"pKIDefaultCSPs"

// The list of critical extensions
#define CERTTYPE_PROP_CRITICAL_EXTENSIONS   L"pKICriticalExtensions"

// The major version of the templates
#define CERTTYPE_PROP_REVISION              L"revision"

// The description of the templates
#define CERTTYPE_PROP_DESCRIPTION           L"templateDescription"

//*****************************************************************************
//
//  The schema version two properties
//
//*****************************************************************************
// The schema version of the templates
// This property may be changed from v3 to v2 or vice versa only.
#define CERTTYPE_PROP_SCHEMA_VERSION	    L"msPKI-Template-Schema-Version"

// The minor version of the templates
#define CERTTYPE_PROP_MINOR_REVISION        L"msPKI-Template-Minor-Revision"

// The number of RA signatures required on a request referencing this template.
#define CERTTYPE_PROP_RA_SIGNATURE	        L"msPKI-RA-Signature"

// The minimal key size required
#define CERTTYPE_PROP_MIN_KEY_SIZE	        L"msPKI-Minimal-Key-Size"

// The OID of this template
#define CERTTYPE_PROP_OID		            L"msPKI-Cert-Template-OID"

// The OID of the template that this template supersedes
#define CERTTYPE_PROP_SUPERSEDE		        L"msPKI-Supersede-Templates"

// The RA issuer policy OIDs required in certs used to sign a request.
// Each signing cert's szOID_CERT_POLICIES extensions must contain at least one
// of the OIDs listed in the msPKI-RA-Policies property.
// Each OID listed must appear in the szOID_CERT_POLICIES extension of at least
// one signing cert.
#define CERTTYPE_PROP_RA_POLICY		        L"msPKI-RA-Policies"

// The RA application policy OIDs required in certs used to sign a request.
// Each signing cert's szOID_APPLICATION_CERT_POLICIES extensions must contain
// all of the OIDs listed in the msPKI-RA-Application-Policies property.
#define CERTTYPE_PROP_RA_APPLICATION_POLICY L"msPKI-RA-Application-Policies"

// The certificate issuer policy OIDs are placed in the szOID_CERT_POLICIES
// extension by the policy module.
#define CERTTYPE_PROP_POLICY		        L"msPKI-Certificate-Policy"

// The certificate application policy OIDs are placed in the
// szOID_APPLICATION_CERT_POLICIES extension by the policy module.
#define CERTTYPE_PROP_APPLICATION_POLICY    L"msPKI-Certificate-Application-Policy"


//*****************************************************************************
//
//  The schema version three properties
//
//*****************************************************************************

// The name of the asymmetric algorithm.
#define CERTTYPE_PROP_ASYM_ALG                  L"msPKI-Asymmetric-Algorithm"

// Security descriptor string for the asymmetric key.
#define CERTTYPE_PROP_KEY_SECURITY_DESCRIPTOR   L"msPKI-Key-Security-Descriptor"

// The name of the symmetric algorithm used by clients for key exchange
#define CERTTYPE_PROP_SYM_ALG                   L"msPKI-Symmetric-Algorithm" 

// Length of the symmetric key in bits
#define CERTTYPE_PROP_SYM_KEY_LENGTH            L"msPKI-Symmetric-Key-Length"

// The name of the hash algorithm used by clients
#define CERTTYPE_PROP_HASH_ALG                  L"msPKI-Hash-Algorithm"

// Private Key KeyUsage
#define CERTTYPE_PROP_KEY_USAGE                  L"msPKI-Key-Usage"

#define CERTTYPE_SCHEMA_VERSION_1	1	
#define CERTTYPE_SCHEMA_VERSION_2	(CERTTYPE_SCHEMA_VERSION_1 + 1)
#define CERTTYPE_SCHEMA_VERSION_3	(CERTTYPE_SCHEMA_VERSION_2 + 1)
#define CERTTYPE_SCHEMA_VERSION_4	(CERTTYPE_SCHEMA_VERSION_3 + 1)
#define CERTTYPE_SCHEMA_VERSION_CURRENT	CERTTYPE_SCHEMA_VERSION_4


//
// CASetCertTypeProperty
// Set a property of a CertType.  This function is obsolete.  
// Use CASetCertTypePropertyEx.
//
// hCertType            - Handle to an open CertType object.
//
// wszPropertyName      - Name of the CertType property
//
// awszPropertyValue    - An array of values to set for this property.  The
//			  last element of this array should be NULL.  For
//			  single valued properties, the values beyond the first
//			  will be ignored upon update.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CASetCertTypeProperty(
    IN  HCERTTYPE   hCertType,
    IN  LPCWSTR     wszPropertyName,
    _In_ PZPWSTR awszPropertyValue
    );

//
// CASetCertTypePropertyEx
// Set a property of a CertType
//
// hCertType            - Handle to an open CertType object.
//
// wszPropertyName      - Name of the CertType property
//
// pPropertyValue       - Depending on the value of wszPropertyName,
//			  pPropertyValue is either DWORD * or LPWSTR *. 
// 
//                        It is a DWORD * for:
//                          CERTTYPE_PROP_REVISION              
//                          CERTTYPE_PROP_MINOR_REVISION        
//                          CERTTYPE_PROP_RA_SIGNATURE			
//                          CERTTYPE_PROP_MIN_KEY_SIZE	
//                          CERTTYPE_PROP_SYM_KEY_LENGTH
//
//                        It is a LPWSTR * for:
//                          CERTTYPE_PROP_FRIENDLY_NAME         
//                          CERTTYPE_PROP_EXTENDED_KEY_USAGE    
//                          CERTTYPE_PROP_CSP_LIST              
//                          CERTTYPE_PROP_CRITICAL_EXTENSIONS   
//                          CERTTYPE_PROP_OID					
//                          CERTTYPE_PROP_SUPERSEDE				
//                          CERTTYPE_PROP_RA_POLICY				
//                          CERTTYPE_PROP_POLICY
//                          CERTTYPE_PROP_ASYM_ALG
//                          CERTTYPE_PROP_SYM_ALG
//                          CERTTYPE_PROP_HASH_ALG
//				
//                      - An array of values to set for this property.  The
//			  last element of this array should be NULL.  For
//			  single valued properties, the values beyond the first
//			  will be ignored upon update.
//
//      
//                      - CertType of V1 schema can only set V1 properties.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CASetCertTypePropertyEx(
    IN  HCERTTYPE   hCertType,
    IN  LPCWSTR     wszPropertyName,
    IN  LPVOID      pPropertyValue);


//
// CADCSetCertTypePropertyEx
// Set a property of a CertType
//
// hCertType            - Handle to an open CertType object.
//
// wszPropertyName      - Name of the CertType property
//
// pPropertyValue       - Depending on the value of wszPropertyName,
//			  pPropertyValue is either DWORD * or LPWSTR *.
// pvldap               - Pointer to an LDAP handle, reqd while
//                        setting the CN property ( when we create a new OID)  
// 
//                        It is a DWORD * for:
//                          CERTTYPE_PROP_REVISION              
//                          CERTTYPE_PROP_MINOR_REVISION        
//                          CERTTYPE_PROP_RA_SIGNATURE			
//                          CERTTYPE_PROP_MIN_KEY_SIZE	
//                          CERTTYPE_PROP_SYM_KEY_LENGTH
//
//                        It is a LPWSTR * for:
//                          CERTTYPE_PROP_FRIENDLY_NAME         
//                          CERTTYPE_PROP_EXTENDED_KEY_USAGE    
//                          CERTTYPE_PROP_CSP_LIST              
//                          CERTTYPE_PROP_CRITICAL_EXTENSIONS   
//                          CERTTYPE_PROP_OID					
//                          CERTTYPE_PROP_SUPERSEDE				
//                          CERTTYPE_PROP_RA_POLICY				
//                          CERTTYPE_PROP_POLICY
//                          CERTTYPE_PROP_ASYM_ALG
//                          CERTTYPE_PROP_SYM_ALG
//                          CERTTYPE_PROP_HASH_ALG
//				
//                      - An array of values to set for this property.  The
//			  last element of this array should be NULL.  For
//			  single valued properties, the values beyond the first
//			  will be ignored upon update.
//
//      
//                      - CertType of V1 schema can only set V1 properties.
//
// Returns              - S_OK on success.
//

HRESULT
WINAPI
CADCSetCertTypePropertyEx(
    IN  HCERTTYPE   hCertType,
    IN  LPCWSTR     wszPropertyName,
    IN  LPVOID      pPropertyValue,
    IN OPTIONAL LPVOID  pvldap
    );


//
// CAFreeCertTypeProperty
// Frees a previously retrieved property value.
//
// hCertType            - Handle to an open CertType object.
//
// awszPropertyValue     - The values to be freed.
//
HRESULT
WINAPI
CAFreeCertTypeProperty(
    IN  HCERTTYPE   hCertType,
    _In_opt_ PZPWSTR awszPropertyValue
    );


//
// CAGetCertTypeExtensions
// Retrieves the extensions associated with this CertType.
//
// hCertType            - Handle to an open CertType object.
// ppCertExtensions     - Pointer to a PCERT_EXTENSIONS to receive the result
//			  of this call.  Should be freed via a
//			  CAFreeCertTypeExtensions call.
//

HRESULT
WINAPI
CAGetCertTypeExtensions(
    IN  HCERTTYPE           hCertType,
    OUT PCERT_EXTENSIONS *  ppCertExtensions
    );


//
// CAGetCertTypeExtensionsEx
// Retrieves the extensions associated with this CertType.
//
// hCertType            - Handle to an open CertType object.
// dwFlags              - Indicate which extension to be returned.
//                        Can be an ORing of following flags:
//                          
//                          CT_EXTENSION_TEMPLATE
//                          CT_EXTENSION_KEY_USAGE
//                          CT_EXTENSION_EKU
//                          CT_EXTENSION_BASIC_CONTRAINTS
//                          CT_EXTENSION_APPLICATION_POLICY (Version 2 template only)
//                          CT_EXTENSION_ISSUANCE_POLICY  (Version 2 template only)
//                          CT_EXTENSION_OCSP_REV_NO_CHECK (Version 2 template only)
//
//                        0 means all avaiable extension for this CertType.
//
// pParam               - optional LDAP Handle
// ppCertExtensions     - Pointer to a PCERT_EXTENSIONS to receive the result
//			  of this call.  Should be freed via a
//			  CAFreeCertTypeExtensions call.
//

HRESULT
WINAPI
CAGetCertTypeExtensionsEx(
    IN  HCERTTYPE           hCertType,
    IN  DWORD               dwFlags,
    IN  LPVOID              pParam,
    OUT PCERT_EXTENSIONS *  ppCertExtensions
    );


#define     CT_EXTENSION_TEMPLATE               0x01
#define     CT_EXTENSION_KEY_USAGE              0x02
#define     CT_EXTENSION_EKU                    0x04
#define     CT_EXTENSION_BASIC_CONTRAINTS       0x08
#define     CT_EXTENSION_APPLICATION_POLICY     0x10
#define     CT_EXTENSION_ISSUANCE_POLICY        0x20
#define     CT_EXTENSION_OCSP_REV_NO_CHECK      0x40



//
// CAFreeCertTypeExtensions
// Free a PCERT_EXTENSIONS allocated by CAGetCertTypeExtensions
//
HRESULT
WINAPI
CAFreeCertTypeExtensions(
    IN  HCERTTYPE           hCertType,
    IN  PCERT_EXTENSIONS    pCertExtensions
    );

//
// CASetCertTypeExtension
// Set the value of an extension for this
// cert type.
//
// hCertType            - handle to the CertType
//
// wszExtensionId       - OID for the extension
//
// dwFlags              - Mark the extension critical
//
// pExtension           - pointer to the appropriate extension structure
//
// Supported extensions/structures
//
// szOID_ENHANCED_KEY_USAGE     CERT_ENHKEY_USAGE
// szOID_KEY_USAGE              CRYPT_BIT_BLOB
// szOID_BASIC_CONSTRAINTS2     CERT_BASIC_CONSTRAINTS2_INFO
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CASetCertTypeExtension(
    IN HCERTTYPE   hCertType,
    IN LPCWSTR wszExtensionId,
    IN DWORD   dwFlags,
    IN LPVOID pExtension
    );

#define CA_EXT_FLAG_CRITICAL   0x00000001



//
// CAGetCertTypeFlags
// Retrieve cert type flags.  
// This function is obsolete.  Use CAGetCertTypeFlagsEx.
//
// hCertType            - handle to the CertType
//
// pdwFlags             - pointer to DWORD receiving flags
//

HRESULT
WINAPI
CAGetCertTypeFlags(
    IN  HCERTTYPE           hCertType,
    OUT DWORD *             pdwFlags
    );

//
// CAGetCertTypeFlagsEx
// Retrieve cert type flags
//
// hCertType            - handle to the CertType
//
// dwOption             - Which flag to set
//                        Can be one of the following:
//                        CERTTYPE_ENROLLMENT_FLAG
//                        CERTTYPE_SUBJECT_NAME_FLAG
//                        CERTTYPE_PRIVATE_KEY_FLAG
//                        CERTTYPE_GENERAL_FLAG
//
// pdwFlags             - pointer to DWORD receiving flags
//

HRESULT
WINAPI
CAGetCertTypeFlagsEx(
    IN  HCERTTYPE           hCertType,
    IN  DWORD               dwOption,
    OUT DWORD *             pdwFlags
    );


//*****************************************************************************
//
// Cert Type Flags
//
// The CertType flags are grouped into 4 categories:
//  1. Enrollment Flags (CERTTYPE_ENROLLMENT_FLAG)     
//	2. Certificate Subject Name Flags (CERTTYPE_SUBJECT_NAME_FLAG)  
//	3. Private Key Flags (CERTTYPE_PRIVATE_KEY_FLAG)    
//	4. General Flags (CERTTYPE_GENERAL_FLAG)        
//*****************************************************************************

//Enrollment Flags
#define CERTTYPE_ENROLLMENT_FLAG            0x01

//Certificate Subject Name Flags
#define CERTTYPE_SUBJECT_NAME_FLAG          0x02

//Private Key Flags
#define CERTTYPE_PRIVATE_KEY_FLAG           0x03

//General Flags
#define CERTTYPE_GENERAL_FLAG               0x04


// Used for certenroll.idl:
// certenroll_begin -- CT_FLAG_xxxx

//*****************************************************************************
//
// Enrollment Flags:
//
//*****************************************************************************
// Include the symmetric algorithms in the requests
#define CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS			0x00000001

// All certificate requests are pended
#define CT_FLAG_PEND_ALL_REQUESTS				0x00000002

// Publish the certificate to the KRA (key recovery agent container) on the DS
#define CT_FLAG_PUBLISH_TO_KRA_CONTAINER			0x00000004
		
// Publish the resultant cert to the userCertificate property in the DS
#define CT_FLAG_PUBLISH_TO_DS					0x00000008

// The autoenrollment will not enroll for new certificate if user has a certificate
// published on the DS with the same template name
#define CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE       0x00000010

// This cert is appropriate for auto-enrollment
#define CT_FLAG_AUTO_ENROLLMENT					0x00000020

// A previously issued certificate will valid subsequent enrollment requests
#define CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT         0x00000040

// Domain authentication is not required.  
#define CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED              0x00000080

// User interaction is required to enroll
#define CT_FLAG_USER_INTERACTION_REQUIRED                       0x00000100

// Add szOID_CERTTYPE_EXTENSION (template name) extension
// This flag will ONLY be set on V1 certificate templates for W2K CA only.
#define CT_FLAG_ADD_TEMPLATE_NAME		                0x00000200

// Remove invalid (expired or revoked) certificate from personal store
#define CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE  0x00000400

// Allow enroll-on-behalf-of; RA requirements still apply to signers
#define CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF  			0x00000800

// Add szOID_PKIX_OCSP_NOCHECK extension 
#define CT_FLAG_ADD_OCSP_NOCHECK				0x00001000

// Used by the enrollment client only, if key generation for renewal fails
// for a smart card then renewal will re-use the existing key
#define CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL	0x00002000

// Tells the CA that this certificate should not have the CDP extension and OCSP AIA extension
#define CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS 0x00004000

// Tells the CA to include the Basic Constraints extension
#define CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS 0x00008000

// For ROBO requests of Offline templates, tells the CA to ignore AccessCheck for the following reasons.
// a) The original request may not be in the CA database as the original cert may have been issued 
//    from a different CA in the enterprise.
// b) The original requestor account\permissions may not be valid anymore but the signer cert is valid.
// c) This flag also informs a KEYONLY CEP to select and return these templates
#define CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT 0x00010000

// Indicates that the Certificate Issuance Policies to be included in the issued certificate come from
// the request rather than the template.  The template contains a list of all of the issuance policies
// the request is allowed to specify -- if the request contains policies not listed in the template
// then the request is rejected.
#define CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST 0x00020000

// Indicates that the certificate should not be autorenewed although it has a valid template.  
// This flag is mainly for templates that deployed by MDM or VSC where the certificate cannot be autorenewed.
#define CT_FLAG_SKIP_AUTO_RENEWAL   0x00040000


//*****************************************************************************
//
// Certificate Subject Name Flags:
//
//*****************************************************************************

// The enrolling application must supply the subject name.
#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT			0x00000001

// The enrolling application must supply the subjectAltName in request
#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME		0x00010000

// Subject name should be full DN
#define CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH			0x80000000

// Subject name should be the common name
#define CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME			0x40000000

// Subject name includes the e-mail name
#define CT_FLAG_SUBJECT_REQUIRE_EMAIL				0x20000000

// Subject name includes the DNS name as the common name
#define CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN			0x10000000

// Subject alt name includes DNS name
#define CT_FLAG_SUBJECT_ALT_REQUIRE_DNS				0x08000000

// Subject alt name includes email name
#define CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL			0x04000000

// Subject alt name requires UPN
#define CT_FLAG_SUBJECT_ALT_REQUIRE_UPN				0x02000000

// Subject alt name requires directory GUID
#define CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID		0x01000000

// Subject alt name requires SPN
#define CT_FLAG_SUBJECT_ALT_REQUIRE_SPN                         0x00800000

// Subject alt name requires Domain DNS name
#define CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS                  0x00400000		

// Subject name should be copied from the renewing certificate
#define CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME          0x00000008	

//
// Obsolete name	
// The following flags are obsolete.  They are used by V1 templates in the
// general flags
//
#define CT_FLAG_IS_SUBJECT_REQ      CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

// The e-mail name of the principal will be added to the cert
#define CT_FLAG_ADD_EMAIL					0x00000002

// Add the object GUID for this principal
#define CT_FLAG_ADD_OBJ_GUID					0x00000004

// Add DS Name (full DN) to szOID_SUBJECT_ALT_NAME2 (Subj Alt Name 2) extension
// This flag is not SET in any of the V1 templates and is of no interests to
// V2 templates since it is not present on the UI and will never be set.
#define CT_FLAG_ADD_DIRECTORY_PATH				0x00000100


//*****************************************************************************
//
// Private Key Flags:
//
//*****************************************************************************

// Archival of the private key is required
#define CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL		0x00000001

// Make the key for this cert exportable.
#define CTPRIVATEKEY_FLAG_EXPORTABLE_KEY		        0x00000010

// Require the strong key protection UI when a new key is generated
#define CTPRIVATEKEY_FLAG_STRONG_KEY_PROTECTION_REQUIRED	0x00000020

// Require discrete signature algorithm when request is signed
// Implies RSA V2.1 signature format for RSA signatures
#define CTPRIVATEKEY_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM	0x00000040

// Renewal must re-use the same key (v4)
#define CTPRIVATEKEY_FLAG_REQUIRE_SAME_KEY_RENEWAL		0x00000080

// Use legacy CSP instead of CNG KSP (v4)
#define CTPRIVATEKEY_FLAG_USE_LEGACY_PROVIDER			0x00000100

// Attestation: allowed EK validation methods:
#define CTPRIVATEKEY_FLAG_EK_TRUST_ON_USE			0x00000200
#define CTPRIVATEKEY_FLAG_EK_VALIDATE_CERT			0x00000400
#define CTPRIVATEKEY_FLAG_EK_VALIDATE_KEY			0x00000800

// Attestation required/preferred/none:
#define CTPRIVATEKEY_FLAG_ATTEST_NONE				0x00000000
#define CTPRIVATEKEY_FLAG_ATTEST_PREFERRED			0x00001000
#define CTPRIVATEKEY_FLAG_ATTEST_REQUIRED			0x00002000
#define CTPRIVATEKEY_FLAG_ATTEST_MASK				0x00003000

#define CTPKSetAttestationLevel(f, v) \
    f = (((f) & ~CTPRIVATEKEY_FLAG_ATTEST_MASK) | (v) )

// Attestation without issuance policies
#define CTPRIVATEKEY_FLAG_ATTEST_WITHOUT_POLICY			0x00004000

// Minimum Template Server OS version:
#define CTPRIVATEKEY_FLAG_SERVERVERSION_MASK			0x000f0000
#define CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT			16

#define TEMPLATE_SERVER_VER_NONE	0
#define TEMPLATE_SERVER_VER_2003	1
#define TEMPLATE_SERVER_VER_2008	2
#define TEMPLATE_SERVER_VER_2008R2	3
#define TEMPLATE_SERVER_VER_WIN8	4
#define TEMPLATE_SERVER_VER_WINBLUE	5
#define TEMPLATE_SERVER_VER_THRESHOLD   6
#define TEMPLATE_SERVER_VER_CURRENT	TEMPLATE_SERVER_VER_THRESHOLD

// produces TEMPLATE_SERVER_VER_* values:
#define CTPKGetServerVersion(f)       (((f) & CTPRIVATEKEY_FLAG_SERVERVERSION_MASK) >> CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT)

#define CTPKSetServerVersion(f, v) \
    f = (((f) & ~CTPRIVATEKEY_FLAG_SERVERVERSION_MASK) | v << CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT)

// Convert CSVER_MAJOR_* to TEMPLATE_SERVER_VER_*
// CSVER_MAJOR increases in each release. TEMPLATE_SERVER_VER_* may or may not.
// Update the following macro if TEMPLATE_SERVER_VER_CURRENT stays the same
#define CS_MAJOR_VERSION_TO_TEMPLATE_SERVER_VERSION(v) (v - 1)

// Minimum Template Client OS version:
#define CTPRIVATEKEY_FLAG_CLIENTVERSION_MASK			0x0f000000
#define CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT			24

#define TEMPLATE_CLIENT_VER_NONE	0
#define TEMPLATE_CLIENT_VER_XP		1
#define TEMPLATE_CLIENT_VER_VISTA	2
#define TEMPLATE_CLIENT_VER_WIN7	3
#define TEMPLATE_CLIENT_VER_WIN8	4
#define TEMPLATE_CLIENT_VER_WINBLUE	5
#define TEMPLATE_CLIENT_VER_THRESHOLD   6
#define TEMPLATE_CLIENT_VER_CURRENT	TEMPLATE_CLIENT_VER_THRESHOLD

// produces TEMPLATE_CLIENT_VER_* values:
#define CTPKGetClientVersion(f)       (((f) & CTPRIVATEKEY_FLAG_CLIENTVERSION_MASK) >> CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT)

#define CTPKSetClientVersion(f, v) \
    f = (((f) & ~CTPRIVATEKEY_FLAG_CLIENTVERSION_MASK) | v << CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT)

#define CTPKIsCNGTemplate(s, f) \
    (CERTTYPE_SCHEMA_VERSION_3 == (s) ||	\
     (CERTTYPE_SCHEMA_VERSION_4 <= (s) &&	\
      0 == (CTPRIVATEKEY_FLAG_USE_LEGACY_PROVIDER & (f))))


//--------------------------------------------------------------
// For backwards compatibility only:
#define CT_FLAG_ALLOW_PRIVATE_KEY_ARCHIVAL	CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL
#define CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL	CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL
#define CT_FLAG_EXPORTABLE_KEY			CTPRIVATEKEY_FLAG_EXPORTABLE_KEY
#define CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED	CTPRIVATEKEY_FLAG_STRONG_KEY_PROTECTION_REQUIRED
#define CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM CTPRIVATEKEY_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM


//*****************************************************************************
//
// General Flags
//
//	More flags should start from 0x00002000
//
//*****************************************************************************
// This is a machine cert type
#define CT_FLAG_MACHINE_TYPE                0x00000040

// This is a CA	cert type
#define CT_FLAG_IS_CA                       0x00000080

// This is a cross CA cert type 
#define CT_FLAG_IS_CROSS_CA                 0x00000800

// Tells the CA that this certificate should not be persisted in
// the database if the CA is configured to do so.
#define CT_FLAG_DONOTPERSISTINDB	0x00001000





// The type is a default cert type (cannot be set).  This flag will be set on
// all V1 templates.  The templates can not be edited or deleted.
#define CT_FLAG_IS_DEFAULT                  0x00010000

// The type has been modified, if it is default (cannot be set)
#define CT_FLAG_IS_MODIFIED                 0x00020000

// settable flags for general flags
#define CT_MASK_SETTABLE_FLAGS              0x0000ffff


// certenroll_end

//
// CASetCertTypeFlags
// Sets the General Flags of a cert type.
// This function is obsolete.  Use CASetCertTypeFlagsEx.
//
// hCertType            - handle to the CertType
//
// dwFlags              - Flags to be set
//

HRESULT
WINAPI
CASetCertTypeFlags(
    IN HCERTTYPE           hCertType,
    IN DWORD               dwFlags
    );

//
// CASetCertTypeFlagsEx
// Sets the Flags of a cert type
//
// hCertType            - handle to the CertType
//
// dwOption             - Which flag to set
//                        Can be one of the following:
//                        CERTTYPE_ENROLLMENT_FLAG
//                        CERTTYPE_SUBJECT_NAME_FLAG
//                        CERTTYPE_PRIVATE_KEY_FLAG
//                        CERTTYPE_GENERAL_FLAG
//
// dwFlags              - Value to be set
//          

HRESULT
WINAPI
CASetCertTypeFlagsEx(
    IN HCERTTYPE           hCertType,
    IN DWORD               dwOption,
    IN DWORD               dwFlags
    );

//
// CAGetCertTypeKeySpec
// Retrieve the CAPI Key Spec for this cert type
//
// hCertType            - handle to the CertType
//
// pdwKeySpec           - pointer to DWORD receiving key spec
//

HRESULT
WINAPI
CAGetCertTypeKeySpec(
    IN  HCERTTYPE           hCertType,
    OUT DWORD *             pdwKeySpec
    );

//
// CACertTypeSetKeySpec
// Sets the CAPI1 Key Spec of a cert type
//
// hCertType            - handle to the CertType
//
// dwKeySpec            - KeySpec to be set
//

HRESULT
WINAPI
CASetCertTypeKeySpec(
    IN HCERTTYPE            hCertType,
    IN DWORD                dwKeySpec
    );

//
// CAGetCertTypeExpiration
// Retrieve the Expiration Info for this cert type
//
// pftExpiration        - pointer to the FILETIME structure receiving
//                        the expiration period for this cert type.
//
// pftOverlap           - pointer to the FILETIME structure receiving the
//			  suggested renewal overlap period for this cert type.
//

HRESULT
WINAPI
CAGetCertTypeExpiration(
    IN  HCERTTYPE           hCertType,
    OUT OPTIONAL FILETIME * pftExpiration,
    OUT OPTIONAL FILETIME * pftOverlap
    );

//
// CASetCertTypeExpiration
// Set the Expiration Info for this cert type
//
// pftExpiration        - pointer to the FILETIME structure containing
//                        the expiration period for this cert type.
//
// pftOverlap           - pointer to the FILETIME structure containing the
//			  suggested renewal overlap period for this cert type.
//

HRESULT
WINAPI
CASetCertTypeExpiration(
    IN  HCERTTYPE           hCertType,
    IN OPTIONAL FILETIME  * pftExpiration,
    IN OPTIONAL FILETIME  * pftOverlap
    );
//
// CACertTypeSetSecurity
// Set the list of Users, Groups, and Machines allowed
// to access this cert type.
//
// hCertType            - handle to the CertType
//
// pSD                  - Security descriptor for this cert type
//

HRESULT
WINAPI
CACertTypeSetSecurity(
    IN HCERTTYPE               hCertType,
    IN PSECURITY_DESCRIPTOR    pSD
    );


//
// CACertTypeGetSecurity
// Get the list of Users, Groups, and Machines allowed
// to access this cert type.
//
// hCertType            - handle to the CertType
//
// ppaSidList           - Pointer to a location receiving the pointer to the
//			  security descriptor.  Free via LocalFree.
//

HRESULT
WINAPI
CACertTypeGetSecurity(
    IN  HCERTTYPE                  hCertType,
    OUT PSECURITY_DESCRIPTOR *     ppSD
    );

//
//
// CACertTypeAccessCheck
// Determine whether the principal specified by
// ClientToken can be issued this cert type.
//
// hCertType            - handle to the CertType
//
// ClientToken          - Handle to an impersonation token that represents the
//			  client attempting to request this cert type.  The
//			  handle must have TOKEN_QUERY access to the token;
//                        otherwise, the call fails with ERROR_ACCESS_DENIED.
//
// Return: S_OK on success
//

HRESULT
WINAPI
CACertTypeAccessCheck(
    IN HCERTTYPE    hCertType,
    IN HANDLE       ClientToken
    );

//
//
// CACertTypeAccessCheckEx
// Determine whether the principal specified by
// ClientToken can be issued this cert type.
//
// hCertType            - handle to the CertType
//
// ClientToken          - Handle to an impersonation token that represents the
//			  client attempting to request this cert type.  The
//			  handle must have TOKEN_QUERY access to the token;
//                        otherwise, the call fails with ERROR_ACCESS_DENIED.
//
// dwOption             - Can be one of the following:
//                        CERTTYPE_ACCESS_CHECK_ENROLL
//                        CERTTYPE_ACCESS_CHECK_AUTO_ENROLL
//                        CERTTYPE_ACCESS_CHECK_WRITE_DAC
//                        CERTTYPE_ACCESS_CHECK_CHANGE_OWNER
//                      
//                      dwOption can be ORed with CERTTYPE_ACCESS_CHECK_NO_MAPPING
//                      to disallow default mapping of client token
//
// Return: S_OK on success
//

HRESULT
WINAPI
CACertTypeAccessCheckEx(
    IN HCERTTYPE    hCertType,
    IN HANDLE       ClientToken,
    IN DWORD        dwOption
    );


//
//
// CACertTypeAuthzAccessCheck
// Determine whether the principal specified by
// AuthzClientToken can be issued this cert type.
//
// hCertType            - handle to the CertType
//
// AuthzClientToken          - Handle to an Authztoken that represents the
//			  client attempting to request this cert type.  
//
// dwOption             - Can be one of the following:
//                        CERTTYPE_ACCESS_CHECK_ENROLL
//                        CERTTYPE_ACCESS_CHECK_AUTO_ENROLL
//                      
//
// Return: S_OK on success
//

HRESULT
WINAPI
CACertTypeAuthzAccessCheck(
    IN HCERTTYPE    hCertType,
    IN  PVOID         AuthzClientToken,
    IN DWORD        dwOption
    );



#define CERTTYPE_ACCESS_CHECK_ENROLL        0x01
#define CERTTYPE_ACCESS_CHECK_AUTO_ENROLL   0x02
#define CERTTYPE_ACCESS_CHECK_READ          0x04
#define CERTTYPE_ACCESS_CHECK_WRITE_DAC  0x08
#define CERTTYPE_ACCESS_CHECK_CHANGE_OWNER 0x10

#define CERTTYPE_ACCESS_CHECK_NO_MAPPING    0x00010000


//
// CAGetCertTypeAccessRights
//
// Determine the access rights of the HCertType based on the current context
//
// hCertType        - Handle to the CertType
//
// dwContext    - Can be one of the following:
//                 CA_CONTEXT_CURREN 
//                 CA_CONTEXT_ADMINISTRATOR_FORCE_MACHINE
//
// pdwAccessRight- Oring of the following flags:
//                 CA_ACCESS_RIGHT_READ
//                 CA_ACCESS_RIGH_ENROLL
//                 CA_ACCESS_RIGHT_AUTO_ENROLL
//
//
// Return: S_OK on success
//
HRESULT
WINAPI
CAGetCertTypeAccessRights(
    IN  HCERTTYPE    hCertType,
    IN  DWORD        dwContext,
    OUT DWORD        *pdwAccessRights 
    );


// CAIsCertTypeValid
//
// Determine if the HCERTTYPE has full properties and readable
// from the current context.  For CertTypes that are not readable from
// current context, only CERTTYPE_PROP_CN are present
//
// hCertType        - Handle to the CertType
//
// pValid           - TRUE is the CertType is readable
//
// Return: S_OK on success
//
HRESULT
WINAPI
CAIsCertTypeValid(
    IN  HCERTTYPE    hCertType,
    OUT BOOL        *pValid
    );


//
//
// CAInstallDefaultCertType
//
// Install default certificate types on the enterprise.  
//
// dwFlags            - Reserved.  Must be 0 for now
//
//
// Return: S_OK on success
//
HRESULT
WINAPI
CAInstallDefaultCertType(
    IN DWORD dwFlags
    );

//
//
// CAInstallDefaultCertTypeEx
//
// Install default certificate types on the enterprise.  
//
// lpPara:-              is a pointer to an LDAP handle
//                           if dwFlags has CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                           and is NULL otherwise
// dwFlags:-                 CT_FLAG_SCOPE_IS_LDAP_HANDLE ,
//                                 0
//
//
// Return: S_OK on success
//
HRESULT
WINAPI
CAInstallDefaultCertTypeEx(
    IN LPVOID lpPara,
    IN DWORD dwFlags
    );


//
//
// CAIsCertTypeCurrent
//
// Check if the certificate type on the DS is up to date 
//
// dwFlags            - Reserved.  Must be 0 for now
// wszCertType        - The name for the certificate type
//
// Return: TRUE if the cert type is update to date
//
BOOL
WINAPI
CAIsCertTypeCurrent(
    IN DWORD    dwFlags,
    _In_ LPWSTR   wszCertType   
    );


//
//
// CAIsCertTypeCurrentEx
//
// Check if the certificate type on the DS is up to date 
//
// lpPara:-              is a pointer to an LDAP handle
//                           if dwFlags has CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                           and is NULL otherwise
// dwFlags:-                 CT_FLAG_SCOPE_IS_LDAP_HANDLE ,
//                                 0
// wszCertType        - The name for the certificate type
//
// Return: TRUE if the cert type is update to date
//
BOOL
WINAPI
CAIsCertTypeCurrentEx(
    IN LPVOID lpPara,
    IN DWORD    dwFlags,
    _In_ LPWSTR   wszCertType   
    );






//*****************************************************************************
//
//  OID management APIs
//
//*****************************************************************************
//
// CAOIDCreateNew
// Create a new OID based on the enterprise base
//
// dwType                - Can be one of the following:
//                        CERT_OID_TYPE_TEMPLATE			
//                        CERT_OID_TYPE_ISSUER_POLICY
//                        CERT_OID_TYPE_APPLICATION_POLICY
//
// dwFlag               - Reserved.  Must be 0.
//
// ppwszOID             - Return the new OID.  Free memory via LocalFree().
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDCreateNew(
    IN	DWORD   dwType,
    IN  DWORD   dwFlag,
    _Outptr_ LPWSTR	*ppwszOID);


// CAOIDCreateNewEx
// Create a new OID based on the enterprise base
//
// dwType                - Can be one of the following:
//                        CERT_OID_TYPE_TEMPLATE			
//                        CERT_OID_TYPE_ISSUER_POLICY
//                        CERT_OID_TYPE_APPLICATION_POLICY
//
// dwFlag               - CA_FLAG_SCOPE_IS_LDAP_HANDLE or 0.
// lpPara			    - if dwFlag is CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                        then this is the LDAP handle otherwise this is NULL                              
//
// ppwszOID             - Return the new OID.  Free memory via LocalFree().
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDCreateNewEx(
    IN	DWORD   dwType,
    IN  DWORD   dwFlag,
    _In_opt_  LPVOID lpPara,    
    _Outptr_ LPWSTR	*ppwszOID);




#define CERT_OID_TYPE_TEMPLATE			0x01
#define CERT_OID_TYPE_ISSUER_POLICY		0x02
#define CERT_OID_TYPE_APPLICATION_POLICY	0x03

//
// CAOIDAdd
// Add an OID to the DS repository
//
// dwType               - Can be one of the following:
//                        CERT_OID_TYPE_TEMPLATE			
//                        CERT_OID_TYPE_ISSUER_POLICY
//                        CERT_OID_TYPE_APPLICATION_POLICY
//
// dwFlag               - Reserved.  Must be 0.
//
// pwszOID              - The OID to add.
//
// Returns S_OK if successful.
// Returns CRYPT_E_EXISTS if the OID alreay exits in the DS repository
//

HRESULT
WINAPI
CAOIDAdd(
    IN	DWORD       dwType,
    IN  DWORD       dwFlag,
    IN  LPCWSTR	    pwszOID);


//
// CAOIDAddEx
// Add an OID to the DS repository
//
// dwType               - Can be one of the following:
//                        CERT_OID_TYPE_TEMPLATE			
//                        CERT_OID_TYPE_ISSUER_POLICY
//                        CERT_OID_TYPE_APPLICATION_POLICY
//
// dwFlag               - CA_FLAG_SCOPE_IS_LDAP_HANDLE or 0.
// lpPara			    - if dwFlag is CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                        then this is the LDAP handle otherwise this is NULL     
//
// pwszOID              - The OID to add.
//
// Returns S_OK if successful.
// Returns CRYPT_E_EXISTS if the OID alreay exits in the DS repository
//

HRESULT
WINAPI
CAOIDAddEx(
    IN	DWORD       dwType,
    IN  DWORD       dwFlag,
    _In_opt_  LPVOID      lpPara,
    IN  LPCWSTR	    pwszOID);




//
// CAOIDDelete
// Delete the OID from the DS repository
//
// pwszOID              - The OID to delete.
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDDelete(
    IN LPCWSTR	pwszOID);

//
// CAOIDDeleteEx
// Delete the OID from the DS repository
//
// dwFlag               - CA_FLAG_SCOPE_IS_LDAP_HANDLE or 0.
// lpPara			    - if dwFlag is CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                        then this is the LDAP handle otherwise this is NULL       
// pwszOID              - The OID to delete.
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDDeleteEx(
    IN  DWORD   dwFlag,
    _In_opt_  LPVOID lpPara, 
    IN LPCWSTR	pwszOID);

//
// CAOIDSetProperty
// Set a property on an OID.  
//
// pwszOID              - The OID whose value is set
// dwProperty           - The property name.  Can be one of the following:
//                        CERT_OID_PROPERTY_DISPLAY_NAME
//                        CERT_OID_PROPERTY_CPS
//
// pPropValue           - The value of the property.
//                        If dwProperty is CERT_OID_PROPERTY_DISPLAY_NAME,
//                        pPropValue is LPWSTR. 
//                        if dwProperty is CERT_OID_PROPERTY_CPS,
//                        pPropValue is LPWSTR.  
//                        NULL will remove the property
//
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDSetProperty(
    IN  LPCWSTR pwszOID,
    IN  DWORD   dwProperty,
    IN  LPVOID  pPropValue);


//
// CAOIDSetPropertyEx
// Set a property on an OID.  
//
// dwFlag               - CA_FLAG_SCOPE_IS_LDAP_HANDLE or 0.
// lpPara			    - if dwFlag is CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                        then this is the LDAP handle otherwise this is NULL  
//
// pwszOID              - The OID whose value is set
// dwProperty           - The property name.  Can be one of the following:
//                        CERT_OID_PROPERTY_DISPLAY_NAME
//                        CERT_OID_PROPERTY_CPS
//
// pPropValue           - The value of the property.
//                        If dwProperty is CERT_OID_PROPERTY_DISPLAY_NAME,
//                        pPropValue is LPWSTR. 
//                        if dwProperty is CERT_OID_PROPERTY_CPS,
//                        pPropValue is LPWSTR.  
//                        NULL will remove the property
//
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDSetPropertyEx(
    IN  DWORD   dwFlag,
    _In_opt_  LPVOID lpPara, 
    IN  LPCWSTR pwszOID,
    IN  DWORD   dwProperty,
    IN  LPVOID  pPropValue);




#define CERT_OID_PROPERTY_DISPLAY_NAME      0x01
#define CERT_OID_PROPERTY_CPS               0x02
#define CERT_OID_PROPERTY_TYPE              0x03

//
// CAOIDGetProperty
// Get a property on an OID.  
//
// pwszOID              - The OID whose value is queried
// dwProperty           - The property name.  Can be one of the following:
//                        CERT_OID_PROPERTY_DISPLAY_NAME
//                        CERT_OID_PROPERTY_CPS
//                        CERT_OID_PROPERTY_TYPE
//
// pPropValue           - The value of the property.
//                        If dwProperty is CERT_OID_PROPERTY_DISPLAY_NAME,
//                        pPropValue is LPWSTR *.  
//                        if dwProperty is CERT_OID_PROPERTY_CPS, pPropValue is
//			  LPWSTR *. 
//
//                        Free the above properties via CAOIDFreeProperty().
//
//                        If dwProperty is CERT_OID_PROPERTY_TYPE, pPropValue
//			  is DWORD *. 
//
// Returns S_OK if successful.
//
HRESULT
WINAPI
CAOIDGetProperty(
    IN  LPCWSTR pwszOID,
    IN  DWORD   dwProperty,
    OUT LPVOID  pPropValue);


//
// CAOIDGetPropertyEx
// Get a property on an OID.  
//
// dwFlag               - CA_FLAG_SCOPE_IS_LDAP_HANDLE or 0.
// lpPara			    - if dwFlag is CT_FLAG_SCOPE_IS_LDAP_HANDLE
//                        then this is the LDAP handle otherwise this is NULL  
//
// pwszOID              - The OID whose value is queried
// dwProperty           - The property name.  Can be one of the following:
//                        CERT_OID_PROPERTY_DISPLAY_NAME
//                        CERT_OID_PROPERTY_CPS
//                        CERT_OID_PROPERTY_TYPE
//
// pPropValue           - The value of the property.
//                        If dwProperty is CERT_OID_PROPERTY_DISPLAY_NAME,
//                        pPropValue is LPWSTR *.  
//                        if dwProperty is CERT_OID_PROPERTY_CPS, pPropValue is
//			  LPWSTR *. 
//
//                        Free the above properties via CAOIDFreeProperty().
//
//                        If dwProperty is CERT_OID_PROPERTY_TYPE, pPropValue
//			  is DWORD *. 
//
// Returns S_OK if successful.
//
HRESULT
WINAPI
CAOIDGetPropertyEx(
    IN  DWORD   dwFlag,
    _In_opt_  LPVOID lpPara, 
    IN  LPCWSTR pwszOID,
    IN  DWORD   dwProperty,
    OUT LPVOID  pPropValue);




//
// CAOIDFreeProperty
// Free a property returned from CAOIDGetProperty  
//
// pPropValue           - The value of the property.
//
// Returns S_OK if successful.
//

HRESULT
WINAPI
CAOIDFreeProperty(
    IN LPVOID  pPropValue);

//
// CAOIDGetLdapURL
// 
// Return the LDAP URL for OID repository.  In the format of 
// LDAP:///DN of the Repository/all attributes?one?filter.  The filter
// is determined by dwType.
//
// dwType               - Can be one of the following:
//                        CERT_OID_TYPE_TEMPLATE			
//                        CERT_OID_TYPE_ISSUER_POLICY
//                        CERT_OID_TYPE_APPLICATION_POLICY
//                        CERT_OID_TYPE_ALL
//
// dwFlag               - Reserved.  Must be 0.
//
// ppwszURL             - Return the URL.  Free memory via CAOIDFreeLdapURL.
//
// Returns S_OK if successful.
//
HRESULT
WINAPI
CAOIDGetLdapURL(
    IN  DWORD   dwType,
    IN  DWORD   dwFlag,
    _Outptr_ LPWSTR  *ppwszURL);

#define CERT_OID_TYPE_ALL           0x0

//
// CAOIDFreeLDAPURL
// Free the URL returned from CAOIDGetLdapURL
//
// pwszURL      - The URL returned from CAOIDGetLdapURL
//
// Returns S_OK if successful.
//
HRESULT
WINAPI
CAOIDFreeLdapURL(
    IN LPCWSTR      pwszURL);


//the LDAP properties for OID class
#define OID_PROP_TYPE                   L"flags"
#define OID_PROP_TYPE_A                 "flags"

#define OID_PROP_OID                    L"msPKI-Cert-Template-OID"
#define OID_PROP_OID_A                  "msPKI-Cert-Template-OID"

#define OID_PROP_DISPLAY_NAME           L"displayName"
#define OID_PROP_DISPLAY_NAME_A         "displayName"

#define OID_PROP_CPS                    L"msPKI-OID-CPS"
#define OID_PROP_CPS_A                  "msPKI-OID-CPS"

#define OID_PROP_LOCALIZED_NAME         L"msPKI-OIDLocalizedName"
#define OID_PROP_LOCALIZED_NAME_A       "msPKI-OIDLocalizedName"

#define CT_QUERY_REGISTER_CERTTYPE_CHANGE_FLAG 0x00000001
#define CT_QUERY_REGISTER_CA_CHANGE_FLAG 0x00000002

//*****************************************************************************
//
//  Cert Type Change Query APIS
//
//*****************************************************************************
//
// CACertTypeRegisterQuery
// 
//      Regiser the calling thread to query if any modification has happened
//  to cert type information on the directory
//
//
// dwFlag               - CT_QUERY_REGISTER_CERTTYPE_CHANGE_FLAG or
//                        CT_QUERY_REGISTER_CA_CHANGE_FLAG                        
//
// pvldap               - The LDAP handle to the directory (LDAP *).  Optional input.
//                        If pvldap is not NULL, then the caller has to call
//                        CACertTypeUnregisterQuery before unbind the pldap.
//
// pHCertTypeQuery      - Receive the HCERTTYPEQUERY handle upon success.
//
// Returns S_OK if successful.
//
//
HRESULT
WINAPI
CACertTypeRegisterQuery(
    IN	DWORD               dwFlag,
    IN  LPVOID              pvldap,
    OUT HCERTTYPEQUERY      *phCertTypeQuery);



//
// CACertTypeQuery
// 
//      Returns a change sequence number which is incremented by 1 whenever
// cert type information on the directory is changed.     
//
// hCertTypeQuery               -  The hCertTypeQuery returned from previous
//                                  CACertTypeRegisterQuery  calls.
//
// *pdwChangeSequence           -  Returns a DWORD, which is incremented by 1 
//                                  whenever any changes has happened to cert type 
//                                  information on the directory since the last 
//                                  call to CACertTypeRegisterQuery or CACertTypeQuery.
//
//
//
// Returns S_OK if successful.
//
//
HRESULT
WINAPI
CACertTypeQuery(
    IN	HCERTTYPEQUERY  hCertTypeQuery,
    OUT DWORD           *pdwChangeSequence);



//
// CACertTypeUnregisterQuery
// 
//      Unregister the calling thread to query if any modification has happened
//  to cert type information on the directory
//
//
// hCertTypeQuery               -  The hCertTypeQuery returned from previous
//                                  CACertTypeRegisterQuery calls.
//
// Returns S_OK if successful.
//
//
HRESULT
WINAPI
CACertTypeUnregisterQuery(
    IN	HCERTTYPEQUERY  hCertTypeQuery);


//*****************************************************************************
//
//  Autoenrollment APIs
//
//*****************************************************************************

//
// CACreateLocalAutoEnrollmentObject
// Create an auto-enrollment object on the local machine.
//
// pwszCertType - The name of the certificate type for which to create the
//		  auto-enrollment object
//
// awszCAs      - The list of CAs to add to the auto-enrollment object with the
//		  last entry in the list being NULL.  If the list is NULL or
//		  empty, then it create an auto-enrollment object which
//		  instructs the system to enroll for a cert at any CA
//		  supporting the requested certificate type.
//
// pSignerInfo  - not used, must be NULL.
//
// dwFlags      - can be CERT_SYSTEM_STORE_CURRENT_USER or
//		  CERT_SYSTEM_STORE_LOCAL_MACHINE, indicating auto-enrollment
//		  store in which the auto-enrollment object is created.
//
// Return:      S_OK on success.
//

HRESULT
WINAPI
CACreateLocalAutoEnrollmentObject(
    IN LPCWSTR                              pwszCertType,
    _In_opt_z_ PWSTR *                      awszCAs,
    IN OPTIONAL PCMSG_SIGNED_ENCODE_INFO    pSignerInfo,
    IN DWORD                                dwFlags);

//
// CADeleteLocalAutoEnrollmentObject
// Delete an auto-enrollment object on the local machine.
//
// pwszCertType - The name of the certificate type for which to delete the
//		  auto-enrollment object
//
// awszCAs      - not used. must be NULL.  All callers to CACreateLocalAutoEnrollmentObject
//                have supplied NULL.
//
// pSignerInfo  - not used, must be NULL.
//
// dwFlags      - can be CERT_SYSTEM_STORE_CURRENT_USER or
//		  CERT_SYSTEM_STORE_LOCAL_MACHINE, indicating auto-enrollment
//		  store in which the auto-enrollment object is deleted.
//
// Return:      S_OK on success.
//

HRESULT
WINAPI
CADeleteLocalAutoEnrollmentObject(
    IN LPCWSTR                              pwszCertType,
    _In_opt_z_ PWSTR *                      awszCAs,
    IN OPTIONAL PCMSG_SIGNED_ENCODE_INFO    pSignerInfo,
    IN DWORD                                dwFlags);


//
// CACreateAutoEnrollmentObjectEx
// Create an auto-enrollment object in the indicated store.
//
// pwszCertType - The name of the certificate type for which to create the
//		  auto-enrollment object
//
// pwszObjectID - An identifying string for this autoenrollment object.  NULL
//		  may be passed if this object is simply to be identified by
//		  its certificate template.  An autoenrollment object is
//		  identified by a combination of its object id and its cert
//		  type name.
//
// awszCAs      - The list of CAs to add to the auto-enrollment object, with
//		  the last entry in the list being NULL.  If the list is NULL
//		  or empty, then it create an auto-enrollment object which
//		  instructs the system to enroll for a cert at any CA
//		  supporting the requested certificate type.
//
// pSignerInfo  - not used, must be NULL.
//
// StoreProvider - see CertOpenStore
//
// dwFlags      - see CertOpenStore
//
// pvPara       - see CertOpenStore
//
// Return:      S_OK on success.
//
//

HRESULT
WINAPI
CACreateAutoEnrollmentObjectEx(
    IN LPCWSTR                     pwszCertType,
    IN LPCWSTR                     wszObjectID,
    _In_z_ PWSTR *                 awszCAs,
    IN PCMSG_SIGNED_ENCODE_INFO    pSignerInfo,
    IN LPCSTR                      StoreProvider,
    IN DWORD                       dwFlags,
    IN const void *                pvPara);



typedef struct _CERTSERVERENROLL
{
    DWORD   Disposition;
    HRESULT hrLastStatus;
    DWORD   RequestId;
    BYTE   *pbCert;
    DWORD   cbCert;
    BYTE   *pbCertChain;
    DWORD   cbCertChain;
    WCHAR  *pwszDispositionMessage;
} CERTSERVERENROLL;


//*****************************************************************************
//
// Cert Server RPC interfaces:
//
//*****************************************************************************

HRESULT
WINAPI
CertServerSubmitRequest(
    _In_ DWORD Flags,
    _In_ BYTE const *pbRequest,
    _In_ DWORD cbRequest,
    _In_opt_ PCWSTR pwszRequestAttributes,
    _In_ PCWSTR pwszServerName,
    _In_ PCWSTR pwszAuthority,
    _Outptr_ CERTSERVERENROLL **ppcsEnroll); // free via CertServerFreeMemory

HRESULT
WINAPI
CertServerRetrievePending(
    _In_ DWORD RequestId,
    _In_opt_ PCWSTR pwszSerialNumber,
    _In_ PCWSTR pwszServerName,
    _In_ PCWSTR pwszAuthority,
    _Outptr_ CERTSERVERENROLL **ppcsEnroll); // free via CertServerFreeMemory

VOID
WINAPI
CertServerFreeMemory(
    _In_ VOID *pv);


enum ENUM_PERIOD
{
    ENUM_PERIOD_INVALID = -1,
    ENUM_PERIOD_SECONDS = 0,
    ENUM_PERIOD_MINUTES,
    ENUM_PERIOD_HOURS,
    ENUM_PERIOD_DAYS,
    ENUM_PERIOD_WEEKS,
    ENUM_PERIOD_MONTHS,
    ENUM_PERIOD_YEARS
};

typedef struct _PERIODUNITS
{
    LONG             lCount;
    enum ENUM_PERIOD enumPeriod;
} PERIODUNITS;


#define TFTP_EXACT		TRUE
#define TFTP_ACCEPTZERO		0x00000002

HRESULT
caTranslateFileTimePeriodToPeriodUnits(
    IN FILETIME const *pftGMT,
    IN BOOL Flags,		// Win7: was BOOL fExact
    OUT DWORD *pcPeriodUnits,
    OUT PERIODUNITS **prgPeriodUnits);

HRESULT
WINAPI
IsRequestConnectionLocal(
    _In_ LPCWSTR pcwszConfig,
    _Out_ BOOL* pfLocal);

BOOL
WINAPI
myNetLogonUser(
    _In_opt_ PCWSTR UserName,
    _In_opt_ PCWSTR DomainName,
    _In_opt_ PCWSTR Password,
    _Out_ PHANDLE phToken);

#ifdef __cplusplus
}
#endif
#endif //__CERTCA_H__
