#include <windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <rpc.h>
#include <lm.h>
#include <sddl.h>
#include <rpcdce.h>
#include <stdint.h>
#define DYNAMIC_LIB_COUNT 1
#include "bofdefs.h"
#include "base.c"
#define SECURITY_WIN32
#include <secext.h> 

#define MAX_ATTRIBUTES 100

typedef long (*_fuuidtostring)(UUID *Uuid,RPC_CSTR *StringUuid);
typedef long (*_RpcStringFreeA)(RPC_CSTR *String);
typedef ULONG LDAPAPI (*_ldap_search_abondon_page)(PLDAP h, PLDAPSearch S);
_fuuidtostring fuuidtostring = (void *)1;
_RpcStringFreeA frpcstringfree = (void *)1;
HMODULE rpcrt = (void *)1; 

typedef LDAP *LDAPAPI (*ldap_init_t)(PSTR HostName, ULONG PortNumber);
typedef ULONG LDAPAPI (*ldap_bind_s_t)(LDAP *ld, const PSTR dn, const PCHAR cred, ULONG method);
typedef ULONG LDAPAPI (*ldap_unbind_t)(LDAP*);
typedef ULONG LDAPAPI (*ldap_msgfree_t)(LDAPMessage*);
typedef VOID LDAPAPI (*ldap_memfree_t)(PCHAR);
typedef LDAPMessage* (*ldap_first_entry_t)(LDAP *ld,LDAPMessage *res);
typedef ULONG LDAPAPI (*ldap_get_next_page_s_t)(PLDAP ExternalHandle,PLDAPSearch SearchHandle,struct l_timeval *timeout,ULONG PageSize,ULONG *TotalCount,LDAPMessage **Results);
typedef ULONG LDAPAPI (*ldap_count_entries_t)(LDAP*,LDAPMessage*);
typedef LDAPMessage*  (*ldap_next_entry_t)(LDAP*,LDAPMessage*);
typedef PCHAR LDAPAPI (*ldap_first_attribute_t)(LDAP *ld,LDAPMessage *entry,BerElement **ptr);
typedef struct berval **LDAPAPI (*ldap_get_values_lenA_t)(LDAP *ExternalHandle,LDAPMessage *Message,const PCHAR attr);
typedef PCHAR * LDAPAPI (*ldap_get_values_t)(LDAP *ld,LDAPMessage *entry,const PSTR attr);
typedef ULONG LDAPAPI (*ldap_value_free_len_t)(struct berval **vals);
typedef ULONG LDAPAPI (*ldap_value_free_t)(PCHAR *);
typedef PCHAR LDAPAPI (*ldap_next_attribute_t)(LDAP *ld,LDAPMessage *entry,BerElement *ptr);
typedef PLDAPSearch LDAPAPI (*ldap_search_init_pageA_t)(PLDAP ExternalHandle,const PCHAR DistinguishedName,ULONG ScopeOfSearch,const PCHAR SearchFilter,PCHAR AttributeList[],ULONG AttributesOnly,PLDAPControlA *ServerControls,PLDAPControlA *ClientControls,ULONG PageTimeLimit,ULONG TotalSizeLimit,PLDAPSortKeyA *SortKeys);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBERAPI BerElement *BERAPI WLDAP32$ber_alloc_t(INT options);
WINBERAPI INT BERAPI WLDAP32$ber_printf(BerElement *pBerElement, PSTR fmt, ...);
WINBERAPI INT BERAPI WLDAP32$ber_flatten(BerElement *pBerElement, PBERVAL *pBerVal);
WINLDAPAPI VOID LDAPAPI WLDAP32$ber_bvfree(PBERVAL bv);

#define WLDAP32$ldap_init ((ldap_init_t)DynamicLoad("WLDAP32", "ldap_init"))
#define WLDAP32$ldap_bind_s ((ldap_bind_s_t)DynamicLoad("WLDAP32", "ldap_bind_s"))
#define WLDAP32$ldap_unbind ((ldap_unbind_t)DynamicLoad("WLDAP32", "ldap_unbind"))
#define WLDAP32$ldap_msgfree ((ldap_msgfree_t)DynamicLoad("WLDAP32", "ldap_msgfree"))
#define WLDAP32$ldap_memfree ((ldap_memfree_t)DynamicLoad("WLDAP32", "ldap_memfree"))
#define WLDAP32$ldap_first_entry ((ldap_first_entry_t)DynamicLoad("WLDAP32", "ldap_first_entry"))
#define WLDAP32$ldap_get_next_page_s ((ldap_get_next_page_s_t)DynamicLoad("WLDAP32", "ldap_get_next_page_s"))
#define WLDAP32$ldap_count_entries ((ldap_count_entries_t)DynamicLoad("WLDAP32", "ldap_count_entries"))
#define WLDAP32$ldap_next_entry ((ldap_next_entry_t)DynamicLoad("WLDAP32", "ldap_next_entry"))
#define WLDAP32$ldap_first_attribute ((ldap_first_attribute_t)DynamicLoad("WLDAP32", "ldap_first_attribute"))
#define WLDAP32$ldap_get_values_lenA ((ldap_get_values_lenA_t)DynamicLoad("WLDAP32", "ldap_get_values_lenA"))
#define WLDAP32$ldap_get_values ((ldap_get_values_t)DynamicLoad("WLDAP32", "ldap_get_values"))
#define WLDAP32$ldap_value_free_len ((ldap_value_free_len_t)DynamicLoad("WLDAP32", "ldap_value_free_len"))
#define WLDAP32$ldap_value_free ((ldap_value_free_t)DynamicLoad("WLDAP32", "ldap_value_free"))
#define WLDAP32$ldap_next_attribute ((ldap_next_attribute_t)DynamicLoad("WLDAP32", "ldap_next_attribute"))
#define WLDAP32$ldap_search_init_pageA ((ldap_search_init_pageA_t)DynamicLoad("WLDAP32", "ldap_search_init_pageA"))

//https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-sd-flags-oid
// Set LDAP server control flags so low-privileged domain users can read nTSecurityDescriptor attribute
PLDAPControlA FormatSDFlags(int iFlagValue) {
	BerElement *pber = NULL;
	PLDAPControl pLControl = NULL;
	PBERVAL pldctrl_value = NULL;
	int success = -1;
	// Format and encode the SEQUENCE data in a BerElement.
	pber = WLDAP32$ber_alloc_t(LBER_USE_DER);
	if(pber==NULL) return NULL;
	pLControl = (PLDAPControl)MSVCRT$malloc(sizeof(LDAPControl));
	if(pLControl==NULL) { WLDAP32$ber_free(pber,1); return NULL; }
	WLDAP32$ber_printf(pber,"{i}",iFlagValue);
	
	// Transfer the encoded data into a BERVAL.
	success = WLDAP32$ber_flatten(pber,&pldctrl_value);
	if(success == 0)
		WLDAP32$ber_free(pber,1);
	else {
		BeaconPrintf(CALLBACK_ERROR, "ber_flatten failed!");
		// Call error handler here.
	}
	// Copy the BERVAL data to the LDAPControl structure.
	pLControl->ldctl_oid = "1.2.840.113556.1.4.801";
	pLControl->ldctl_iscritical = TRUE;
	pLControl->ldctl_value.bv_val = (char*)MSVCRT$malloc((size_t)pldctrl_value->bv_len);
	memcpy(pLControl->ldctl_value.bv_val, pldctrl_value->bv_val, pldctrl_value->bv_len);
	pLControl->ldctl_value.bv_len = pldctrl_value->bv_len;
	
	// Cleanup temporary berval.
	WLDAP32$ber_bvfree(pldctrl_value);
	// Return the formatted LDAPControl data.
	return pLControl;
}

// https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c.auto.html
static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode(char* encoded, const char* string, int len) {
	int i;
	char* p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
			((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
			((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}

LDAP* InitialiseLDAPConnection(PCHAR hostName, PCHAR distinguishedName){
	LDAP* pLdapConnection = NULL;

    pLdapConnection = WLDAP32$ldap_init(hostName, 389);
    
    if (pLdapConnection == NULL)
    {
      	BeaconPrintf(CALLBACK_ERROR, "Failed to establish LDAP connection on 389.");
        return NULL;
    }
    ULONG Version = 3;
    //WLDAP32$ldap_set_optionA(pLdapConnection, LDAP_OPT_VERSION,&Version );

	//////////////////////////////
	// Bind to DC
	//////////////////////////////
    ULONG lRtn = 0;

    lRtn = WLDAP32$ldap_bind_s(
                pLdapConnection,      // Session Handle
                distinguishedName,    // Domain DN
                NULL,                 // Credential structure
                LDAP_AUTH_NEGOTIATE); // Auth mode

    if(lRtn != LDAP_SUCCESS)
    {
    	BeaconPrintf(CALLBACK_ERROR, "Bind Failed: %lu", lRtn);
        WLDAP32$ldap_unbind(pLdapConnection);
        pLdapConnection = NULL; 
    }
    return pLdapConnection;
}

PLDAPSearch ExecuteLDAPQuery(LDAP* pLdapConnection, PCHAR distinguishedName, char * ldap_filter, char * ldap_attributes, ULONG maxResults, ULONG scope_of_search){
    internal_printf("[*] Filter: %s\n",ldap_filter);
    internal_printf("[*] Scope of search value: %lu\n",scope_of_search);

	// Security descriptor flags to read nTSecurityDescriptor as low-priv domain user
	// value taken from https://github.com/fortalice/pyldapsearch/blob/main/pyldapsearch/__main__.py (Microsoft docs mentioned XORing all possible values to get this, but that didn't work)
	int sdFlags = 0x07;
	PLDAPControlA serverControls[2];
	int aclSearch = 0;
    ULONG scope;

    ULONG errorCode = LDAP_SUCCESS;
    PLDAPSearch pSearchResult = NULL;
    PCHAR attr[MAX_ATTRIBUTES] = {0};
	if(ldap_attributes){
        internal_printf("[*] Returning specific attribute(s): %s\n",ldap_attributes);
        
        int attribute_count = 0;
        char *token = NULL;
        const char s[2] = ","; //delimiter

        token = MSVCRT$strtok(ldap_attributes, s);

        while( token != NULL ) {
			if (MSVCRT$_stricmp(token, "nTSecurityDescriptor") == 0) {
				serverControls[0] = FormatSDFlags(sdFlags);
				serverControls[1] = NULL;
				aclSearch = 1;
			}
            if(attribute_count < (MAX_ATTRIBUTES - 1)){
                attr[attribute_count] = token;
                attribute_count++;
                token = MSVCRT$strtok(NULL, s);
            } else {
                internal_printf("[!] Cannot return more than %i attributes, will omit additional attributes.\n", MAX_ATTRIBUTES);
                break;
            }
        }
    }

    if (scope_of_search == 1){
        scope = LDAP_SCOPE_BASE;
    } 
    else if (scope_of_search == 2){
        scope = LDAP_SCOPE_ONELEVEL;
    }
    else if (scope_of_search == 3){
        scope = LDAP_SCOPE_SUBTREE;
    }
    

   	if (aclSearch) {
		pSearchResult = WLDAP32$ldap_search_init_pageA(
		pLdapConnection,    // Session handle
		distinguishedName,  // DN to start search
		scope, // Scope
		ldap_filter,        // Filter
		(*attr) ? attr : NULL,               // Retrieve list of attributes
		0,                  // Get both attributes and values
		serverControls,
		NULL,
		15,
		maxResults,
		NULL);    // [out] Search results
		
		MSVCRT$free(serverControls[0]->ldctl_value.bv_val);
		MSVCRT$free(serverControls[0]);
	} else {
		pSearchResult = WLDAP32$ldap_search_init_pageA(
		pLdapConnection,    // Session handle
		distinguishedName,  // DN to start search
		scope, // Scope
		ldap_filter,        // Filter
		(*attr) ? attr : NULL,               // Retrieve list of attributes
		0,                  // Get both attributes and values
		NULL,
		NULL,
		15,
		maxResults,
		NULL);    // [out] Search results
	}
    
    if (pSearchResult == NULL) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Paging not supported on this server, aborting");
    }
    return pSearchResult;

}

void customAttributes(PCHAR pAttribute, PCHAR pValue)
{
    if(MSVCRT$strcmp(pAttribute, "objectGUID") == 0) 
    {
        if(fuuidtostring == (void *)1) // I'm doing this because we ran out of function slots for dynamic function resolution
        {
           rpcrt = LoadLibraryA("rpcrt4");
           fuuidtostring = (_fuuidtostring)GetProcAddress(rpcrt, "UuidToStringA");
           frpcstringfree = (_RpcStringFreeA)GetProcAddress(rpcrt, "RpcStringFreeA");
        }
        RPC_CSTR G = NULL;
        PBERVAL tmp = (PBERVAL)pValue;
        //RPCRT4$UuidToStringA((UUID *) tmp->bv_val, &G);
        fuuidtostring((UUID *) tmp->bv_val, &G);
        internal_printf("%s", G);
        //RPCRT4$RpcStringFreeA(&G);       
        frpcstringfree(&G);
    } else if (MSVCRT$strcmp(pAttribute, "nTSecurityDescriptor") == 0 || MSVCRT$strcmp(pAttribute, "msDS-AllowedToActOnBehalfOfOtherIdentity") == 0 || MSVCRT$strcmp(pAttribute, "msDS-GenerationId") == 0 || MSVCRT$strcmp(pAttribute, "auditingPolicy") == 0 || MSVCRT$strcmp(pAttribute, "dSASignature") == 0 || MSVCRT$strcmp(pAttribute, "mS-DS-CreatorSID") == 0 || MSVCRT$strcmp(pAttribute, "logonHours") == 0 || MSVCRT$strcmp(pAttribute, "schemaIDGUID") == 0 || MSVCRT$strcmp(pAttribute, "mSMQDigests") == 0 || MSVCRT$strcmp(pAttribute, "mSMQSignCertificates") == 0 || MSVCRT$strcmp(pAttribute, "userCertificate") == 0 || MSVCRT$strcmp(pAttribute, "attributeSecurityGUID") == 0  ) {
		char *encoded = NULL;
		PBERVAL tmp = (PBERVAL)pValue;
		ULONG len = tmp->bv_len;
		encoded = (char *)MSVCRT$malloc((size_t)len*2);
		Base64encode(encoded, (char *)tmp->bv_val, len);
		internal_printf("%s", encoded);
		MSVCRT$free(encoded);
	}
    else if(MSVCRT$strcmp(pAttribute, "objectSid") == 0 || MSVCRT$strcmp(pAttribute, "securityIdentifier") == 0)
    {
        LPSTR sid = NULL;
		//internal_printf("len of objectSID: %d\n", MSVCRT$strlen(pValue));
        PBERVAL tmp = (PBERVAL)pValue;
        ADVAPI32$ConvertSidToStringSidA((PSID)tmp->bv_val, &sid);
        internal_printf("%s", sid);
        KERNEL32$LocalFree(sid);
    }
    else
    {
        internal_printf("%s", pValue);
    }
    
}

void printAttribute(PCHAR pAttribute, PCHAR* ppValue){
    internal_printf("\n%s: ", pAttribute);
    customAttributes(pAttribute, *ppValue);
    ppValue++;
    while(*ppValue != NULL)
    {
        internal_printf(", ");
        customAttributes(pAttribute, *ppValue);
        ppValue++;
    }
}

void ldapSearch(char * ldap_filter, char * ldap_attributes,	ULONG results_count, ULONG scope_of_search, char * hostname, char * domain){
    char szDN[1024] = {0};
	ULONG ulSize = sizeof(szDN)/sizeof(szDN[0]);
	
    BOOL res = (domain) ? TRUE : SECUR32$GetUserNameExA(NameFullyQualifiedDN, szDN, &ulSize);
    DWORD dwRet = 0;
    PDOMAIN_CONTROLLER_INFO pdcInfo = NULL;
    LDAP* pLdapConnection = NULL; 
    PLDAPSearch pPageHandle = NULL;
    PLDAPMessage pSearchResult = NULL;
    char* distinguishedName = NULL;
    BerElement* pBer = NULL;
    LDAPMessage* pEntry = NULL;
    PCHAR pEntryDN = NULL;
    LDAP_TIMEVAL timeout = {20, 0};
    ULONG iCnt = 0;
    PCHAR pAttribute = NULL;
    PCHAR* ppValue = NULL;
    ULONG results_limit = 0;
    BOOL isbinary = FALSE;
    ULONG stat = 0;
    ULONG totalResults = 0;
    HMODULE wldap = LoadLibrary("wldap32");
    if(wldap == NULL) {internal_printf("Unable to load required library\n"); return;}
    _ldap_search_abondon_page searchDone = (_ldap_search_abondon_page)GetProcAddress(wldap, "ldap_search_abandon_page");
    if(searchDone == NULL) {internal_printf("Unable to load required function"); return;}

	distinguishedName = (domain) ? domain : MSVCRT$strstr(szDN, "DC=");
	if(distinguishedName != NULL && res) {
    	internal_printf("[*] Distinguished name: %s\n", distinguishedName);	
	}
	else{
		BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve distinguished name.");
        return;

	}

	////////////////////////////
	// Retrieve PDC
	////////////////////////////
    
    dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
    if (ERROR_SUCCESS == dwRet || hostname) {
        if(!hostname){
            internal_printf("[*] targeting DC: %s\n", pdcInfo->DomainControllerName);       
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to identify PDC, are we domain joined?");
        goto end;
    }


	//////////////////////////////
	// Initialise LDAP Session
    // Taken from https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-a-directory
	//////////////////////////////
    char * targetdc = (hostname == NULL) ? pdcInfo->DomainControllerAddress + 2 : hostname;
    BeaconPrintf(CALLBACK_OUTPUT, "Binding to %s", targetdc);
    pLdapConnection = InitialiseLDAPConnection(targetdc, distinguishedName);

    if(!pLdapConnection)
        {goto end;}

	//////////////////////////////
	// Perform LDAP Search
	//////////////////////////////
	pPageHandle = ExecuteLDAPQuery(pLdapConnection, distinguishedName, ldap_filter, ldap_attributes, results_count, scope_of_search);   
    ULONG pagecount = 0;
    do
    {
        stat = WLDAP32$ldap_get_next_page_s(pLdapConnection, pPageHandle, &timeout, (results_count && ((results_count - totalResults) < 64))  ? results_count - totalResults : 64, &pagecount,&pSearchResult );
        if(!pSearchResult || ! (stat == LDAP_SUCCESS || stat == LDAP_NO_RESULTS_RETURNED))
            {goto end;}

        //////////////////////////////
        // Get Search Result Count
        //////////////////////////////
        DWORD numberOfEntries = WLDAP32$ldap_count_entries(
                            pLdapConnection,    // Session handle
                            pSearchResult);     // Search result
        
        if(numberOfEntries == -1) // -1 is functions return value when it failed
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to count search results.");
            goto end;
        }
        else if(!numberOfEntries)
        {
            BeaconPrintf(CALLBACK_ERROR, "Search returned zero results");
            goto end;
        }    
        
        totalResults += numberOfEntries;


        for( iCnt=0; iCnt < numberOfEntries; iCnt++ )
        {
            internal_printf("\n--------------------");

            // Get the first/next entry.
            if( !iCnt )
                {pEntry = WLDAP32$ldap_first_entry(pLdapConnection, pSearchResult);}
            else
                {pEntry = WLDAP32$ldap_next_entry(pLdapConnection, pEntry);}
            
            if( pEntry == NULL )
            {
                break;
            }
                    
            // Get the first attribute name.
            pAttribute = WLDAP32$ldap_first_attribute(
                        pLdapConnection,   // Session handle
                        pEntry,            // Current entry
                        &pBer);            // [out] Current BerElement
            
            // Output the attribute names for the current object
            // and output values.
            while(pAttribute != NULL)
            {
                isbinary = FALSE;
                // Get the string values.
                if(MSVCRT$strcmp(pAttribute, "objectSid") == 0 || MSVCRT$strcmp(pAttribute, "objectGUID") == 0 || MSVCRT$strcmp(pAttribute, "nTSecurityDescriptor") == 0 || MSVCRT$strcmp(pAttribute, "msDS-GenerationId") == 0 || MSVCRT$strcmp(pAttribute, "auditingPolicy") == 0 || MSVCRT$strcmp(pAttribute, "dSASignature") == 0 || MSVCRT$strcmp(pAttribute, "mS-DS-CreatorSID") == 0 || MSVCRT$strcmp(pAttribute, "logonHours") == 0 || MSVCRT$strcmp(pAttribute, "schemaIDGUID") == 0 || MSVCRT$strcmp(pAttribute, "msDS-AllowedToActOnBehalfOfOtherIdentity") == 0 || MSVCRT$strcmp(pAttribute, "msDS-GenerationId") == 0 || MSVCRT$strcmp(pAttribute, "mSMQDigests") == 0 || MSVCRT$strcmp(pAttribute, "mSMQSignCertificates") == 0 || MSVCRT$strcmp(pAttribute, "userCertificate") == 0 || MSVCRT$strcmp(pAttribute, "attributeSecurityGUID") == 0  )
                {
					//internal_printf("\n%s\n", pAttribute);
                    ppValue = (char **)WLDAP32$ldap_get_values_lenA(pLdapConnection, pEntry, pAttribute); //not really a char **
                    isbinary = TRUE;
				} else {
                    ppValue = WLDAP32$ldap_get_values(
                                pLdapConnection,  // Session Handle
                                pEntry,           // Current entry
                                pAttribute);      // Current attribute
                }


                // Use and Free memory.
                if(ppValue != NULL)  
                {
                    printAttribute(pAttribute, ppValue);
                    if(isbinary)
                    {WLDAP32$ldap_value_free_len((PBERVAL *)ppValue);}
                    else
                    {WLDAP32$ldap_value_free(ppValue);}
                    ppValue = NULL;
                }
                WLDAP32$ldap_memfree(pAttribute);
                
                // Get next attribute name.
                pAttribute = WLDAP32$ldap_next_attribute(
                    pLdapConnection,   // Session Handle
                    pEntry,            // Current entry
                    pBer);             // Current BerElement
            }
            
            if( pBer != NULL )
            {
                WLDAP32$ber_free(pBer,0);
                pBer = NULL;
            }
        }
        if(totalResults >= results_count && results_count != 0)
        {
            break;
        }
        WLDAP32$ldap_msgfree(pSearchResult); pSearchResult = NULL;
    }while(stat == LDAP_SUCCESS);

    end: 
    internal_printf("\nretreived %lu results total\n", totalResults);
    if(pPageHandle)
    {
        searchDone(pLdapConnection, pPageHandle);
    }
    if( pBer != NULL )
    {
        WLDAP32$ber_free(pBer,0);
        pBer = NULL;
    }
    if(pdcInfo)
    {
        NETAPI32$NetApiBufferFree(pdcInfo);
        pdcInfo = NULL;
    }
    if(pLdapConnection)
    {
        WLDAP32$ldap_unbind(pLdapConnection);
        pLdapConnection = NULL;
    }
    if(pSearchResult)
    {
        WLDAP32$ldap_msgfree(pSearchResult);
        pSearchResult = NULL;
    }
    if (ppValue)
    {
        WLDAP32$ldap_value_free(ppValue);
        ppValue = NULL;
    }    
    if(wldap)
    {
        FreeLibrary(wldap);
        wldap = NULL;
    }

}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap  parser;
	char * ldap_filter;
	char * ldap_attributes;
    char * hostname;
    char * domain;
	ULONG results_count;
    ULONG scope_of_search;

	BeaconDataParse(&parser, Buffer, Length);
	ldap_filter = BeaconDataExtract(&parser, NULL);
	ldap_attributes = BeaconDataExtract(&parser, NULL);
	results_count = BeaconDataInt(&parser);
	scope_of_search = BeaconDataInt(&parser);
    hostname = BeaconDataExtract(&parser, NULL);
    domain = BeaconDataExtract(&parser, NULL);

    ldap_attributes = *ldap_attributes == 0 ? NULL : ldap_attributes;
    hostname = *hostname == 0 ? NULL : hostname;
    domain = *domain == 0 ? NULL : domain;

	
	if(!bofstart())
	{
		return;
	}

	ldapSearch(ldap_filter, ldap_attributes, results_count, scope_of_search, hostname, domain);

	printoutput(TRUE);
    if(fuuidtostring != (void *)1)
    {
        FreeLibrary(rpcrt);
    }
    bofstop();
};

#else

int main()
{
    char a[] = "(objectclass=*)";
    char b[] = "(objectclass=*)";
    char c[] = "(objectclass=*)";
    char d[] = "(asdf=*)";
    char attr[] = "objectSID,name";
    char asdf1[] = "asdf";
    char asdf2[] = "asdf";
    char asdf3[] = "asdf";
    ldapSearch(a, NULL, 0, NULL, NULL);
    ldapSearch(d, NULL, 248, NULL, NULL);
    ldapSearch(c, attr, 0, NULL, NULL);
    ldapSearch(b, asdf1, 0, NULL, NULL);
    ldapSearch(b, asdf2, 0, "TrashMaster", NULL);
    ldapSearch(b, asdf3, 0, NULL, "TrashMaster");
    return 1;
}

#endif

