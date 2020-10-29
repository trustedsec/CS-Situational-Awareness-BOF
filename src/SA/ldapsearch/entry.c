#include <windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <rpc.h>
#include <rpcdce.h>
#include <stdint.h>
#include "bofdefs.h"
#include "base.c"
#include <string.h>

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_init(PSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_s(LDAP *ld,const PSTR  dn,const PCHAR cred,ULONG method);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_s(LDAP *ld,PSTR base,ULONG scope,PSTR filter,PZPSTR attrs,ULONG attrsonly,PLDAPMessage *res);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_entries(LDAP*,LDAPMessage*);

DECLSPEC_IMPORT LDAPMessage*  WINAPI WLDAP32$ldap_first_entry(LDAP *ld,LDAPMessage *res);
DECLSPEC_IMPORT LDAPMessage*  WINAPI WLDAP32$ldap_next_entry(LDAP*,LDAPMessage*);
DECLSPEC_IMPORT PCHAR WINAPI WLDAP32$ldap_first_attribute(LDAP *ld,LDAPMessage *entry,BerElement **ptr);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_values(PCHAR);
DECLSPEC_IMPORT PCHAR WINAPI WLDAP32$ldap_get_values(LDAP *ld,LDAPMessage *entry,const PSTR attr);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free(PCHAR);
DECLSPEC_IMPORT PCHAR WINAPI WLDAP32$ldap_next_attribute(LDAP *ld,LDAPMessage *entry,BerElement **ptr);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ber_free(BerElement *pBerElement,INT fbuf);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_memfree(PCHAR);

DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind_s(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);

DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
DECLSPEC_IMPORT PCHAR WINAPI MSVCRT$strstr(const char *haystack, const char *needle);

#define TICKSTO1970         0x019db1ded53e8000LL
#define TICKSTO1980         0x01a8e79fe1d58000LL
#define TICKSPERSEC         10000000
#ifdef _WIN64 //can't use builtin function for extended divition on x86
DWORD GetTimeInSeconds(VOID)
{
    LARGE_INTEGER Time;
    FILETIME FileTime;
    DWORD dwSeconds;
    int junk = 0;
    lldiv_t test;
    KERNEL32$GetSystemTimeAsFileTime(&FileTime);
    Time.u.LowPart = FileTime.dwLowDateTime;
    Time.u.HighPart = FileTime.dwHighDateTime;
    Time.QuadPart = Time.QuadPart - TICKSTO1970;
    Time.QuadPart = (uint64_t)Time.QuadPart / (uint64_t)TICKSPERSEC;
    dwSeconds = Time.u.LowPart;

    return dwSeconds;
}
#endif
VOID ReturnDateTime(DWORD dwSeconds)
{
    LARGE_INTEGER Time;
    FILETIME FileTime;
    SYSTEMTIME SystemTime;
    PCHAR DateBuffer[80];
    PCHAR TimeBuffer[80];

    Time.QuadPart = ((LONGLONG)dwSeconds * TICKSPERSEC) + TICKSTO1970;
    // Time.QuadPart = ((LONGLONG)dwSeconds - TICKSTO1970);
    
    FileTime.dwLowDateTime = Time.u.LowPart;
    FileTime.dwHighDateTime = Time.u.HighPart;
    KERNEL32$FileTimeToLocalFileTime(&FileTime, &FileTime);
    KERNEL32$FileTimeToSystemTime(&FileTime, &SystemTime);

    KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT,
                   DATE_SHORTDATE,
                   &SystemTime,
                   NULL,
                   DateBuffer,
                   ARRAYSIZE(DateBuffer));

    KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT,
                   TIME_NOSECONDS,
                   &SystemTime,
                   NULL,
                   TimeBuffer,
                   ARRAYSIZE(TimeBuffer));

    internal_printf("%S %S", DateBuffer, TimeBuffer);
}

PCHAR GetDomainControllerHostName(){
	DWORD dwRet;
	PDOMAIN_CONTROLLER_INFO pdcInfo;

	dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (ERROR_SUCCESS == dwRet) {
		internal_printf("[*] Using DC: %s\n", pdcInfo->DomainControllerName);		
	} else {
 	    BeaconPrintf(CALLBACK_ERROR, "Failed to identify PDC, are we domain joined?");
	}

	PCHAR hostName = pdcInfo->DomainControllerName + 2; // Remove preceeding backslashes

	NETAPI32$NetApiBufferFree(pdcInfo);
	return hostName;
}

LDAP* InitialiseLDAPConnection(PCHAR hostName, PCHAR distinguishedName){
	LDAP* pLdapConnection = NULL;

    pLdapConnection = WLDAP32$ldap_init(hostName, 389);
    
    if (pLdapConnection == NULL)
    {
      	BeaconPrintf(CALLBACK_ERROR, "Failed to establish LDAP connection on 389.");
        WLDAP32$ldap_unbind(pLdapConnection);
    }
    else {
		internal_printf("[+] Initialised Connection.\n");
    }

	//////////////////////////////
	// Bind to DC
	//////////////////////////////
    ULONG lRtn = 0;

    lRtn = WLDAP32$ldap_bind_s(
                pLdapConnection,      // Session Handle
                distinguishedName,                // Domain DN
                NULL,                 // Credential structure
                LDAP_AUTH_NEGOTIATE); // Auth mode

    if(lRtn == LDAP_SUCCESS)
    {
    	internal_printf("[+] Bind Successful.\n");
    }
    else
    {
      	BeaconPrintf(CALLBACK_ERROR, "Bind Failed: %i", lRtn);
        WLDAP32$ldap_unbind(pLdapConnection);
    }
    return pLdapConnection;
}

LDAPMessage* ExecuteLDAPQuery(LDAP* pLdapConnection, PCHAR distinguishedName, char * ldap_filter, char * ldap_attributes){
	ULONG errorCode = LDAP_SUCCESS;
    LDAPMessage* pSearchResult;
    
	if(strlen(ldap_attributes)!=0){
		PCHAR attr[1];
		attr[0] = ldap_attributes;

		errorCode = WLDAP32$ldap_search_s(
        pLdapConnection,    // Session handle
        distinguishedName,           // DN to start search
        LDAP_SCOPE_SUBTREE, // Scope
        ldap_filter,          // Filter
        attr,      // Retrieve list of attributes
        0,                  // Get both attributes and values
        &pSearchResult);    // [out] Search results
	} else {
		errorCode = WLDAP32$ldap_search_s(
        pLdapConnection,    // Session handle
        distinguishedName,           // DN to start search
        LDAP_SCOPE_SUBTREE, // Scope
        ldap_filter,          // Filter
        NULL,      // Retrieve list of attributes
        0,                  // Get both attributes and values
        &pSearchResult);    // [out] Search results
	}   
    
    if (errorCode != LDAP_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "LDAP Search Failed: %i", errorCode);

        WLDAP32$ldap_unbind_s(pLdapConnection);
        if(pSearchResult != NULL)
            WLDAP32$ldap_msgfree(pSearchResult);
    }
    else {
    	internal_printf("[+] LDAP Search Succeeded.\n");
    }
    return pSearchResult;

}

void printAttribute(PCHAR pAttribute, PCHAR* ppValue){
    ULONG iValue = 0;

	// Print status if no values are returned (NULL ptr)
    if(ppValue == NULL)
    {
    	internal_printf("%s: [NO ATTRIBUTE VALUE RETURNED]", pAttribute);
    }

    // Output the attribute values
    else
    {
        iValue = WLDAP32$ldap_count_values(ppValue);
        if(!iValue)
        {
        	internal_printf("%s: [BAD VALUE LIST]", pAttribute);
        }
        else
        {
            if((MSVCRT$strcmp(pAttribute, "pwdLastSet") == 0)||
            	(MSVCRT$strcmp(pAttribute, "lastLogon") == 0)||
            	(MSVCRT$strcmp(pAttribute, "badPasswordTime") == 0)||
            	(MSVCRT$strcmp(pAttribute, "lastLogonTimestamp") == 0)){
            	internal_printf("\n%s: ", pAttribute);
            	internal_printf("%s", *ppValue);
            	// ReturnDateTime(*ppValue);
            } else
                internal_printf("\n%s: %s", pAttribute, *ppValue); // Output the first attribute value

            // Output more values if available
            ULONG z;
            for(z=1; z<iValue; z++)
            {
                internal_printf(", %s", ppValue[z]);
            }
        }
    }
}


void ldapSearch(char * ldap_filter, char * ldap_attributes,	ULONG results_count){
	ULONG numberOfEntries;
	ULONG results_limit = 0;

	internal_printf("[*] Using filter: %s\n",ldap_filter);
	
	if(strlen(ldap_attributes)==0)
		internal_printf("[*] Returning all attributes.\n\n");
	else
		internal_printf("[*] Returning specific attribute: %s\n\n",ldap_attributes);
	

	TCHAR szDN[1024];
	ULONG ulSize = sizeof(szDN)/sizeof(szDN[0]);
	BOOL res = SECUR32$GetUserNameExA(1, szDN, &ulSize);

	char * dc = "DC";
	char* distinguishedName;

	distinguishedName = MSVCRT$strstr(szDN, dc);
	if(distinguishedName != NULL) {
    	internal_printf("[*] Using distinguished name: %s\n", distinguishedName);	
	}
	else{
		BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve distinguished name.");
		return ;
	}

	////////////////////////////
	// Retrieve PDC
	////////////////////////////
	PCHAR hostName = GetDomainControllerHostName();

	//////////////////////////////
	// Initialise LDAP Session
	//////////////////////////////
    LDAP* pLdapConnection = InitialiseLDAPConnection(hostName, distinguishedName);

    if(!pLdapConnection)
        return;

	//////////////////////////////
	// Perform LDAP Search
	//////////////////////////////
	LDAPMessage* pSearchResult = ExecuteLDAPQuery(pLdapConnection, distinguishedName, ldap_filter, ldap_attributes);    

    if(!pSearchResult)
        return;

    //////////////////////////////
	// Get Search Result Count
	//////////////////////////////
    numberOfEntries = WLDAP32$ldap_count_entries(
                        pLdapConnection,    // Session handle
                        pSearchResult);     // Search result
    
    if(!numberOfEntries)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to count search results.");
        WLDAP32$ldap_unbind_s(pLdapConnection);
        if(pSearchResult != NULL)
            WLDAP32$ldap_msgfree(pSearchResult);
        return;
    }
    
    //////////////////////////////
	// Get Search Result Count
	//////////////////////////////
    LDAPMessage* pEntry = NULL;
    PCHAR pEntryDN = NULL;
    ULONG iCnt = 0;
    char* sMsg;
    BerElement* pBer = NULL;
    PCHAR pAttribute = NULL;
    PCHAR* ppValue = NULL;

    if (results_count == 0 || results_count > numberOfEntries){
		results_limit = numberOfEntries;
  	    internal_printf("[*] Result count: %d\n", numberOfEntries);
    }
    else { 
    	results_limit = results_count;
    	internal_printf("[*] Result count: %d (showing max. %d)\n", numberOfEntries, results_count);
    }


    for( iCnt=0; iCnt < results_limit; iCnt++ )
    {
       	internal_printf("\n--------------------");

        // Get the first/next entry.
        if( !iCnt )
            pEntry = WLDAP32$ldap_first_entry(pLdapConnection, pSearchResult);
        else
            pEntry = WLDAP32$ldap_next_entry(pLdapConnection, pEntry);
        
        // Output a status message.
        sMsg = (!iCnt ? "ldap_first_entry" : "ldap_next_entry");
        if( pEntry == NULL )
        {
            WLDAP32$ldap_unbind_s(pLdapConnection);
            WLDAP32$ldap_msgfree(pSearchResult);
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
            // Get the string values.
            ppValue = WLDAP32$ldap_get_values(
                          pLdapConnection,  // Session Handle
                          pEntry,           // Current entry
                          pAttribute);      // Current attribute

            printAttribute(pAttribute, ppValue); 

            // Free memory.
            if(ppValue != NULL)  
                WLDAP32$ldap_value_free(ppValue);
            ppValue = NULL;
            WLDAP32$ldap_memfree(pAttribute);
            
            // Get next attribute name.
            pAttribute = WLDAP32$ldap_next_attribute(
                pLdapConnection,   // Session Handle
                pEntry,            // Current entry
                pBer);             // Current BerElement
        }
        
        if( pBer != NULL )
            WLDAP32$ber_free(pBer,0);
        pBer = NULL;
    }


    WLDAP32$ldap_unbind(pLdapConnection);
    WLDAP32$ldap_msgfree(pSearchResult);
    WLDAP32$ldap_value_free(ppValue);
}


VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap  parser;
	char * ldap_filter;
	char * ldap_attributes;
	ULONG results_count = 0;
	
	BeaconDataParse(&parser, Buffer, Length);
	ldap_filter = BeaconDataExtract(&parser, NULL);
	ldap_attributes = BeaconDataExtract(&parser, NULL);
	results_count = BeaconDataInt(&parser);

	if(!bofstart())
	{
		return;
	}

	ldapSearch(ldap_filter, ldap_attributes, results_count);
	printoutput(TRUE);
	bofstop();
};
