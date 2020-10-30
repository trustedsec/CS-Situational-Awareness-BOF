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

char* GetDomainControllerHostName(){
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
        return NULL;
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
      	BeaconPrintf(CALLBACK_ERROR, "Bind Failed: %u", lRtn);
        WLDAP32$ldap_unbind(pLdapConnection);
    }
    return pLdapConnection;
}

LDAPMessage* ExecuteLDAPQuery(LDAP* pLdapConnection, PCHAR distinguishedName, char * ldap_filter, char * ldap_attributes){
	ULONG errorCode = LDAP_SUCCESS;
    LDAPMessage* pSearchResult = NULL;
    
	if(strlen(ldap_attributes) != 0){
		PCHAR attr[2];
		attr[0] = ldap_attributes;
        attr[1] = NULL;

		errorCode = WLDAP32$ldap_search_s(
        pLdapConnection,    // Session handle
        distinguishedName,  // DN to start search
        LDAP_SCOPE_SUBTREE, // Scope
        ldap_filter,        // Filter
        attr,               // Retrieve list of attributes
        0,                  // Get both attributes and values
        &pSearchResult);    // [out] Search results
	} else {
		errorCode = WLDAP32$ldap_search_s(
        pLdapConnection,    // Session handle
        distinguishedName,  // DN to start search
        LDAP_SCOPE_SUBTREE, // Scope
        ldap_filter,        // Filter
        NULL,               // Retrieve list of attributes
        0,                  // Get both attributes and values
        &pSearchResult);    // [out] Search results
	}   
    
    if (errorCode != LDAP_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "LDAP Search Failed: %u", errorCode);

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
 //    ULONG iValue = 0;

	// // Print status if no values are returned (NULL ptr)
 //    if(ppValue == NULL)
 //    {
 //    	internal_printf("%s: [NO ATTRIBUTE VALUE RETURNED]", pAttribute);
 //    }

 //    // Output the attribute values
 //    else
 //    {
 //        iValue = WLDAP32$ldap_count_values(ppValue);
 //        if(!iValue)
 //        {
 //        	internal_printf("%s: [BAD VALUE LIST]", pAttribute);
 //        }
 //        else
 //        {
 //            if((MSVCRT$strcmp(pAttribute, "pwdLastSet") == 0)||
 //            	(MSVCRT$strcmp(pAttribute, "lastLogon") == 0)||
 //            	(MSVCRT$strcmp(pAttribute, "badPasswordTime") == 0)||
 //            	(MSVCRT$strcmp(pAttribute, "lastLogonTimestamp") == 0)){
 //            	internal_printf("\n%s: ", pAttribute);
 //            	// TODO: Implement transformations for various attribute data types.
 //                internal_printf("%s", *ppValue);
            	
 //            } else
 //                internal_printf("\n%s: %s", pAttribute, *ppValue); // Output the first attribute value

 //            // Output more values if available
 //            ULONG z;
 //            for(z=1; z<iValue; z++)
 //            {
 //                internal_printf(", %s", ppValue[z]);
 //            }
 //        }
 //    }
    internal_printf("\n%s: ", pAttribute);
    internal_printf("%s", *ppValue);
    ppValue++;
    while(*ppValue != NULL)
    {
        internal_printf(", %s", *ppValue);
        ppValue++;
    }
}


void ldapSearch(char * ldap_filter, char * ldap_attributes,	ULONG results_count){
	internal_printf("[*] Using filter: %s\n",ldap_filter);
	
	if(strlen(ldap_attributes)==0)
		internal_printf("[*] Returning all attributes.\n\n");
	else
		internal_printf("[*] Returning specific attribute: %s\n\n",ldap_attributes);
	

	char szDN[1024];
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
		return;
	}

	////////////////////////////
	// Retrieve PDC
	////////////////////////////
	PCHAR hostName = GetDomainControllerHostName();

	//////////////////////////////
	// Initialise LDAP Session
    // Taken from https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-a-directory
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
    DWORD numberOfEntries = WLDAP32$ldap_count_entries(
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
    BerElement* pBer = NULL;
    PCHAR pAttribute = NULL;
    PCHAR* ppValue = NULL;

    ULONG results_limit = 0;

    if ((results_count == 0) || (results_count > numberOfEntries)){
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
	ULONG results_count;

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
