#include <windows.h>
#include <netfw.h>
#include <comutil.h>
#include "bofdefs.h"
#include "base.c"

//ported from https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-enumerating-firewall-rules

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"
    typedef struct ProfileMapElement
    {
        NET_FW_PROFILE_TYPE2 Id;
        LPCWSTR Name;
    }ProfileMapElement;

void DumpFWRulesInCollection(INetFwRule* FwRule)
{
    VARIANT InterfaceArray;
    VARIANT InterfaceString;

    VARIANT_BOOL bEnabled;
    BSTR bstrVal;

    long lVal = 0;
    long lProfileBitmask = 0;

    NET_FW_RULE_DIRECTION fwDirection;
    NET_FW_ACTION fwAction;


	OLEAUT32$VariantInit(&InterfaceArray);
	OLEAUT32$VariantInit(&InterfaceString);

    ProfileMapElement ProfileMap[3];
    ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
    ProfileMap[0].Name = L"Domain";
    ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
    ProfileMap[1].Name = L"Private";
    ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
    ProfileMap[2].Name = L"Public";

    internal_printf("---------------------------------------------\n");

    if (SUCCEEDED(FwRule->lpVtbl->get_Name(FwRule, &bstrVal)))
    {
        internal_printf("Name:             %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Description(FwRule, &bstrVal)))
    {
        internal_printf("Description:      %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_ApplicationName(FwRule, &bstrVal)))
    {
        internal_printf("Application Name: %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_ServiceName(FwRule, &bstrVal)))
    {
        internal_printf("Service Name:     %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Protocol(FwRule, &lVal)))
    {
        switch (lVal)
        {
        case NET_FW_IP_PROTOCOL_TCP:

            internal_printf("IP Protocol:      %ls\n", NET_FW_IP_PROTOCOL_TCP_NAME);
            break;

        case NET_FW_IP_PROTOCOL_UDP:

            internal_printf("IP Protocol:      %ls\n", NET_FW_IP_PROTOCOL_UDP_NAME);
            break;

        default:

            break;
        }

        if (lVal != NET_FW_IP_VERSION_V4 && lVal != NET_FW_IP_VERSION_V6)
        {
            if (SUCCEEDED(FwRule->lpVtbl->get_LocalPorts(FwRule, &bstrVal)))
            {
                internal_printf("Local Ports:      %ls\n", (bstrVal) ? bstrVal : L"N/A");
            }

            if (SUCCEEDED(FwRule->lpVtbl->get_RemotePorts(FwRule, &bstrVal)))
            {
                internal_printf("Remote Ports:      %ls\n", (bstrVal) ? bstrVal : L"N/A");
            }
        }
        else
        {
            if (SUCCEEDED(FwRule->lpVtbl->get_IcmpTypesAndCodes(FwRule, &bstrVal)))
            {
                internal_printf("ICMP TypeCode:      %ls\n", (bstrVal) ? bstrVal : L"N/A");
            }
        }
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_LocalAddresses(FwRule, &bstrVal)))
    {
        internal_printf("LocalAddresses:   %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_RemoteAddresses(FwRule, &bstrVal)))
    {
        internal_printf("RemoteAddresses:  %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Profiles(FwRule, &lProfileBitmask)))
    {
        // The returned bitmask can have more than 1 bit set if multiple profiles 
        //   are active or current at the same time

        for (int i = 0; i < 3; i++)
        {
            if (lProfileBitmask & ProfileMap[i].Id)
            {
                internal_printf("Profile:  %ls\n", (ProfileMap[i].Name) ? ProfileMap[i].Name : L"N/A");
            }
        }
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Direction(FwRule, &fwDirection)))
    {
        switch (fwDirection)
        {
        case NET_FW_RULE_DIR_IN:

            internal_printf("Direction:        %ls\n", NET_FW_RULE_DIR_IN_NAME);
            break;

        case NET_FW_RULE_DIR_OUT:

            internal_printf("Direction:        %ls\n", NET_FW_RULE_DIR_OUT_NAME);
            break;

        default:

            break;
        }
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Action(FwRule, &fwAction)))
    {
        switch (fwAction)
        {
        case NET_FW_ACTION_BLOCK:

            internal_printf("Action:           %ls\n", NET_FW_RULE_ACTION_BLOCK_NAME);
            break;

        case NET_FW_ACTION_ALLOW:

            internal_printf("Action:           %ls\n", NET_FW_RULE_ACTION_ALLOW_NAME);
            break;

        default:

            break;
        }
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Interfaces(FwRule, &InterfaceArray)))
    {
        if (InterfaceArray.vt != VT_EMPTY)
        {
            SAFEARRAY* pSa = NULL;

            pSa = InterfaceArray.parray;

            for (long index = pSa->rgsabound->lLbound; index < (long)pSa->rgsabound->cElements; index++)
            {
                OLEAUT32$SafeArrayGetElement(pSa, &index, &InterfaceString);
                internal_printf("Interfaces:       %ls\n", ((BSTR)InterfaceString.bstrVal) ? (BSTR)InterfaceString.bstrVal : L"N/A");
            }
        }
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_InterfaceTypes(FwRule, &bstrVal)))
    {
        internal_printf("Interface Types:  %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Enabled(FwRule, &bEnabled)))
    {
        if (bEnabled)
        {
            internal_printf("Enabled:          %ls\n", NET_FW_RULE_ENABLE_IN_NAME);
        }
        else
        {
            internal_printf("Enabled:          %ls\n", NET_FW_RULE_DISABLE_IN_NAME);
        }
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_Grouping(FwRule, &bstrVal)))
    {
        internal_printf("Grouping:         %ls\n", (bstrVal) ? bstrVal : L"N/A");
    }

    if (SUCCEEDED(FwRule->lpVtbl->get_EdgeTraversal(FwRule, &bEnabled)))
    {
        if (bEnabled)
        {
            internal_printf("Edge Traversal:   %ls\n", NET_FW_RULE_ENABLE_IN_NAME);
        }
        else
        {
            internal_printf("Edge Traversal:   %ls\n", NET_FW_RULE_DISABLE_IN_NAME);
        }
    }
}

HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	const IID NetFwPolicy2_uuid = {0xE2B3C97F,0x6AE1,0x41AC,{0x81,0x7A,0xF6,0xF9,0x21,0x66,0xD7,0xDD}};
	const IID INetFwPolicy2_uuid = {0x98325047,0xC671,0x4174,{0x8D,0x81,0xDE,0xFC,0xD3,0xF0,0x31,0x86}};
    HRESULT hr = S_OK;

    hr = OLE32$CoCreateInstance(
        &NetFwPolicy2_uuid, 
        NULL, 
        CLSCTX_INPROC_SERVER, 
        &INetFwPolicy2_uuid, 
        (void**)ppNetFwPolicy2);

    if (FAILED(hr))
    {
        internal_printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);    
    }
    return hr;
}


void list_rules()
{
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    ULONG cFetched = 0;
    VARIANT var;

    IUnknown* pEnumerator;
    IEnumVARIANT* pVariant = NULL;

    INetFwPolicy2* pNetFwPolicy2 = NULL;
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;

        long fwRuleCount;

	hrComInit = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            internal_printf("CoInitialize failed: 0x%08lx\n", hr);
            goto Cleanup;
        }
    }
    OLEAUT32$VariantInit(&var);
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr))
    {
        goto Cleanup;
    }

    // Retrieve INetFwRules
    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr))
    {
        internal_printf("get_Rules failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Obtain the number of Firewall rules
    hr = pFwRules->lpVtbl->get_Count(pFwRules, &fwRuleCount);
    if (FAILED(hr))
    {
        internal_printf("get_Count failed: 0x%08lx\n", hr);
        goto Cleanup;
    }
    
    internal_printf("The number of rules in the Windows Firewall are %d\n", fwRuleCount);

    // Iterate through all of the rules in pFwRules
    pFwRules->lpVtbl->get__NewEnum(pFwRules, &pEnumerator);
    const IID IEnumVARIANT_uuid = {0x00020404,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
    const IID INetFwRule_uuid = {0xAF230D27,0xBABA,0x4E42,{0xAC,0xED,0xF5,0x24,0xF2,0x2C,0xFC,0xE2}};
    if(pEnumerator)
    {
        hr = pEnumerator->lpVtbl->QueryInterface(pEnumerator, &IEnumVARIANT_uuid, (void **) &pVariant);
    }

    while(SUCCEEDED(hr) && hr != S_FALSE)
    {
        OLEAUT32$VariantClear(&var);
        hr = pVariant->lpVtbl->Next(pVariant, 1, &var, &cFetched);

        if (S_FALSE != hr)
        {
            if (SUCCEEDED(hr))
            {
                hr = OLEAUT32$VariantChangeType(&var, &var, 0, VT_DISPATCH);
            }
            if (SUCCEEDED(hr))
            {
                hr = (V_DISPATCH(&var))->lpVtbl->QueryInterface(V_DISPATCH(&var), &INetFwRule_uuid, (void**)(&pFwRule));
            }

            if (SUCCEEDED(hr))
            {
                // Output the properties of this rule
                DumpFWRulesInCollection(pFwRule);
            }
        }
    }
 
Cleanup:

    // Release pFwRule
    if (pFwRule != NULL)
    {
        pFwRule->lpVtbl->Release(pFwRule);
    }

    // Release INetFwPolicy2
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit))
    {
        OLE32$CoUninitialize();
    }
}



#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	list_rules();
	printoutput(TRUE);
};

#else

int main()
{
list_rules();
}

#endif
