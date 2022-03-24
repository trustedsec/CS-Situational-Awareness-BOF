#include <windows.h>
#include <process.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"
#include "stack.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
char ** ERegTypes = 1;
char * gHiveName = 1;
#pragma GCC diagnostic pop
//const char * hostname, HKEY hivekey, DWORD Arch, const char* keystring, int depth, int maxdepth)

typedef struct _regkeyval{
    char * keypath;
    DWORD dwkeypathsz;
    HKEY hreg;
} regkeyval, *pregkeyval;

void init_enums(){
    ERegTypes = antiStringResolve(12, "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REGDWORD_BE", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESC", "REG_RESOURCE_REQ_LIST", "REG_QWORD");
}

void free_enums(){
    intFree(ERegTypes);
}

//HKEY compare didn't work in BOF for some reason
void set_hive_name(DWORD h)
{
    if(h == 2)
    {
        gHiveName = "HKEY_LOCAL_MACHINE";
    }else if (h == 1)
    {
        gHiveName = "HKEY_CURRENT_USER";
    }else if (h == 3)
    {
        gHiveName = "HKEY_USERS";
    }else if(h == 0)
    {
        gHiveName = "HKEY_CLASSES_ROOT";
    } else
    {
        gHiveName = "UNKNOWN";
    }
}

pregkeyval init_regkey(const char * curpath, DWORD dwcurpathsz, const char * childkey, DWORD dwchildkeysz, HKEY hreg)
{
    pregkeyval item = (pregkeyval)intAlloc(sizeof(regkeyval));
    item->dwkeypathsz = dwcurpathsz + ((dwchildkeysz) ? dwchildkeysz + 1 : 0); //str\str does not include null or just str, if we don't have a child key
    item->keypath = intAlloc(item->dwkeypathsz + 1);
    memcpy(item->keypath, curpath, dwcurpathsz);
    if(dwchildkeysz > 0)
    {
        item->keypath[dwcurpathsz] = '\\';
        memcpy(item->keypath + dwcurpathsz + 1, childkey, dwchildkeysz);
    }
    item->hreg = hreg;
    //item->keypath[item->dwkeypathsz] = 0;
    return item;
}

void free_regkey(pregkeyval val)
{
    if(val->keypath)
    {
        intFree(val->keypath);
    }
    if(val->hreg)
    {
        ADVAPI32$RegCloseKey(val->hreg);
    }
}

void Reg_InternalPrintKey(char * data, const char * valuename, DWORD type, DWORD datalen){
    char default_name[] = {'[', 'N', 'U', 'L', 'L', ']', 0};
    int i = 0;
    if(valuename == NULL)
    {
        valuename = default_name;
    }
    internal_printf("\t%-20s   %-15s ", valuename, (type >= 0 && type <= 11) ? ERegTypes[type] : "UNKNOWN");

    if(type == REG_BINARY)
    {
        for(i = 0; i < datalen; i++)
        {
            if(i % 16 == 0)
                internal_printf("\n");
            internal_printf(" %2.2x ", data[i] & 0xff);  
        }
        internal_printf("\n");
    }
    else if ((type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) && datalen == 4)
        internal_printf("%lu\n", *(DWORD *)data);
    else if (type == REG_QWORD && datalen == 8)
        internal_printf("%llu\n", *(QWORD *)data);
    else if (type == REG_SZ || type == REG_EXPAND_SZ)
        internal_printf("%s\n", data);
    else if (type == REG_MULTI_SZ)
    {
        while(data[0] != '\0')
        {
            DWORD len = MSVCRT$strlen(data)+1;
            internal_printf("%s%s", data, (data[len]) ? "\\0" : "");
            data += MSVCRT$strlen(data)+1;
        }
        internal_printf("\n");
    }
    else
    {
        internal_printf("None data type, or unhandled\n");
    }

}

DWORD Reg_GetValue(const char * hostname, HKEY hivekey, DWORD Arch, const char* keystring, const char* value){
    HKEY key = 0;
	HKEY RemoteKey = NULL;
    char* ValueData = NULL;
	DWORD type = 0;
    DWORD dwRet = 0;
    ValueData = NULL;
    DWORD flags = RRF_RT_ANY;
    DWORD size = 0;
	if(hostname == NULL)
	{
		dwRet = ADVAPI32$RegOpenKeyExA(hivekey, keystring, 0, KEY_READ, &key);

		if(dwRet){ goto END;}
	}
	else
	{
		dwRet = ADVAPI32$RegConnectRegistryA(hostname, hivekey, &RemoteKey);

		if(dwRet){
			internal_printf("failed to connect"); 
			goto END;
			}
		dwRet = ADVAPI32$RegOpenKeyExA(RemoteKey, keystring, 0, KEY_READ, &key);

		if(dwRet){
			internal_printf("failed to open remote key"); 
			goto END;
			}
	}

    dwRet = ADVAPI32$RegQueryValueExA( key,
                        value,
                        NULL,
                        &type,
                        NULL,
                        &size );
    if(dwRet != ERROR_SUCCESS){goto END;}
    if(type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)
        size += 2; // This makes sure that even if the string was stored without the appropriate terminating characters we don't overrun, 2 because multi needs 2
    ValueData = intAlloc(size);
    if (ValueData == NULL){
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory\n");
        dwRet =  E_OUTOFMEMORY;
        goto END;
    }
    dwRet = ADVAPI32$RegQueryValueExA( 
        key,
        value,
        NULL,
        &type,
        (LPBYTE)ValueData,
        &size
    );
	if(!dwRet)
	{
        internal_printf("%s\\%s\n", gHiveName, keystring);
        Reg_InternalPrintKey(ValueData, value, type, size);
	}
    END:
	if(ValueData)
		intFree(ValueData);
    if(key)
     	ADVAPI32$RegCloseKey(key);
	if(RemoteKey)
		ADVAPI32$RegCloseKey(RemoteKey);
    return dwRet;


}

DWORD Reg_EnumKey(const char * hostname, HKEY hivekey, DWORD Arch, const char* keystring, BOOL recursive){
    DWORD testval = 0;
    DWORD    cbName = 0;                   // size of name string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey = 0;              // longest subkey size 
    DWORD    cchMaxClass = 0;              // longest class string 
    DWORD    cValues = 0;              // number of values for key 
    DWORD    cchMaxValue = 0;          // longest value name 
    DWORD cchMaxData = 0;
    DWORD cchData = 0;
    DWORD cchValue = 0;
    DWORD   regType = 0;
    DWORD i = 0, j = 0, retCode = 0;
	DWORD dwresult = 0;
	HKEY rootkey = 0;
    HKEY curKey = 0;
	HKEY RemoteKey = 0;
    Pstack keyStack = NULL;
    pregkeyval curitem = NULL;
    char * errormsg = NULL; 
    char * currentkeyname = NULL;
    char * currentvaluename = NULL;
    char * currentdata = NULL;
    //char * fullkeyname = NULL;
	if(hostname == NULL)
	{
		dwresult = ADVAPI32$RegOpenKeyExA(hivekey, keystring, 0, KEY_READ, &rootkey);

		if(dwresult){ goto END;}
	}
	else
	{
		dwresult = ADVAPI32$RegConnectRegistryA(hostname, hivekey, &RemoteKey);

		if(dwresult){
			internal_printf("failed to connect"); 
			goto END;
			}
		dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, keystring, 0, KEY_READ, &rootkey);

		if(dwresult){
			internal_printf("failed to open remote key"); 
			goto END;
			}
	}
    keyStack = stackInit();

    keyStack->push(keyStack, init_regkey(keystring, MSVCRT$strlen(keystring), NULL, 0, rootkey));
    while((curitem = keyStack->pop(keyStack)) != NULL)
    {
        
        internal_printf("%s%s\n", gHiveName, curitem->keypath);
        // Get the class name and the value count.
        dwresult = ADVAPI32$RegQueryInfoKeyA(
            curitem->hreg,                    // key handle 
            NULL,                // buffer for class name 
            NULL,                // size of class string 
            NULL,                    // reserved 
            &cSubKeys,               // number of subkeys 
            &cbMaxSubKey,            // longest subkey size 
            NULL,            // longest class string 
            &cValues,                // number of values for this key 
            &cchMaxValue,            // longest value name 
            &cchMaxData,         // longest value data 
            NULL,   // security descriptor 
            NULL);       // last write time 
    
            if(dwresult){
                internal_printf("failed to query info about key"); 
                goto nextloop;
                }
        // Enumerate the subkeys, until RegEnumKeyEx fails.
        currentkeyname = intAlloc(cbMaxSubKey +1);
        currentvaluename = intAlloc(cchMaxValue+2);
        currentdata = intAlloc(cchMaxData);
        if (cValues) 
        {
            for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
            { 
                cchValue = cchMaxValue+2; 
                cchData = cchMaxData;
                retCode = ADVAPI32$RegEnumValueA(curitem->hreg, i, 
                    currentvaluename, 
                    &cchValue, 
                    NULL, 
                    &regType,
                    (LPBYTE)currentdata,
                    &cchData);
                if (retCode == ERROR_SUCCESS ) 
                { 
                        Reg_InternalPrintKey(currentdata, currentvaluename, regType, cchData);
                } 
                
            }
            internal_printf("\n");
        }
        if (cSubKeys)
        {
            for (i=0; i<cSubKeys; i++) 
            { 
                cbName = cbMaxSubKey +1;
                retCode = ADVAPI32$RegEnumKeyExA(curitem->hreg, i,
                        currentkeyname, 
                        &cbName, 
                        NULL, 
                        NULL, 
                        NULL, 
                        NULL); 
                if (retCode == ERROR_SUCCESS) 
                {
                    if(recursive)
                    {
                        dwresult = ADVAPI32$RegOpenKeyExA(curitem->hreg, currentkeyname, 0, KEY_READ, &curKey);
                        if(dwresult)
                        {
                            BeaconPrintf(CALLBACK_ERROR, "Could not open key %s\\%s\\%s: Error %lx", gHiveName, curitem->keypath, currentkeyname, dwresult);
                        }
                        else{
                            keyStack->push(keyStack, init_regkey(curitem->keypath, curitem->dwkeypathsz, currentkeyname, cbName, curKey));
                        }
                    }
                    else
                    {
                        internal_printf("%s%s\\%s\n", gHiveName, curitem->keypath, currentkeyname);
                    }
                }
            }
        } 
        nextloop:
        if(currentkeyname)
        {intFree(currentkeyname); currentkeyname = NULL;}
        if(currentvaluename)
        {intFree(currentvaluename); currentvaluename = NULL;}
        if(currentdata)
        {intFree(currentdata); currentdata = NULL;}
        cSubKeys = 0;
        cbMaxSubKey = 0;
        cValues = 0;
        cchMaxValue = 0;
        cchMaxData = 0;
		if (curitem)
		{
			free_regkey(curitem);
			intFree(curitem);
			curitem = NULL;
		}
    } // end While

	END:
	if(rootkey){
    	ADVAPI32$RegCloseKey(rootkey);
	}
    if(currentkeyname != NULL)
        intFree(currentkeyname);
    if(currentvaluename != NULL)
        intFree(currentvaluename);
    if(currentdata != NULL)
        intFree(currentdata);
	if(RemoteKey)
		ADVAPI32$RegCloseKey(RemoteKey);
    if(keyStack)
    {
        keyStack->free(keyStack);
    }
	return dwresult;
}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	const char * hostname = NULL;
	HKEY hive = (HKEY)0x80000000;

	const char * path = NULL;
	const char * key = NULL;
	int t = 0;
    BOOL recursive = FALSE;
	DWORD dwresult = 0;
    init_enums();
	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	t = BeaconDataInt(&parser);
    set_hive_name(t);
    #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	hive = (HKEY)((DWORD) hive + (DWORD)t);
    #pragma GCC diagnostic pop
	path = BeaconDataExtract(&parser, NULL);
	key = BeaconDataExtract(&parser, NULL);
    recursive = BeaconDataInt(&parser);
	//correct hostname param
	if(*hostname == 0)
	{
		hostname = NULL;
	}
	if(*key == 0)
	{
		key = NULL;
	}
	if(!bofstart())
	{
		return;
	}
	if(key)
	{
		dwresult = Reg_GetValue(hostname,hive,0,path,key);
	}
	else
	{
		dwresult = Reg_EnumKey(hostname,hive,0,path, recursive);
	}
	if(dwresult)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to query Regkey, error value: %d", dwresult);
	}
	printoutput(TRUE);
    free_enums();
};

#else

int main()
{
    init_enums();
    gHiveName = "Testname";
    Reg_EnumKey(NULL,HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\webclient", 1);
    Reg_EnumKey(NULL,HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\webclient", FALSE);
    Reg_EnumKey(NULL,HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\asdf\\webclient", TRUE);
    Reg_GetValue(NULL,HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\webclient","ImagePath");
    Reg_GetValue(NULL,HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\webclient","nope");
    Reg_GetValue(NULL,HKEY_LOCAL_MACHINE,0,"nope","ImagePath");
    Reg_EnumKey("172.31.0.1",HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\vds", TRUE);
    Reg_EnumKey("172.31.0.1",HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\vds", FALSE);
    Reg_EnumKey("172.31.0.1",HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\asdf\\vds", TRUE);
    Reg_GetValue("172.31.0.1",HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\vds","ImagePath");
    Reg_GetValue("172.31.0.1",HKEY_LOCAL_MACHINE,0,"system\\currentcontrolset\\services\\vds","nope");
    Reg_GetValue("172.31.0.1",HKEY_LOCAL_MACHINE,0,"nope","ImagePath");
    Reg_GetValue("nope",HKEY_LOCAL_MACHINE,0,"nope","ImagePath");
    free_enums();
    return 0;
}

#endif