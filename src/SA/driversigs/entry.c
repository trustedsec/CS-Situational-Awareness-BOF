//Credit for this function goes to http://jackson-t.ca/edr-reversing-evading-02.html
//This code is adapted from the repo published here https://gist.github.com/jthuraisamy/4c4c751df09f83d3620013f5d370d3b9

#include <windows.h>
#include <winternl.h>
#include <imagehlp.h>
#include "bofdefs.h"
#include "base.c"

DWORD intstrlen(const char * s, BOOL u)
{
    DWORD i = 0;
    if(u)
    {
    while(s[i] || s[i+1])
    {
        i++;
    }
    return i + i%2;
    }
    else 
    while(s[i])
    {
        i++;
    }
    return i;
}


void makestr(PUNICODE_STRING ustr, const wchar_t * string)
{

    ustr->Buffer = (wchar_t *)string;
    ustr->Length = intstrlen((const char *)string, TRUE);
    ustr->MaximumLength = ustr->Length + 2;

}

int validate_driver(wchar_t * file_path)
{
	wchar_t mypath[512] = {0};
	wchar_t *  drivers[8]; // make sure you update this if you cange the list below
	PCCERT_CONTEXT certificate_context = NULL;
	LPWIN_CERTIFICATE certificate = NULL;
	LPWIN_CERTIFICATE certificate_header = NULL;
	HANDLE file_handle = 0;
	int ret = 0;
	
	drivers[0] = L"Carbon Black, Inc.";
	drivers[1] = L"CrowdStrike, Inc.";
	drivers[2] = L"Cylance, Inc.";
	drivers[3] = L"FireEye, Inc.";
	drivers[4] = L"McAfee, Inc.";
	drivers[5] = L"Sentinel Labs, Inc.";
	drivers[6] = L"Symantec Corporation";
	drivers[7] = L"Tanium Inc."; 
	//drivers[8] = L"Vmware, Inc.";// I did this because bof can't handle it being defined like a normal array of wchar_t's uncomment this if you want to just verify things are working and you don't have an edr in your lab to hit
	
	if(file_path == NULL || *file_path == 0)
		return 1;

	if((*file_path) != '\\')
	{
		MSVCRT$wcscat(mypath, L"\\SystemRoot\\");
		MSVCRT$wcscat(mypath, file_path);
	}
	else{
		MSVCRT$wcscat(mypath, file_path);
	}

	
	// Create handle to driver file.

	UNICODE_STRING file_path_us = { 0 };
	makestr(&file_path_us, mypath);
	OBJECT_ATTRIBUTES object_attributes = { 0 };
	object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);
	object_attributes.RootDirectory = NULL;
	object_attributes.ObjectName = &file_path_us;
	object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
	object_attributes.SecurityDescriptor = NULL;
	object_attributes.SecurityQualityOfService = NULL;
	IO_STATUS_BLOCK io_status_block = { 0 };
	NTDLL$NtCreateFile(&file_handle, GENERIC_READ, &object_attributes, &io_status_block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (!file_handle)
	{
		internal_printf("%S -> cannot obtain handle (insufficient privs?)\n", mypath);
		ret = 1;
		goto end;
	}

	// Count certificates in file.
	unsigned long certificate_count = 0;
	if(!IMAGEHLP$ImageEnumerateCertificates(file_handle, CERT_SECTION_TYPE_ANY, &certificate_count, NULL, 0))
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to enumerate certs");
		goto end;
	}

	for (unsigned long i = 0; i < certificate_count; i++)
	{
		// Determine the length for the ImageGetCertificateData call.
		certificate_header = (LPWIN_CERTIFICATE)intAlloc(sizeof(WIN_CERTIFICATE));
		if(!IMAGEHLP$ImageGetCertificateHeader(file_handle, i, certificate_header))
		{ 		
			BeaconPrintf(CALLBACK_ERROR, "Failed to get header of cert");
			goto clear;
		}

		// Get the buffer for the certificate.
		unsigned long certificate_length = certificate_header->dwLength;
		certificate = (LPWIN_CERTIFICATE)intAlloc(certificate_length);
		if(!IMAGEHLP$ImageGetCertificateData(file_handle, i, certificate, &certificate_length))
		{ 		
			BeaconPrintf(CALLBACK_ERROR, "Failed to get cert data");
			goto clear;
		}
		// Call CryptVerifyMessageSignature to get a context used for CertGetNameStringW.
		CRYPT_VERIFY_MESSAGE_PARA verify_params = { 0 };
		verify_params.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
		verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

		if(!CRYPT32$CryptVerifyMessageSignature(&verify_params, i, certificate->bCertificate, certificate->dwLength, NULL, NULL, &certificate_context))
		{ 		
			BeaconPrintf(CALLBACK_ERROR, "Failed to verify message");
			goto clear;
		}
		// Get the name string for the certificate.
		wchar_t certificate_name[MAX_PATH] = { 0 };
		CRYPT32$CertGetNameStringW(certificate_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, (LPWSTR)&certificate_name, MAX_PATH);


		for(int i = 0; i < (sizeof(drivers) / sizeof(wchar_t*)); i++)
		{	
			if (MSVCRT$_wcsicmp(drivers[i], certificate_name) == 0)
				internal_printf("%S -> %S\n", file_path, certificate_name);

		}
		clear:
		if (certificate_context)
		{
			CRYPT32$CertFreeCertificateContext(certificate_context);
			certificate_context = NULL;
		}
		if(certificate_header)
		{
			intFree(certificate_header);
			certificate_header = NULL;
		}
		if(certificate)
		{
			intFree(certificate);
			certificate = NULL;
		}
	}
	end:
	if(file_handle)
	{
		NTDLL$NtClose(file_handle);
		file_handle = 0;
	}
	return ret;
}


int enumerate_loaded_drivers()
{
	// Create a handle to the service manager for calls to EnumServicesStatusExW.
	SC_HANDLE scm_handle = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm_handle)
	{
		internal_printf("[ERROR] Cannot open handle to service manager.\n");
		return 1;
	}
	
	// Determine the bytes needed for allocation.
	unsigned long bytes_needed = 0;
	unsigned long services_returned = 0;
	ADVAPI32$EnumServicesStatusExW(scm_handle, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, NULL, 0, &bytes_needed, &services_returned, NULL, NULL);

	// Retrieve a buffer of active driver services.
	PBYTE services = (PBYTE)intAlloc(bytes_needed);
	if (!ADVAPI32$EnumServicesStatusExW(scm_handle, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER , SERVICE_ACTIVE, services, bytes_needed, &bytes_needed, &services_returned, NULL, NULL))
	{
		internal_printf("[ERROR] Cannot enumerate services -> %ld.\n", KERNEL32$GetLastError());
		return 1;
	}
	LPENUM_SERVICE_STATUS_PROCESSW service = (LPENUM_SERVICE_STATUS_PROCESSW)services;
	// Get the ImagePath for each service from registry, and pass that to the validate_driver() function.
	for (unsigned long i = 0; i < services_returned; i++)
	{
		PWCHAR registry_path = (PWCHAR)intAlloc(MAX_PATH * 2);
		if (registry_path)
		{
			MSVCRT$wcsncat(registry_path,  L"SYSTEM\\CurrentControlSet\\Services\\", MAX_PATH);
			MSVCRT$wcsncat(registry_path, service->lpServiceName, MAX_PATH);
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Out of memory");
			return 1;
		}
		
		HKEY key_handle;
		ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, registry_path, 0, KEY_QUERY_VALUE, &key_handle);
		
		unsigned long length = 0;
		ADVAPI32$RegQueryValueExW(key_handle, L"ImagePath", NULL, NULL, NULL, &length);
		intFree(registry_path);
		if (length)
		{
			PWCHAR driver_path = (PWCHAR)intAlloc(length);
			ADVAPI32$RegQueryValueExW(key_handle, L"ImagePath", NULL, NULL, (LPBYTE)driver_path, &length);
			validate_driver(driver_path);
			intFree(driver_path);
		}
		
		KERNEL32$CloseHandle(key_handle);
		service++;
	}

	intFree(services);
	KERNEL32$CloseHandle(scm_handle);
	return 0;
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
	enumerate_loaded_drivers();
	printoutput(TRUE);
};
#else

int main()
{
	enumerate_loaded_drivers();
	return 1;
}

#endif
