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

DWORD validate_driver(wchar_t * file_path)
{
	DWORD dwStatus = ERROR_SUCCESS;
	wchar_t mypath[512] = {0};
	wchar_t *  drivers[8]; // make sure you update this if you change the list below
	PCCERT_CONTEXT certificate_context = NULL;
	LPWIN_CERTIFICATE certificate = NULL;
	LPWIN_CERTIFICATE certificate_header = NULL;
	HANDLE file_handle = 0;
	UNICODE_STRING file_path_us = { 0 };
	OBJECT_ATTRIBUTES object_attributes = { 0 };
	IO_STATUS_BLOCK io_status_block = { 0 };
	unsigned long certificate_count = 0;
	unsigned long certificate_length = 0;
	CRYPT_VERIFY_MESSAGE_PARA verify_params = { 0 };
	wchar_t certificate_name[MAX_PATH] = { 0 };
	
	drivers[0] = L"Carbon Black, Inc.";
	drivers[1] = L"CrowdStrike, Inc.";
	drivers[2] = L"Cylance, Inc.";
	drivers[3] = L"FireEye, Inc.";
	drivers[4] = L"McAfee, Inc.";
	drivers[5] = L"Sentinel Labs, Inc.";
	drivers[6] = L"Symantec Corporation";
	drivers[7] = L"Tanium Inc."; 
	//drivers[8] = L"Vmware, Inc.";// I did this because bof can't handle it being defined like a normal array of wchar_t's uncomment this if you want to just verify things are working and you don't have an edr in your lab to hit
	
	if (file_path == NULL || *file_path == 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Invalid file_path\n");
		dwStatus = ERROR_BAD_ARGUMENTS;
		goto end;
	}

	if((*file_path) != '\\')
	{
		MSVCRT$wcscat(mypath, L"\\SystemRoot\\");
		MSVCRT$wcscat(mypath, file_path);
	}
	else{
		MSVCRT$wcscat(mypath, file_path);
	}

	
	// Create handle to driver file.

	
	makestr(&file_path_us, mypath);
	
	object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);
	object_attributes.RootDirectory = NULL;
	object_attributes.ObjectName = &file_path_us;
	object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
	object_attributes.SecurityDescriptor = NULL;
	object_attributes.SecurityQualityOfService = NULL;
	
	dwStatus = (DWORD)NTDLL$NtCreateFile(&file_handle, GENERIC_READ, &object_attributes, &io_status_block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(dwStatus))
	{
		BeaconPrintf(CALLBACK_ERROR, "NTDLL$NtCreateFile(%S) failed (%lu)\n", mypath, dwStatus);
		goto end;
	}
	if (!file_handle)
	{
		BeaconPrintf(CALLBACK_ERROR, "%S -> cannot obtain handle (insufficient privs?)\n", mypath);
		dwStatus = ERROR_INVALID_HANDLE;
		goto end;
	}

	// Count certificates in file.
	if(!IMAGEHLP$ImageEnumerateCertificates(file_handle, CERT_SECTION_TYPE_ANY, &certificate_count, NULL, 0))
	{
		dwStatus = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "IMAGEHLP$ImageEnumerateCertificates failed. (%lu)", dwStatus);
		goto end;
	}

	for (unsigned long i = 0; i < certificate_count; i++)
	{
		// Determine the length for the ImageGetCertificateData call.
		certificate_header = (LPWIN_CERTIFICATE)intAlloc(sizeof(WIN_CERTIFICATE));
		if (NULL == certificate_header)
        	{
			dwStatus = ERROR_OUTOFMEMORY;
			internal_printf("WARNING: certificate_header allocation failed (%lu)", dwStatus);
			goto clear;
        	}

		if(!IMAGEHLP$ImageGetCertificateHeader(file_handle, i, certificate_header))
		{ 		
			dwStatus = KERNEL32$GetLastError();
			internal_printf("WARNING: IMAGEHLP$ImageGetCertificateHeader failed. (%lu)", dwStatus);
			goto clear;
		}

		// Get the buffer for the certificate.
		certificate_length = certificate_header->dwLength;
		certificate = (LPWIN_CERTIFICATE)intAlloc(certificate_length);
	        if (NULL == certificate)
        	{
			dwStatus = ERROR_OUTOFMEMORY;
			internal_printf("WARNING: certificate allocation failed (%lu)", dwStatus);
			goto clear;
	        }
		if(!IMAGEHLP$ImageGetCertificateData(file_handle, i, certificate, &certificate_length))
		{ 		
			dwStatus = KERNEL32$GetLastError();
			internal_printf("WARNING: IMAGEHLP$ImageGetCertificateData failed. (%lu)", dwStatus);
			goto clear;
		}
		// Call CryptVerifyMessageSignature to get a context used for CertGetNameStringW.
		
		verify_params.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
		verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
		if(!CRYPT32$CryptVerifyMessageSignature(&verify_params, i, certificate->bCertificate, certificate->dwLength, NULL, NULL, &certificate_context))
		{ 		
			dwStatus = KERNEL32$GetLastError();
			internal_printf("WARNING: CRYPT32$CryptVerifyMessageSignature failed. (%lu)", dwStatus);
			goto clear;
		}
		// Get the name string for the certificate.
		
		CRYPT32$CertGetNameStringW(certificate_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, (LPWSTR)&certificate_name, MAX_PATH);
		for(unsigned int j = 0; j < (sizeof(drivers) / sizeof(wchar_t*)); j++)
		{	
			if (MSVCRT$_wcsicmp(drivers[j], certificate_name) == 0)
			{
				internal_printf("FOUND: %S -> %S\n", file_path, certificate_name);
			}
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
		// reset dwStatus
		dwStatus = ERROR_SUCCESS;
	} // end for loop through certificates

end:
	if(file_handle)
	{
		NTDLL$NtClose(file_handle);
		file_handle = 0;
	}
	return dwStatus;
}


DWORD enumerate_loaded_drivers()
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scm_handle = NULL;
	unsigned long bytes_needed = 0;
	unsigned long services_returned = 0;
	PBYTE services = NULL;
	PWCHAR registry_path = NULL;
	HKEY key_handle = NULL;
	unsigned long length = MAX_PATH * 2;
	PWCHAR driver_path = NULL;
	
	// Allocate memory for registry path buffer.
	registry_path = (PWCHAR)intAlloc(MAX_PATH * 2);
	if (NULL == registry_path)
	{
		dwResult = ERROR_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
		goto fail;
	}

	// Allocate memory for registry path buffer.
	driver_path = (PWCHAR)intAlloc(MAX_PATH * 2);
	if (NULL == driver_path)
	{
		dwResult = ERROR_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
		goto fail;
	}

	// Create a handle to the service manager for calls to EnumServicesStatusExW.
	scm_handle = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm_handle)
	{
		dwResult = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$OpenSCManagerA failed. (%lu)\n", dwResult);
		goto fail;
	}
	
	// Determine the bytes needed for allocation.
	if (FALSE == ADVAPI32$EnumServicesStatusExW(scm_handle, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, NULL, 0, &bytes_needed, &services_returned, NULL, NULL))
	{
		dwResult = KERNEL32$GetLastError();
		if (ERROR_MORE_DATA != dwResult)
		{
			BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$EnumServicesStatusExW failed. (%lu)\n", dwResult);
			goto fail;
		}
	}
	dwResult = ERROR_SUCCESS;

	// Allocate memory for the services buffer.
	services = (PBYTE)intAlloc(bytes_needed);
	if (NULL == services)
	{
		dwResult = ERROR_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "Out of memory\n");
		goto fail;
	}

	// Retrieve a buffer of active driver services.
	if (FALSE == ADVAPI32$EnumServicesStatusExW(scm_handle, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER , SERVICE_ACTIVE, services, bytes_needed, &bytes_needed, &services_returned, NULL, NULL))
	{
		dwResult = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$EnumServicesStatusExW failed. (%lu)\n", dwResult);
		goto fail;
	}

	LPENUM_SERVICE_STATUS_PROCESSW service = (LPENUM_SERVICE_STATUS_PROCESSW)services;
	// Get the ImagePath for each service from registry, and pass that to the validate_driver() function.
	for (unsigned long i = 0; i < services_returned; i++)
	{
		// Set the registry path
		MSVCRT$memset(driver_path, 0, (MAX_PATH * 2));
		MSVCRT$memset(registry_path, 0, (MAX_PATH * 2));
		MSVCRT$wcsncat(registry_path,  L"SYSTEM\\CurrentControlSet\\Services\\", MAX_PATH);
		MSVCRT$wcsncat(registry_path, service->lpServiceName, MAX_PATH);
		
		// Open the registry key
		dwResult = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, registry_path, 0, KEY_QUERY_VALUE, &key_handle);
		if (ERROR_SUCCESS != dwResult)
		{
			BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$RegOpenKeyExW failed. (%lu)\n", dwResult);
			goto fail;
		}

		length = MAX_PATH * 2;

		// Actually query the IMagePath and fill in the buffer
		dwResult = ADVAPI32$RegQueryValueExW(key_handle, L"ImagePath", NULL, NULL, (LPBYTE)driver_path, &length);
		if (ERROR_SUCCESS != dwResult)
		{
			//BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$RegQueryValueExW failed. (%lu)\n", dwResult);
			//goto fail;
			internal_printf("WARNING: Failed to get ImagePath for %S\n", service->lpServiceName);
			dwResult = ERROR_SUCCESS;
		}
		else
		{
			// Validate the driver
			if (0 != validate_driver(driver_path))
			{
				internal_printf("WARNING: validate_driver failed for %S\n", driver_path);
			}
		}
		
		if (NULL != key_handle)
		{
			KERNEL32$CloseHandle(key_handle);
			key_handle = NULL;
		}
		service++;
	}

fail:
	if (services)
	{
		intFree(services);
		services = NULL;
	}
	if (registry_path)
	{
		intFree(registry_path);
		registry_path = NULL;
	}
	if (driver_path)
	{
		intFree(driver_path);
		driver_path = NULL;
	}
	if (NULL != key_handle)
	{
		ADVAPI32$RegCloseKey(key_handle);
		key_handle = NULL;
	}
	if (scm_handle)
	{
		ADVAPI32$CloseServiceHandle(scm_handle);
		scm_handle = NULL;
	}
	return dwResult;
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
	if (0 != enumerate_loaded_drivers())
	{
		BeaconPrintf(CALLBACK_ERROR, "enumerate_loaded_drivers failed");
	}
	printoutput(TRUE);
};
#else

int main()
{
	if (0 != enumerate_loaded_drivers())
	{
		BeaconPrintf(CALLBACK_ERROR, "enumerate_loaded_drivers failed");
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "enumerate_loaded_drivers was successful");
	}
	return 1;
}

#endif
