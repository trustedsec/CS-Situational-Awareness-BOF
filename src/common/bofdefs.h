#pragma once
#pragma intrinsic(memcpy,strcpy,strcmp,strlen)
#include <windows.h>
#include <process.h>
#include <winternl.h>
#include <imagehlp.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <windns.h>
#include <dbghelp.h>
#include <winldap.h>

//KERNEL32
#ifdef BOF
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc (UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree (HLOCAL);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI Kernel32$FormatMessageA (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime (CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime (CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI int WINAPI KERNEL32$GetDateFormatW (LCID Locale, DWORD dwFlags, CONST SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemTimeAsFileTime (LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount (VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$CreateFiber (SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
WINBASEAPI LPVOID WINAPI KERNEL32$ConvertThreadToFiber (LPVOID lpParameter);
WINBASEAPI WINBOOL WINAPI KERNEL32$ConvertFiberToThread (VOID);
WINBASEAPI VOID WINAPI KERNEL32$DeleteFiber (LPVOID lpFiber);
WINBASEAPI VOID WINAPI KERNEL32$SwitchToFiber (LPVOID lpFiber);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
WINBASEAPI WINBOOL WINAPI KERNEL32$DeleteFileW (LPCWSTR lpFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameExW (COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize);
WINBASEAPI int WINAPI KERNEL32$lstrlenW (LPCWSTR lpString);
WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcatW (LPWSTR lpString1, LPCWSTR lpString2);
WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcpynW (LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength);
WINBASEAPI DWORD WINAPI KERNEL32$GetFullPathNameW (LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW (LPCWSTR lpFileName);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentDirectoryW (DWORD nBufferLength, LPWSTR lpBuffer);
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileW (LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI WINBOOL WINAPI KERNEL32$FindNextFileW (HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI WINBOOL WINAPI KERNEL32$FindClose (HANDLE hFindFile);
WINBASEAPI VOID WINAPI KERNEL32$SetLastError (DWORD dwErrCode);
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree(HGLOBAL hMem);

//Iphlpapi.lib
//ULONG WINAPI IPHLPAPI$GetAdaptersInfo (PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO,PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpForwardTable (PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, WINBOOL bOrder);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO,PULONG);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetUdpTable (PMIB_UDPTABLE UdpTable, PULONG SizePointer, WINBOOL Order);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetTcpTable (PMIB_TCPTABLE TcpTable, PULONG SizePointer, WINBOOL Order);

//MSVCRT
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI size_t __cdecl MSVCRT$strnlen(const char *_Str,size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$swprintf(wchar_t *__stream, const wchar_t *__format, ...);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$sprintf (char *__stream, const char *__format, ...);

WINBASEAPI wchar_t *__cdecl MSVCRT$wcstok(wchar_t * __restrict__ _Str,const wchar_t * __restrict__ _Delim);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsstr(const wchar_t *_Str,const wchar_t *_SubStr);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsncat(wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source, size_t _Count);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscpy(wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1,const wchar_t *_Str2);
WINBASEAPI _CONST_RETURN wchar_t *__cdecl MSVCRT$wcschr(const wchar_t *_Str, wchar_t _Ch);
WINBASEAPI wchar_t * __cdecl MSVCRT$wcsncat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source,size_t _Count);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsrchr(const wchar_t *_Str,wchar_t _Ch);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsrchr(const wchar_t *_Str,wchar_t _Ch);

DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);


//DNSAPI
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A(PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree(PVOID pData,DNS_FREE_TYPE FreeType);

//WSOCK32
DECLSPEC_IMPORT unsigned long __stdcall WSOCK32$inet_addr(const char *cp);
DECLSPEC_IMPORT u_long __stdcall WS2_32$htonl(u_long hostlong);
DECLSPEC_IMPORT u_short __stdcall WS2_32$htons(u_short hostshort);
DECLSPEC_IMPORT char * __stdcall WS2_32$inet_ntoa(struct in_addr in);

//NETAPI32
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserModalsGet(LPCWSTR servername,DWORD level,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetServerEnum(LMCSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,DWORD servertype,LMCSTR domain,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetGroups(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetLocalGroups(LPCWSTR servername,LPCWSTR username,DWORD level,DWORD flags,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
WINBASEAPI DWORD WINAPI NETAPI32$NetGetAnyDCName(LPCWSTR servername,LPCWSTR domainname,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserEnum(LPCWSTR servername,DWORD level,DWORD filter,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetGroupGetUsers(LPCWSTR servername,LPCWSTR groupname,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,PDWORD_PTR ResumeHandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetQueryDisplayInformation(LPCWSTR ServerName,DWORD Level,DWORD Index,DWORD EntriesRequested,DWORD PreferredMaximumLength,LPDWORD ReturnedEntryCount,PVOID *SortedBuffer);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupEnum(LPCWSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,PDWORD_PTR resumehandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupGetMembers(LPCWSTR servername,LPCWSTR localgroupname,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,PDWORD_PTR resumehandle);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserSetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE buf,LPDWORD parm_err);
WINBASEAPI DWORD WINAPI NETAPI32$NetShareEnum(LMSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

//user32
WINUSERAPI int WINAPI USER32$EnumDesktopWindows(HDESK hDesktop,WNDENUMPROC lpfn,LPARAM lParam);
WINUSERAPI int WINAPI USER32$IsWindowVisible (HWND hWnd);
WINUSERAPI int WINAPI USER32$GetWindowTextA(HWND hWnd,LPSTR lpString,int nMaxCount);
WINUSERAPI int WINAPI USER32$GetClassNameA(HWND hWnd,LPSTR lpClassName,int nMaxCount);
WINUSERAPI LPWSTR WINAPI USER32$CharPrevW(LPCWSTR lpszStart,LPCWSTR lpszCurrent);

//secur32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA (int NameFormat, LPSTR lpNameBuffer, PULONG nSize);

//advapi32
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid,LPSTR *StringSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA (LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeNameA (LPCSTR lpSystemName, PLUID lpLuid, LPSTR lpName, LPDWORD cchName);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeDisplayNameA (LPCSTR lpSystemName, LPCSTR lpName, LPSTR lpDisplayName, LPDWORD cchDisplayName, LPDWORD lpLanguageId);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE hService,LPSERVICE_STATUS lpServiceStatus);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE hService,LPQUERY_SERVICE_CONFIGA lpServiceConfig,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE hSCManager,SC_ENUM_TYPE InfoLevel,DWORD dwServiceType,DWORD dwServiceState,LPBYTE lpServices,DWORD cbBufSize,LPDWORD pcbBytesNeeded,LPDWORD lpServicesReturned,LPDWORD lpResumeHandle,LPCSTR pszGroupName);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService,SC_STATUS_TYPE InfoLevel,LPBYTE lpBuffer,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfig2A(SC_HANDLE hService,DWORD dwInfoLevel,LPBYTE lpBuffer,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfig2A(SC_HANDLE hService,DWORD dwInfoLevel,LPVOID lpInfo);
WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfigA(SC_HANDLE hService,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword,LPCSTR lpDisplayName);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
WINADVAPI WINBOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY hKey,LPCWSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExW(SC_HANDLE hSCManager,SC_ENUM_TYPE InfoLevel,DWORD dwServiceType,DWORD dwServiceState,LPBYTE lpServices,DWORD cbBufSize,LPDWORD pcbBytesNeeded,LPDWORD lpServicesReturned,LPDWORD lpResumeHandle,LPCWSTR pszGroupName);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyA(HKEY hKey,LPCSTR lpSubKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey,LPCSTR lpValueName,DWORD Reserved,DWORD dwType,CONST BYTE *lpData,DWORD cbData);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR lpMachineName,HKEY hKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyA(HKEY hKey,LPCSTR lpSubKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD Reserved,LPSTR lpClass,DWORD dwOptions,REGSAM samDesired,LPSECURITY_ATTRIBUTES lpSecurityAttributes,PHKEY phkResult,LPDWORD lpdwDisposition);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExA(HKEY hKey,LPCSTR lpSubKey,REGSAM samDesired,DWORD Reserved);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyValueA(HKEY hKey,LPCSTR lpSubKey,LPCSTR lpValueName);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY hKey,LPSTR lpClass,LPDWORD lpcchClass,LPDWORD lpReserved,LPDWORD lpcSubKeys,LPDWORD lpcbMaxSubKeyLen,LPDWORD lpcbMaxClassLen,LPDWORD lpcValues,LPDWORD lpcbMaxValueNameLen,LPDWORD lpcbMaxValueLen,LPDWORD lpcbSecurityDescriptor,PFILETIME lpftLastWriteTime);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumValueA(HKEY hKey,DWORD dwIndex,LPSTR lpValueName,LPDWORD lpcchValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY hKey,DWORD dwIndex,LPSTR lpName,LPDWORD lpcchName,LPDWORD lpReserved,LPSTR lpClass,LPDWORD lpcchClass,PFILETIME lpftLastWriteTime);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY hKey,LPCSTR lpValueName);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegSaveKeyExA(HKEY hKey,LPCSTR lpFile,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD Flags);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetFileSecurityW (LPCWSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetAce (PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW (LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid,LPWSTR *StringSid);
WINADVAPI VOID WINAPI ADVAPI32$MapGenericMask (PDWORD AccessMask, PGENERIC_MAPPING GenericMapping);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI WINBOOL WINAPI ADVAPI32$InitializeSecurityDescriptor (PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
WINADVAPI WINBOOL WINAPI ADVAPI32$SetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, WINBOOL bDaclPresent, PACL pDacl, WINBOOL bDaclDefaulted);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor,DWORD RequestedStringSDRevision,SECURITY_INFORMATION SecurityInformation,LPWSTR *StringSecurityDescriptor,PULONG StringSecurityDescriptorLen);


//NTDLL
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);

//IMAGEHLP
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageEnumerateCertificates(HANDLE FileHandle,WORD TypeFilter,PDWORD CertificateCount,PDWORD Indices,DWORD IndexCount);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateHeader(HANDLE FileHandle,DWORD CertificateIndex,LPWIN_CERTIFICATE Certificateheader);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateData(HANDLE FileHandle,DWORD CertificateIndex,LPWIN_CERTIFICATE Certificate,PDWORD RequiredLength);


WINADVAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors);
WINADVAPI WINBOOL WINAPI ADVAPI32$ControlService(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus);
WINADVAPI WINBOOL WINAPI ADVAPI32$EnumDependentServicesA(SC_HANDLE hService,DWORD dwServiceState,LPENUM_SERVICE_STATUSA lpServices,DWORD cbBufSize,LPDWORD pcbBytesNeeded,LPDWORD lpServicesReturned);
//cyprt32
WINIMPM WINBOOL WINAPI CRYPT32$CryptVerifyMessageSignature (PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara, DWORD dwSignerIndex, const BYTE *pbSignedBlob, DWORD cbSignedBlob, BYTE *pbDecoded, DWORD *pcbDecoded, PCCERT_CONTEXT *ppSignerCert);
WINIMPM DWORD WINAPI CRYPT32$CertGetNameStringW (PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
WINIMPM WINBOOL WINAPI CRYPT32$CertFreeCertificateContext (PCCERT_CONTEXT pCertContext);

//WS2_32
DECLSPEC_IMPORT LPCWSTR WINAPI WS2_32$InetNtopW(INT Family, LPCVOID pAddr, LPWSTR pStringBuf, size_t StringBufSIze);
DECLSPEC_IMPORT INT WINAPI WS2_32$inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);

//dnsapi
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree(PVOID pData,DNS_FREE_TYPE FreeType);
DECLSPEC_IMPORT int WINAPI DNSAPI$DnsGetCacheDataTable(PVOID data);

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx (LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize (void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity (PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities, void *pReserved3);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString (LPCOLESTR lpsz, LPCLSID pclsid);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString (LPCOLESTR lpsz, LPIID lpiid);
DECLSPEC_IMPORT	HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);
DECLSPEC_IMPORT LPVOID	WINAPI OLE32$CoTaskMemAlloc(SIZE_T cb);
DECLSPEC_IMPORT void	WINAPI OLE32$CoTaskMemFree(LPVOID pv);


//OLEAUT32
DECLSPEC_IMPORT BSTR	WINAPI OLEAUT32$SysAllocString(const OLECHAR *);
DECLSPEC_IMPORT INT		WINAPI OLEAUT32$SysReAllocString(BSTR *, const OLECHAR *);
DECLSPEC_IMPORT void	WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void	WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void	WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT	WINAPI OLEAUT32$SysAddRefString(BSTR);
DECLSPEC_IMPORT HRESULT	WINAPI OLEAUT32$VariantChangeType(VARIANTARG *pvargDest, VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt);
DECLSPEC_IMPORT void	WINAPI OLEAUT32$VarFormatDateTime(LPVARIANT pvarIn,int iNamedFormat,ULONG dwFlags,BSTR *pbstrOut);
DECLSPEC_IMPORT void	WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY *psa);
DECLSPEC_IMPORT HRESULT	WINAPI OLEAUT32$SafeArrayLock(SAFEARRAY *psa);
DECLSPEC_IMPORT HRESULT	WINAPI OLEAUT32$SafeArrayGetLBound(SAFEARRAY *psa, UINT nDim, LONG *plLbound);
DECLSPEC_IMPORT HRESULT	WINAPI OLEAUT32$SafeArrayGetUBound(SAFEARRAY *psa, UINT nDim, LONG *plUbound);
DECLSPEC_IMPORT HRESULT	WINAPI OLEAUT32$SafeArrayGetElement(SAFEARRAY *psa, LONG *rgIndices, void *pv);
DECLSPEC_IMPORT UINT	WINAPI OLEAUT32$SafeArrayGetElemsize(SAFEARRAY *psa);

//dbghelp
DECLSPEC_IMPORT WINBOOL WINAPI DBGHELP$MiniDumpWriteDump(HANDLE hProcess,DWORD ProcessId,HANDLE hFile,MINIDUMP_TYPE DumpType,CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

//WLDAP32
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_init(PSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_s(LDAP *ld,const PSTR  dn,const PCHAR cred,ULONG method);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_s(LDAP *ld,PSTR base,ULONG scope,PSTR filter,PZPSTR attrs,ULONG attrsonly,PLDAPMessage *res);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_entries(LDAP*,LDAPMessage*);

DECLSPEC_IMPORT LDAPMessage*  WINAPI WLDAP32$ldap_first_entry(LDAP *ld,LDAPMessage *res);
DECLSPEC_IMPORT LDAPMessage*  WINAPI WLDAP32$ldap_next_entry(LDAP*,LDAPMessage*);
DECLSPEC_IMPORT PCHAR WINAPI WLDAP32$ldap_first_attribute(LDAP *ld,LDAPMessage *entry,BerElement **ptr);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_values(PCHAR);
DECLSPEC_IMPORT PCHAR * WINAPI WLDAP32$ldap_get_values(LDAP *ld,LDAPMessage *entry,const PSTR attr);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free(PCHAR *);
DECLSPEC_IMPORT PCHAR WINAPI WLDAP32$ldap_next_attribute(LDAP *ld,LDAPMessage *entry,BerElement *ptr);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ber_free(BerElement *pBerElement,INT fbuf);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_memfree(PCHAR);

DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind_s(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);

//RPCRT4
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringA(UUID *Uuid,RPC_CSTR *StringUuid);
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR *String);

//PSAPI
DECLSPEC_IMPORT WINBOOL WINAPI PSAPI$EnumProcessModulesEx(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
DECLSPEC_IMPORT DWORD WINAPI PSAPI$GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);

//VERSION
DECLSPEC_IMPORT DWORD WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR lptstrFilenamea ,LPDWORD lpdwHandle);
DECLSPEC_IMPORT WINBOOL WINAPI VERSION$GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DECLSPEC_IMPORT WINBOOL WINAPI VERSION$VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);

#else
//Not Kept up to date, update if required
#pragma comment(lib "Dnsapi")
#define KERNEL32$VirtualAlloc VirtualAlloc
#define KERNEL32$VirtualFree VirtualFree
__forceinline LPVOID intAlloc(SIZE_T size, DWORD type) { return KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, type);}
#define KERNEL32$WideCharToMultiByte WideCharToMultiByte
#define Kernel32$WideCharToMultiByte WideCharToMultiByte
__forceinline LPVOID intAlloc(SIZE_T size) { return KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);}
__forceinline BOOL intFree(LPVOID addr) { return KERNEL32$VirtualFree(addr, 0, MEM_RELEASE);}

//Iphlpapi.lib
//ULONG WINAPI IPHLPAPI$GetAdaptersInfo (PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
#define IPHLPAPI$GetAdaptersInfo GetAdaptersInfo
#define IPHLPAPI$GetNetworkParams GetNetworkParams


//MSVCRT
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$calloc calloc
#define MSVCRT$realloc realloc
#define MSVCRT$free free
#define MSVCRT$strnlen strnlen
#define MSVCRT$strlen strlen
#define MSVCRT$memcpy memcpy

#define DNSAPI$DnsQuery_A DnsQuery_A
#define DNSAPI$DnsFree DnsFree
#define KERNEL32$LocalAlloc LocalAlloc
#define KERNEL32$LocalFree LocalFree
#define WSOCK32$inet_addr inet_addr
//DECLSPEC_IMPORT char * __stdcall  WS2_32$inet_ntop(INT Family, LPCVOID pAddr, LPSTR pStringBuf, size_t StringBufSize);
//DECLSPEC_IMPORT INT __stdcall WS2_32$inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);
#define Kernel32$FormatMessageA FormatMessageA
#define BeaconPrintf(x, y, ...) printf(y, ##__VA_ARGS__)
#define NETAPI32$NetServerEnum NetServerEnum
#define NETAPI32$NetApiBufferFree NetApiBufferFree
#define internal_printf printf
#endif
