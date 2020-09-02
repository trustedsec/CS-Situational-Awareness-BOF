#pragma once
#pragma intrinsic(memcpy,strcpy,strcmp,strlen)
#include <windows.h>
#include <winternl.h>
#include <imagehlp.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <windns.h>


//KERNEL32
#ifdef BOF
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc (UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree (HLOCAL);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI Kernel32$FormatMessageA (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime (CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime (CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI int WINAPI KERNEL32$GetDateFormatW (LCID Locale, DWORD dwFlags, CONST SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemTimeAsFileTime (LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

//Iphlpapi.lib
//ULONG WINAPI IPHLPAPI$GetAdaptersInfo (PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO,PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpForwardTable (PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, WINBOOL bOrder);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO,PULONG);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetUdpTable (PMIB_UDPTABLE UdpTable, PULONG SizePointer, WINBOOL Order);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetTcpTable (PMIB_TCPTABLE TcpTable, PULONG SizePointer, WINBOOL Order);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements,size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory,size_t _NewSize);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI size_t __cdecl MSVCRT$strnlen(const char *_Str,size_t _MaxCount);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$sprintf (char *__stream, const char *__format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcstok(wchar_t * __restrict__ _Str,const wchar_t * __restrict__ _Delim);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsstr(const wchar_t *_Str,const wchar_t *_SubStr);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source);
_CRTIMP int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1,const wchar_t *_Str2);
WINBASEAPI wchar_t * MSVCRT$wcsncat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source,size_t _Count);

//DNSAPI
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A(PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree(PVOID pData,DNS_FREE_TYPE FreeType);

//WSOCK32
DECLSPEC_IMPORT unsigned long __stdcall WSOCK32$inet_addr(const char *cp);
DECLSPEC_IMPORT u_long __stdcall WS2_32$htonl(u_long hostlong);
DECLSPEC_IMPORT u_short __stdcall WS2_32$htons(u_short hostshort);
DECLSPEC_IMPORT char * __stdcall WS2_32$inet_ntoa(struct in_addr in);

//NETAPI32
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserModalsGet(LPCWSTR servername,DWORD level,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetServerEnum(LMCSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,DWORD servertype,LMCSTR domain,LPDWORD resume_handle);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetGroups(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetLocalGroups(LPCWSTR servername,LPCWSTR username,DWORD level,DWORD flags,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
WINBASEAPI DWORD WINAPI NETAPI32$NetGetAnyDCName(LPCWSTR servername,LPCWSTR domainname,LPBYTE *bufptr);
WINBASEAPI DWORD WINAPI NETAPI32$NetUserEnum(LPCWSTR servername,DWORD level,DWORD filter,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,LPDWORD resume_handle);

//user32
WINUSERAPI int WINAPI USER32$EnumDesktopWindows(HDESK hDesktop,WNDENUMPROC lpfn,LPARAM lParam);
WINUSERAPI int WINAPI USER32$IsWindowVisible (HWND hWnd);
WINUSERAPI int WINAPI USER32$GetWindowTextA(HWND hWnd,LPSTR lpString,int nMaxCount);
WINUSERAPI int WINAPI USER32$GetClassNameA(HWND hWnd,LPSTR lpClassName,int nMaxCount);

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
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);


//NTDLL
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);

//IMAGEHLP
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageEnumerateCertificates(HANDLE FileHandle,WORD TypeFilter,PDWORD CertificateCount,PDWORD Indices,DWORD IndexCount);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateHeader(HANDLE FileHandle,DWORD CertificateIndex,LPWIN_CERTIFICATE Certificateheader);
WINBASEAPI WINBOOL IMAGEAPI IMAGEHLP$ImageGetCertificateData(HANDLE FileHandle,DWORD CertificateIndex,LPWIN_CERTIFICATE Certificate,PDWORD RequiredLength);


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

//netapi32
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetShareEnum(LMSTR servername,DWORD level,LPBYTE *bufptr,DWORD prefmaxlen,LPDWORD entriesread,LPDWORD totalentries,LPDWORD resume_handle);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
#else
//Not Kept up to date, update if required
#pragma comment(lib "Dnsapi")
#define KERNEL32$VirtualAlloc VirtualAlloc
#define KERNEL32$VirtualFree VirtualFree
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