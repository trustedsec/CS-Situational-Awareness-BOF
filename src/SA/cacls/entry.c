#include <windows.h>
#include "bofdefs.h"
#include "defines.h"
#include "base.c"
#include <sddl.h>
#include <windef.h>


//credit to the ReactOS project for this code

enum searchtype{
    File,
    Folder,
    Fail
};
#pragma pack (push, 1) // This is required because x64 can crash when running as a bof otherwise.
typedef struct _AR
{
    DWORD Access;
    const char * uID;
}AR, *pAR;
#pragma pack (pop)
pAR AccessRights = (pAR)1;

#define LOVEIT(a, b, c) a.Access = b; a.uID = c

void LovingIt() // Fix bof's inability to handle initialized ** type values
{
    AccessRights = (pAR)intAlloc(26 * sizeof(AR));
    LOVEIT(AccessRights[0], FILE_WRITE_ATTRIBUTES, IDS_FILE_WRITE_ATTRIBUTES);
    LOVEIT(AccessRights[1], FILE_READ_ATTRIBUTES, IDS_FILE_READ_ATTRIBUTES);
    LOVEIT(AccessRights[2], FILE_DELETE_CHILD, IDS_FILE_DELETE_CHILD);
    LOVEIT(AccessRights[3], FILE_EXECUTE, IDS_FILE_EXECUTE);
    LOVEIT(AccessRights[4], FILE_WRITE_EA, IDS_FILE_WRITE_EA);
    LOVEIT(AccessRights[5], FILE_READ_EA, IDS_FILE_READ_EA);
    LOVEIT(AccessRights[6], FILE_APPEND_DATA, IDS_FILE_APPEND_DATA);
    LOVEIT(AccessRights[7], FILE_WRITE_DATA, IDS_FILE_WRITE_DATA);
    LOVEIT(AccessRights[8], FILE_READ_DATA, IDS_FILE_READ_DATA);
    LOVEIT(AccessRights[9], FILE_GENERIC_EXECUTE, IDS_FILE_GENERIC_EXECUTE);
    LOVEIT(AccessRights[10], FILE_GENERIC_WRITE, IDS_FILE_GENERIC_WRITE);
    LOVEIT(AccessRights[11], FILE_GENERIC_READ, IDS_FILE_GENERIC_READ);
    LOVEIT(AccessRights[12], GENERIC_ALL, IDS_GENERIC_ALL);
    LOVEIT(AccessRights[13], GENERIC_EXECUTE, IDS_GENERIC_EXECUTE);
    LOVEIT(AccessRights[14], GENERIC_WRITE, IDS_GENERIC_WRITE);
    LOVEIT(AccessRights[15], GENERIC_READ, IDS_GENERIC_READ);
    LOVEIT(AccessRights[16], MAXIMUM_ALLOWED, IDS_MAXIMUM_ALLOWED);
    LOVEIT(AccessRights[17], ACCESS_SYSTEM_SECURITY, IDS_ACCESS_SYSTEM_SECURITY);
    LOVEIT(AccessRights[18], SPECIFIC_RIGHTS_ALL, IDS_SPECIFIC_RIGHTS_ALL);
    LOVEIT(AccessRights[19], STANDARD_RIGHTS_REQUIRED, IDS_STANDARD_RIGHTS_REQUIRED);
    LOVEIT(AccessRights[20], SYNCHRONIZE, IDS_SYNCHRONIZE);
    LOVEIT(AccessRights[21], WRITE_OWNER, IDS_WRITE_OWNER);
    LOVEIT(AccessRights[22], WRITE_DAC, IDS_WRITE_DAC);
    LOVEIT(AccessRights[23], READ_CONTROL, IDS_READ_CONTROL);
    LOVEIT(AccessRights[24], DELETE, IDS_DELETE);
    LOVEIT(AccessRights[25], STANDARD_RIGHTS_ALL, IDS_STANDARD_RIGHTS_ALL);
}

void DoneLovingIt()
{
    intFree(AccessRights);
}



static BOOL
PrintFileDacl(IN LPWSTR FilePath,
              IN LPWSTR FileName,
              IN enum searchtype ST)
{
	GENERIC_MAPPING FileGenericMapping = {0};
    SIZE_T Length;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    DWORD SDSize = 0;
    WCHAR FullFileName[MAX_PATH + 1];
    BOOL Error = FALSE, Ret = FALSE;
    int x = 0, x2 = 0;
    if(ST == File)
    {
        Length = KERNEL32$lstrlenW(FilePath) + KERNEL32$lstrlenW(FileName);
        if (Length > MAX_PATH)
        {
            /* file name too long */
            KERNEL32$SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        }

        KERNEL32$lstrcpynW(FullFileName, FilePath, MAX_PATH);
        KERNEL32$lstrcatW(FullFileName, FileName);
    }else
    {
        KERNEL32$lstrcpynW(FullFileName, FilePath, MAX_PATH);
    }


    /* find out how much memory we need */
    if (!ADVAPI32$GetFileSecurityW(FullFileName,
                         DACL_SECURITY_INFORMATION,
                         NULL,
                         0,
                         &SDSize) &&
        KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return FALSE;
    }

    SecurityDescriptor = (PSECURITY_DESCRIPTOR)intAlloc(SDSize);
    if (SecurityDescriptor != NULL)
    {
        if (ADVAPI32$GetFileSecurityW(FullFileName,
                            DACL_SECURITY_INFORMATION,
                            SecurityDescriptor,
                            SDSize,
                            &SDSize))
        {
            PACL Dacl;
            BOOL DaclPresent;
            BOOL DaclDefaulted;
            if (ADVAPI32$GetSecurityDescriptorDacl(SecurityDescriptor,
                                          &DaclPresent,
                                          &Dacl,
                                          &DaclDefaulted))
            {
                if (Dacl && DaclPresent)
                {
                    PACCESS_ALLOWED_ACE Ace;
                    DWORD AceIndex = 0;

                    /* dump the ACL */
                    while (ADVAPI32$GetAce(Dacl,
                                  AceIndex,
                                  (PVOID*)&Ace))
                    {
                        SID_NAME_USE Use;
                        DWORD NameSize = 0;
                        DWORD DomainSize = 0;
                        LPWSTR Name = NULL;
                        LPWSTR Domain = NULL;
                        LPWSTR SidString = NULL;
                        DWORD IndentAccess = 0;
                        
                        DWORD AccessMask = Ace->Mask;
                        PSID Sid = (PSID)&Ace->SidStart;
//                         /* attempt to translate the SID into a readable string */
                        if (!ADVAPI32$LookupAccountSidW(NULL,
                                              Sid,
                                              Name,
                                              &NameSize,
                                              Domain,
                                              &DomainSize,
                                              &Use))
                        {
                            if (KERNEL32$GetLastError() == ERROR_NONE_MAPPED || NameSize == 0)
                            {
                                goto BuildSidString;
                            }
                            else
                            {
                                if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                                {
                                    Error = TRUE;
                                    break;
                                }

                                Name = (LPWSTR)intAlloc((NameSize + DomainSize) * 2);
                                if (Name == NULL)
                                {
                                    KERNEL32$SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                                    Error = TRUE;
                                    break;
                                }

                                Domain = Name + NameSize;
                                Name[0] = L'\0';
                                if (DomainSize != 0)
                                    Domain[0] = L'\0';
                                if (!ADVAPI32$LookupAccountSidW(NULL,
                                                      Sid,
                                                      Name,
                                                      &NameSize,
                                                      Domain,
                                                      &DomainSize,
                                                      &Use))
                                {
                                    intFree(Name);
                                    Name = NULL;
                                    goto BuildSidString;
                                }
                            }

                        }
                        else
                        {
BuildSidString:
                            if (!ADVAPI32$ConvertSidToStringSidW(Sid,
                                                       &SidString))
                            {
                                Error = TRUE;
                                break;
                            }
                        }

                        /* print the file name or space */
                        internal_printf("%S ", FullFileName);

                        /* attempt to map the SID to a user name */
                        if (AceIndex == 0)
                        {
                            DWORD i = 0;

                            /* overwrite the full file name with spaces so we
                               only print the file name once */
                            while (FullFileName[i] != L'\0')
                                FullFileName[i++] = L' ';
                        }

                        /* print the domain and/or user if possible, or the SID string */
                        if (Name != NULL && Domain != NULL && Domain[0] != L'\0')
                        {
                            internal_printf("%S\\%S:", Domain, Name);
                            IndentAccess = (DWORD)KERNEL32$lstrlenW(Domain) + KERNEL32$lstrlenW(Name);
                        }
                        else
                        {
                            LPWSTR DisplayString = (Name != NULL ? Name : SidString);
                            if(DisplayString)
                            {
                                internal_printf( "%S:", DisplayString);
                                IndentAccess = (DWORD)KERNEL32$lstrlenW(DisplayString);
                            }
                        }

                        /* print the ACE Flags */
                        if (Ace->Header.AceFlags & CONTAINER_INHERIT_ACE)
                        {
							internal_printf("%s", IDS_ABBR_CI);
							IndentAccess += 4;
                            //IndentAccess += ConResPuts(StdOut, IDS_ABBR_CI);
                        }
                        if (Ace->Header.AceFlags & OBJECT_INHERIT_ACE)
                        {
							internal_printf("%s", IDS_ABBR_OI);
							IndentAccess += 4;
                            //IndentAccess += ConResPuts(StdOut, IDS_ABBR_OI);
                        }
                        if (Ace->Header.AceFlags & INHERIT_ONLY_ACE)
                        {
							internal_printf("%s", IDS_ABBR_IO);
							IndentAccess += 4;

                            //IndentAccess += ConResPuts(StdOut, IDS_ABBR_IO);
                        }

                        IndentAccess += 2;
                        /* print the access rights */
                        ADVAPI32$MapGenericMask(&AccessMask,
                                       &FileGenericMapping);
                        if (Ace->Header.AceType & ACCESS_DENIED_ACE_TYPE)
                        {
                            if (AccessMask == FILE_ALL_ACCESS)
                            {
                                internal_printf("%s", IDS_ABBR_NONE);
                            }
                            else
                            {
                                internal_printf("%s", IDS_DENY);
                                goto PrintSpecialAccess;
                            }
                        }
                        else
                        {
                            if (AccessMask == FILE_ALL_ACCESS)
                            {
                                internal_printf("%s", IDS_ABBR_FULL);
                            }
                            else if (!(Ace->Mask & (GENERIC_READ | GENERIC_EXECUTE)) &&
                                     AccessMask == (FILE_GENERIC_READ | FILE_EXECUTE))
                            {
                                internal_printf("%s", IDS_ABBR_READ);
                            }
                            else if (AccessMask == (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_EXECUTE | DELETE))
                            {
                                internal_printf("%s", IDS_ABBR_CHANGE);
                            }
                            else if (AccessMask == FILE_GENERIC_WRITE)
                            {
                                internal_printf("%s", IDS_ABBR_WRITE);
                            }
                            else
                            {
                                internal_printf("%s", IDS_ALLOW);
PrintSpecialAccess:
                                internal_printf("%s", IDS_SPECIAL_ACCESS);
                                /* print the special access rights */
                                x = 26;
                                while (x >= 0)
                                {
                                    if ((Ace->Mask & AccessRights[x].Access) == AccessRights[x].Access)
                                    {
                                        internal_printf("\n%S ", FullFileName);
                                        for (x2 = 0; x2 < IndentAccess; x2++)
                                        {
                                            internal_printf("%s", " ");
                                        }

                                        internal_printf("%s", AccessRights[x].uID);
                                    }
                                    x--;
                                }

                                internal_printf("%s", "\n");
//                             }
                            }
                        }

                        internal_printf("%s", "\n");

                        /* free up all resources */
                        if (Name != NULL)
                        {
                            intFree(Name);
                            Name = NULL;
                        }

                        if (SidString != NULL)
                        {
                            KERNEL32$LocalFree((HLOCAL)SidString);
                            SidString = NULL;
                        }

                        AceIndex++;
                    }
                    if (!Error)
                        Ret = TRUE;
                }
                else
                {
                    KERNEL32$SetLastError(ERROR_NO_SECURITY_ON_OBJECT);
                }
            }
        }
        if(SecurityDescriptor)
        {
		    intFree(SecurityDescriptor);
            SecurityDescriptor = NULL;
        }
    }
    else
    {
        KERNEL32$SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }

    return Ret;
}

static VOID
AddBackslash(LPWSTR FilePath)
{
    INT len = KERNEL32$lstrlenW(FilePath);
    LPWSTR pch = USER32$CharPrevW(FilePath, FilePath + len);
    if (*pch != L'\\')
        KERNEL32$lstrcatW(pch, L"\\");
}

static enum searchtype
GetPathOfFile(LPWSTR FilePath, LPCWSTR pszFiles)
{
    WCHAR FullPath[MAX_PATH];
    LPWSTR pch;
    DWORD attrs;
    //First lets check if we are pointing at a folder

    attrs = KERNEL32$GetFileAttributesW(pszFiles);
    if(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
    {
        KERNEL32$GetFullPathNameW(pszFiles, MAX_PATH, FilePath, NULL); 
        return Folder;
    }
    // if we get here its probably not a folder, lets follow file logic
    KERNEL32$lstrcpynW(FilePath, pszFiles, MAX_PATH);


    pch = MSVCRT$wcsrchr(FilePath, L'\\');
    if (pch != NULL)
    {
        *pch = 0;
        if (!KERNEL32$GetFullPathNameW(FilePath, MAX_PATH, FullPath, NULL))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resolve path: 0x%lx", KERNEL32$GetLastError());
            return Fail;
        }
        KERNEL32$lstrcpynW(FilePath, FullPath, MAX_PATH);

        attrs = KERNEL32$GetFileAttributesW(FilePath);
        if (attrs == 0xFFFFFFFF || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resolve attributes: %ld", ERROR_DIRECTORY);
            return Fail;
        }
    }
    else
        KERNEL32$GetCurrentDirectoryW(MAX_PATH, FilePath);

    AddBackslash(FilePath);
    return File;
}

static BOOL
PrintDaclsOfFiles(LPCWSTR pszFiles)
{
    WCHAR FilePath[MAX_PATH] = {0};
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;
    DWORD LastError;
    enum searchtype ST;
    /*
     * get the file path
     */
    ST = GetPathOfFile(FilePath, pszFiles);
    switch (ST)
    {
        case Fail:
            BeaconPrintf(CALLBACK_ERROR, "Unable to resolve file path");
            return FALSE;
        case Folder:
        {
            if(!PrintFileDacl(FilePath, L"", ST))
            {
                BeaconPrintf(CALLBACK_ERROR, "Unable to list permissions of file %S", pszFiles);
                return FALSE;
            }
            return TRUE;
        }
        case File:
            break;
        default:
            break;
    }

    //again lets see if this is a folder
    
    /*
     * search for the files
     */
    hFind = KERNEL32$FindFirstFileW(pszFiles, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error starting search handle\n");
        return FALSE;
    }

    do
    {
        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        if (!PrintFileDacl(FilePath, FindData.cFileName, ST))
        {
            LastError = KERNEL32$GetLastError();
            if (LastError == ERROR_ACCESS_DENIED)
            {
                BeaconPrintf(CALLBACK_ERROR, "Unable to list permissions of file %S", FindData.cFileName);
            }
            else
            {
				BeaconPrintf(CALLBACK_ERROR, "Unhandled error in listing: 0x%lx", LastError);
                break;
            }
        }
        else
        {
            internal_printf("\n");
        }
    } while(KERNEL32$FindNextFileW(hFind, &FindData));
    LastError = KERNEL32$GetLastError();
    KERNEL32$FindClose(hFind);

    if (LastError != ERROR_NO_MORE_FILES)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to handle all files, received error 0x%lx", LastError);
        return FALSE;
    }

    return TRUE;
}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	const wchar_t * targetpath = NULL;
	BeaconDataParse(&parser, Buffer, Length);
	targetpath = (const wchar_t*) BeaconDataExtract(&parser, NULL);
	if(!bofstart())
	{
		return;
	}
    LovingIt();
	PrintDaclsOfFiles(targetpath);
    DoneLovingIt();
	printoutput(TRUE);
};

#else
int main()
{
    LovingIt();
    PrintDaclsOfFiles(L".");
    PrintDaclsOfFiles(L"*");
    PrintDaclsOfFiles(L"C:\\windows\\system32\\notepad.exe");
    PrintDaclsOfFiles(L"C:\\windows\\system32");
    PrintDaclsOfFiles(L"C:\\asdf");
    PrintDaclsOfFiles(L"C:\\windows\\system32\\*");
    PrintDaclsOfFiles(L"C:\\windows\\system32\\asdf");
    DoneLovingIt();
}
#endif
