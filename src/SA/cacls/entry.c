#include <windows.h>
#include "bofdefs.h"
#include "defines.h"
#include "base.c"
#include <windef.h>


static char * resolveAccessName(DWORD mask)
{
	if(mask & FILE_WRITE_ATTRIBUTES){return IDS_FILE_WRITE_ATTRIBUTES;}
	else if(mask & FILE_READ_ATTRIBUTES){return IDS_FILE_READ_ATTRIBUTES;}
	else if(mask & FILE_DELETE_CHILD){ return IDS_FILE_DELETE_CHILD;}
	else if(mask & FILE_EXECUTE){return IDS_FILE_EXECUTE;}
	else if(mask & FILE_WRITE_EA){return IDS_FILE_WRITE_EA;}
	else if(mask & FILE_READ_EA){return IDS_FILE_READ_EA;}
	else if(mask & FILE_APPEND_DATA){return IDS_FILE_APPEND_DATA;}
	else if(mask & FILE_WRITE_DATA){return IDS_FILE_WRITE_DATA;}
	else if(mask & FILE_READ_DATA){return IDS_FILE_READ_DATA;}
	else if(mask & FILE_GENERIC_EXECUTE){return IDS_FILE_GENERIC_EXECUTE;}
	else if(mask & FILE_GENERIC_WRITE){return IDS_FILE_GENERIC_WRITE;}
	else if(mask & FILE_GENERIC_READ){return IDS_FILE_GENERIC_READ;}
	else if(mask & GENERIC_ALL){return IDS_GENERIC_ALL;}
	else if(mask & GENERIC_EXECUTE){return IDS_GENERIC_EXECUTE;}
	else if(mask & GENERIC_WRITE){return IDS_GENERIC_WRITE;}
	else if(mask & GENERIC_READ){return IDS_GENERIC_READ;}
	else if(mask & MAXIMUM_ALLOWED){return IDS_MAXIMUM_ALLOWED;}
	else if(mask & ACCESS_SYSTEM_SECURITY){return IDS_ACCESS_SYSTEM_SECURITY;}
	else if(mask & SPECIFIC_RIGHTS_ALL){return IDS_SPECIFIC_RIGHTS_ALL;}
	else if(mask & STANDARD_RIGHTS_REQUIRED){return IDS_STANDARD_RIGHTS_REQUIRED;}
	else if(mask & SYNCHRONIZE){return IDS_SYNCHRONIZE;}
	else if(mask & WRITE_OWNER){return IDS_WRITE_OWNER;}
	else if(mask & WRITE_DAC){return IDS_WRITE_DAC;}
	else if(mask & READ_CONTROL){return IDS_READ_CONTROL;}
	else if(mask & DELETE){return IDS_DELETE;}
	else if(mask & STANDARD_RIGHTS_ALL){return IDS_STANDARD_RIGHTS_ALL;}
	else{return "UNKNOWN||UNHANDLED";}

}

static BOOL
PrintFileDacl(IN LPWSTR FilePath,
              IN LPWSTR FileName)
{
	GENERIC_MAPPING FileGenericMapping = {0};
    SIZE_T Length;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    DWORD SDSize = 0;
    WCHAR FullFileName[MAX_PATH + 1];
    BOOL Error = FALSE, Ret = FALSE;

    Length = KERNEL32$lstrlenW(FilePath) + KERNEL32$lstrlenW(FileName);
    if (Length > MAX_PATH)
    {
        /* file name too long */
        KERNEL32$SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    KERNEL32$lstrcpynW(FullFileName, FilePath, MAX_PATH);
    KERNEL32$lstrcatW(FullFileName, FileName);

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
                if (DaclPresent)
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
                        DWORD IndentAccess;
                        DWORD AccessMask = Ace->Mask;
                        PSID Sid = (PSID)&Ace->SidStart;

                        /* attempt to translate the SID into a readable string */
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
                        if (Name != NULL && Domain[0] != L'\0')
                        {
                            internal_printf("%S\\%S:", Domain, Name);
                            IndentAccess = (DWORD)KERNEL32$lstrlenW(Domain) + KERNEL32$lstrlenW(Name);
                        }
                        else
                        {
                            LPWSTR DisplayString = (Name != NULL ? Name : SidString);

                            internal_printf( "%S:", DisplayString);
                            IndentAccess = (DWORD)KERNEL32$lstrlenW(DisplayString);
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
                                DWORD x, x2;
                                static const struct
                                {
                                    DWORD Access;
                                    const char * uID;
                                }
                                AccessRights[] =
                                {
                                    {FILE_WRITE_ATTRIBUTES, IDS_FILE_WRITE_ATTRIBUTES},
                                    {FILE_READ_ATTRIBUTES, IDS_FILE_READ_ATTRIBUTES},
                                    {FILE_DELETE_CHILD, IDS_FILE_DELETE_CHILD},
                                    {FILE_EXECUTE, IDS_FILE_EXECUTE},
                                    {FILE_WRITE_EA, IDS_FILE_WRITE_EA},
                                    {FILE_READ_EA, IDS_FILE_READ_EA},
                                    {FILE_APPEND_DATA, IDS_FILE_APPEND_DATA},
                                    {FILE_WRITE_DATA, IDS_FILE_WRITE_DATA},
                                    {FILE_READ_DATA, IDS_FILE_READ_DATA},
                                    {FILE_GENERIC_EXECUTE, IDS_FILE_GENERIC_EXECUTE},
                                    {FILE_GENERIC_WRITE, IDS_FILE_GENERIC_WRITE},
                                    {FILE_GENERIC_READ, IDS_FILE_GENERIC_READ},
                                    {GENERIC_ALL, IDS_GENERIC_ALL},
                                    {GENERIC_EXECUTE, IDS_GENERIC_EXECUTE},
                                    {GENERIC_WRITE, IDS_GENERIC_WRITE},
                                    {GENERIC_READ, IDS_GENERIC_READ},
                                    {MAXIMUM_ALLOWED, IDS_MAXIMUM_ALLOWED},
                                    {ACCESS_SYSTEM_SECURITY, IDS_ACCESS_SYSTEM_SECURITY},
                                    {SPECIFIC_RIGHTS_ALL, IDS_SPECIFIC_RIGHTS_ALL},
                                    {STANDARD_RIGHTS_REQUIRED, IDS_STANDARD_RIGHTS_REQUIRED},
                                    {SYNCHRONIZE, IDS_SYNCHRONIZE},
                                    {WRITE_OWNER, IDS_WRITE_OWNER},
                                    {WRITE_DAC, IDS_WRITE_DAC},
                                    {READ_CONTROL, IDS_READ_CONTROL},
                                    {DELETE, IDS_DELETE},
                                    {STANDARD_RIGHTS_ALL, IDS_STANDARD_RIGHTS_ALL},
                                };

                                internal_printf("%s", IDS_ALLOW);

PrintSpecialAccess:
                                internal_printf("%s", IDS_SPECIAL_ACCESS);

                                /* print the special access rights */
                                x = ARRAYSIZE(AccessRights);
                                while (x-- != 0)
                                {
                                    if ((Ace->Mask & AccessRights[x].Access) == AccessRights[x].Access)
                                    {
                                        internal_printf("\n%S ", FullFileName);
                                        for (x2 = 0; x2 < IndentAccess; x2++)
                                        {
                                            internal_printf("%s", L" ");
                                        }

                                        internal_printf("%s", AccessRights[x].uID);
                                    }
                                }

                                internal_printf("%s", L"\n");
                            }
                        }

                        internal_printf("%s", L"\n");

                        /* free up all resources */
                        if (Name != NULL)
                        {
                            intFree(Name);
                        }

                        if (SidString != NULL)
                        {
                            KERNEL32$LocalFree((HLOCAL)SidString);
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

		intFree(SecurityDescriptor);
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

static BOOL
GetPathOfFile(LPWSTR FilePath, LPCWSTR pszFiles)
{
    WCHAR FullPath[MAX_PATH];
    LPWSTR pch;
    DWORD attrs;

    KERNEL32$lstrcpynW(FilePath, pszFiles, MAX_PATH);
    pch = MSVCRT$wcsrchr(FilePath, L'\\');
    if (pch != NULL)
    {
        *pch = 0;
        if (!KERNEL32$GetFullPathNameW(FilePath, MAX_PATH, FullPath, NULL))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resolve path: 0x%x", KERNEL32$GetLastError());
            return FALSE;
        }
        KERNEL32$lstrcpynW(FilePath, FullPath, MAX_PATH);

        attrs = KERNEL32$GetFileAttributesW(FilePath);
        if (attrs == 0xFFFFFFFF || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to resolve attributes: %u", ERROR_DIRECTORY);
            return FALSE;
        }
    }
    else
        KERNEL32$GetCurrentDirectoryW(MAX_PATH, FilePath);

    AddBackslash(FilePath);
    return TRUE;
}

static BOOL
PrintDaclsOfFiles(LPCWSTR pszFiles)
{
    WCHAR FilePath[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;
    DWORD LastError;

    /*
     * get the file path
     */
    if (!GetPathOfFile(FilePath, pszFiles))
        return FALSE;

    /*
     * search for the files
     */
    hFind = KERNEL32$FindFirstFileW(pszFiles, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do
    {
        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        if (!PrintFileDacl(FilePath, FindData.cFileName))
        {
            LastError = KERNEL32$GetLastError();
            if (LastError == ERROR_ACCESS_DENIED)
            {
                BeaconPrintf(CALLBACK_ERROR, "Unable to list permissions of file %S", FindData.cFileName);
                // if (!OptionC)
                // {
                //     FindClose(hFind);
                //     return FALSE;
                // }
            }
            else
            {
				BeaconPrintf(CALLBACK_ERROR, "Unhandled error in listing: 0x%x", LastError);
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
        BeaconPrintf(CALLBACK_ERROR, "Unable to handle all files, received error 0x%x", LastError);
        return FALSE;
    }

    return TRUE;
}

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	const wchar_t * targetpath = NULL;
	BeaconDataParse(&parser, Buffer, Length);
	targetpath = (const wchar_t*) BeaconDataExtract(&parser, NULL);
	//const BOOL mode = MSVCRT$wcsrchr(targetpath, L'*') ? 1 : 0; //1 = recursive, 0 = single file or folder
	if(!bofstart())
	{
		return;
	}
	PrintDaclsOfFiles(targetpath);
	printoutput(TRUE);
	bofstop();
};
