#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <sys/stat.h>
#include <string.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_PATH_LEN 260
#define HASH_SIZE 65

typedef struct HashNode {
    char hash[HASH_SIZE];
    struct HashNode *next;
} HashNode;

HashNode *hash_cache = NULL;

void sha256_hash_string(unsigned char hash[32], char outputBuffer[HASH_SIZE]) {
    int i;
    for (i = 0; i < 32; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

void get_sha256(const char *path, char outputBuffer[HASH_SIZE]) {
    HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[32768];
    DWORD bytesRead = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return;
        }
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        sha256_hash_string(hash, outputBuffer);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
}

void copy_file(const char *src, const char *dest) {
    CopyFile(src, dest, FALSE);
}

int hash_exists(const char *hash) {
    HashNode *current = hash_cache;
    while (current != NULL) {
        if (strcmp(current->hash, hash) == 0) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

void add_hash_to_cache(const char *hash) {
    HashNode *new_node = (HashNode *)malloc(sizeof(HashNode));
    strcpy(new_node->hash, hash);
    new_node->next = hash_cache;
    hash_cache = new_node;
}

void collect_process_binaries(const char *outputDir) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    FILE *csvFile;
    char csvPath[MAX_PATH_LEN];
    char hash[HASH_SIZE];

    // Create the output directory if it doesn't exist
    if (!file_exists(outputDir)) {
        if (!CreateDirectory(outputDir, NULL)) {
            printf("Failed to create directory: %s\n", outputDir);
            return;
        }
    }

    snprintf(csvPath, MAX_PATH_LEN, "%s\\processes.csv", outputDir);

    csvFile = fopen(csvPath, "w");
    if (!csvFile) return;

    fprintf(csvFile, "PID,Original File Path,SHA-256\n");

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fclose(csvFile);
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        fclose(csvFile);
        return;
    }

    do {
        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        MODULEENTRY32 me32;
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
        if (hModuleSnap == INVALID_HANDLE_VALUE) continue;

        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hModuleSnap, &me32)) {
            char destPath[MAX_PATH_LEN];
            get_sha256(me32.szExePath, hash);
            snprintf(destPath, MAX_PATH_LEN, "%s\\%s.exe", outputDir, hash);

            if (!hash_exists(hash)) {
                copy_file(me32.szExePath, destPath);
                add_hash_to_cache(hash);
            }

            fprintf(csvFile, "%lu,%s,%s\n", pe32.th32ProcessID, me32.szExePath, hash);
        }
        CloseHandle(hModuleSnap);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    fclose(csvFile);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <output_directory>\n", argv[0]);
        return 1;
    }

    collect_process_binaries(argv[1]);
    return 0;
}