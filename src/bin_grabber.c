#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_PATH_LEN 260
#define HASH_SIZE 65
#define BUFFER_SIZE 32768
#define MAX_ERROR_MSG 256

// Error handling codes
typedef enum {
    SUCCESS = 0,
    ERROR_FILE_OPEN,
    ERROR_CRYPTO_INIT,
    ERROR_HASH_COMPUTE,
    ERROR_MEMORY_ALLOC,
    ERROR_DIR_CREATE,
    ERROR_PROCESS_SNAPSHOT,
    ERROR_MODULE_SNAPSHOT,
    ERROR_PROCESS_INFO
} ErrorCode;

// Structure to store hash values in a linked list
typedef struct HashNode {
    char hash[HASH_SIZE];
    struct HashNode* next;
} HashNode;

// Structure to hold program configuration
typedef struct {
    const char* outputDir;
    FILE* logFile;
    HashNode* hashCache;
} ProgramConfig;

// Function to get timestamp for logging
static void get_timestamp(char* buffer, size_t bufferSize) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buffer, bufferSize, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Logging function
static void log_message(FILE* logFile, const char* level, const char* message, const char* detail) {
    if (!logFile) return;

    char timestamp[20];
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(logFile, "[%s] %s: %s %s\n", timestamp, level, message, detail);
    fflush(logFile);
}

// Check if directory is valid
static bool is_valid_directory(const char* path) {
    if (!path) return false;
    
    struct stat st;
    if (stat(path, &st) == 0) {
        return (st.st_mode & S_IFDIR) != 0;
    }
    return false;
}

// Create output directory if it doesn't exist
static bool create_output_directory(const char* path, FILE* logFile) {
    if (is_valid_directory(path)) return true;

    if (!CreateDirectory(path, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            char errorMsg[MAX_ERROR_MSG];
            snprintf(errorMsg, sizeof(errorMsg), "Failed to create directory (Error: %lu)", error);
            log_message(logFile, "ERROR", errorMsg, path);
            return false;
        }
    }
    return true;
}

// Initialize cryptography providers
static ErrorCode initialize_crypto(HCRYPTPROV* hProv, HCRYPTHASH* hHash) {
    if (!CryptAcquireContext(hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return ERROR_CRYPTO_INIT;
    }

    if (!CryptCreateHash(*hProv, CALG_SHA_256, 0, 0, hHash)) {
        CryptReleaseContext(*hProv, 0);
        return ERROR_CRYPTO_INIT;
    }

    return SUCCESS;
}

// Clean up hash cache
static void cleanup_hash_cache(HashNode* cache) {
    while (cache) {
        HashNode* next = cache->next;
        free(cache);
        cache = next;
    }
}

// Check if hash exists in cache
static bool hash_exists(HashNode* cache, const char* hash) {
    HashNode* current = cache;
    while (current) {
        if (strcmp(current->hash, hash) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

// Add hash to cache
static ErrorCode add_hash_to_cache(HashNode** cache, const char* hash) {
    HashNode* new_node = (HashNode*)malloc(sizeof(HashNode));
    if (!new_node) return ERROR_MEMORY_ALLOC;

    strncpy(new_node->hash, hash, HASH_SIZE - 1);
    new_node->hash[HASH_SIZE - 1] = '\0';
    new_node->next = *cache;
    *cache = new_node;

    return SUCCESS;
}

// Get process creation time
static BOOL GetProcessCreationTime(DWORD processId, SYSTEMTIME* creationTime) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return FALSE;
    }

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    BOOL result = GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser);
    CloseHandle(hProcess);

    if (!result) {
        return FALSE;
    }

    FILETIME localFtCreation;
    FileTimeToLocalFileTime(&ftCreation, &localFtCreation);
    FileTimeToSystemTime(&localFtCreation, creationTime);
    
    return TRUE;
}

// Format system time to string
static void FormatSystemTime(const SYSTEMTIME* st, char* buffer, size_t bufferSize) {
    snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
             st->wYear, st->wMonth, st->wDay,
             st->wHour, st->wMinute, st->wSecond);
}

// Compute file hash
static ErrorCode compute_file_hash(const char* path, char outputBuffer[HASH_SIZE], ProgramConfig* config) {
    HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                            FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        log_message(config->logFile, "ERROR", "Failed to open file for hashing", path);
        return ERROR_FILE_OPEN;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    ErrorCode result = initialize_crypto(&hProv, &hHash);
    
    if (result != SUCCESS) {
        CloseHandle(hFile);
        return result;
    }

    BYTE buffer[BUFFER_SIZE];
    DWORD bytesRead;
    BOOL readSuccess = TRUE;
    
    while ((readSuccess = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return ERROR_HASH_COMPUTE;
        }
    }

    if (!readSuccess) {
        log_message(config->logFile, "ERROR", "Failed to read file during hashing", path);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return ERROR_HASH_COMPUTE;
    }

    BYTE hash[32];
    DWORD hashLen = sizeof(hash);
    
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return ERROR_HASH_COMPUTE;
    }

    for (DWORD i = 0; i < hashLen; i++) {
        sprintf(&outputBuffer[i * 2], "%02x", hash[i]);
    }
    outputBuffer[HASH_SIZE - 1] = '\0';

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return SUCCESS;
}

// Process a single binary
static ErrorCode process_single_binary(const char* filepath, const char* outputDir, 
                                     char* hash_output, ProgramConfig* config) {
    ErrorCode result = compute_file_hash(filepath, hash_output, config);
    if (result != SUCCESS) {
        return result;
    }

    if (!hash_exists(config->hashCache, hash_output)) {
        char destPath[MAX_PATH_LEN];
        snprintf(destPath, MAX_PATH_LEN, "%s\\%s", outputDir, hash_output);

        if (!CopyFile(filepath, destPath, FALSE)) {
            log_message(config->logFile, "ERROR", "Failed to copy file", filepath);
            return ERROR_FILE_OPEN;
        }

        result = add_hash_to_cache(&config->hashCache, hash_output);
        if (result != SUCCESS) {
            return result;
        }
    }

    return SUCCESS;
}

// Initialize program configuration
static ProgramConfig* init_config(const char* outputDir) {
    ProgramConfig* config = (ProgramConfig*)malloc(sizeof(ProgramConfig));
    if (!config) return NULL;

    config->outputDir = outputDir;
    config->hashCache = NULL;
    
    char logPath[MAX_PATH_LEN];
    snprintf(logPath, MAX_PATH_LEN, "%s\\collection.log", outputDir);
    config->logFile = fopen(logPath, "a");
    
    return config;
}

// Cleanup program configuration
static void cleanup_config(ProgramConfig* config) {
    if (!config) return;
    
    cleanup_hash_cache(config->hashCache);
    if (config->logFile) fclose(config->logFile);
    free(config);
}

// Main process collection function
static ErrorCode collect_process_binaries(ProgramConfig* config) {
    if (!config || !is_valid_directory(config->outputDir)) {
        return ERROR_DIR_CREATE;
    }

    char csvPath[MAX_PATH_LEN];
    snprintf(csvPath, MAX_PATH_LEN, "%s\\processes.csv", config->outputDir);
    
    FILE* csvFile = fopen(csvPath, "w");
    if (!csvFile) {
        log_message(config->logFile, "ERROR", "Failed to create CSV file", csvPath);
        return ERROR_FILE_OPEN;
    }

    fprintf(csvFile, "ProcessCreationTime,PID,ProcessName,OriginalPath,SHA256,CollectionStatus\n");

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fclose(csvFile);
        return ERROR_PROCESS_SNAPSHOT;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 
                                                        pe32.th32ProcessID);
            if (hModuleSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 me32;
                me32.dwSize = sizeof(MODULEENTRY32);

                if (Module32First(hModuleSnap, &me32)) {
                    char hash[HASH_SIZE] = {0};
                    char timestamp[20] = {0};
                    
                    // Get process creation time
                    SYSTEMTIME creationTime;
                    if (GetProcessCreationTime(pe32.th32ProcessID, &creationTime)) {
                        FormatSystemTime(&creationTime, timestamp, sizeof(timestamp));
                    } else {
                        strcpy(timestamp, "UNKNOWN");
                        log_message(config->logFile, "WARNING", 
                                  "Could not get creation time for process", pe32.szExeFile);
                    }

                    ErrorCode result = process_single_binary(me32.szExePath, config->outputDir, 
                                                          hash, config);
                    
                    fprintf(csvFile, "%s,%lu,%s,%s,%s,%s\n",
                            timestamp,
                            pe32.th32ProcessID,
                            pe32.szExeFile,
                            me32.szExePath,
                            hash,
                            (result == SUCCESS) ? "SUCCESS" : "FAILED");
                }
                CloseHandle(hModuleSnap);
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    fclose(csvFile);
    return SUCCESS;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <output_directory>\n", argv[0]);
        return 1;
    }

    // Initialize configuration
    ProgramConfig* config = init_config(argv[1]);
    if (!config) {
        fprintf(stderr, "Failed to initialize program configuration\n");
        return 1;
    }

    // Create output directory if it doesn't exist
    if (!create_output_directory(config->outputDir, config->logFile)) {
        cleanup_config(config);
        return 1;
    }

    // Collect process binaries
    ErrorCode result = collect_process_binaries(config);
    if (result != SUCCESS) {
        log_message(config->logFile, "ERROR", "Process collection failed", "");
    }

    // Cleanup
    cleanup_config(config);
    return (result == SUCCESS) ? 0 : 1;
}
