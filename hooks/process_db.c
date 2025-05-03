#include "process_db.h"
#include "logger.h"
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "shlwapi.lib")

#define MAX_PROCESS_NAME_LEN 256
#define MAX_PROCESS_RULES 1000

typedef struct
{
    CHAR name[MAX_PROCESS_NAME_LEN];
    BOOL is_whitelisted;
    BOOL is_blacklisted;
} PROCESS_RULE;

static PROCESS_RULE g_process_rules[MAX_PROCESS_RULES];
static DWORD g_rule_count = 0;
static DB_MODE g_db_mode = DB_MODE_MEMORY;
static WCHAR g_storage_path[MAX_PATH] = {0};

// Internal helper functions
static BOOL SaveToRegistry();
static BOOL LoadFromRegistry();
static BOOL SaveToFile();
static BOOL LoadFromFile();
static BOOL AddProcessRule(LPCSTR name, BOOL whitelist, BOOL blacklist);

BOOL InitProcessDatabase(DB_MODE mode, LPCWSTR storage_path)
{
    g_db_mode = mode;

    if (storage_path)
    {
        wcsncpy_s(g_storage_path, MAX_PATH, storage_path, _TRUNCATE);
    }
    else
    {
        // Default paths
        switch (mode)
        {
        case DB_MODE_REGISTRY:
            wcscpy_s(g_storage_path, MAX_PATH, L"SOFTWARE\\AntiRansomware\\ProcessDB");
            break;
        case DB_MODE_FILE:
            wcscpy_s(g_storage_path, MAX_PATH, L"C:\\AntiRansomware\\process_db.dat");
            break;
        default:
            break;
        }
    }

    return LoadProcessDatabase();
}

BOOL LoadProcessDatabase()
{
    // Clear existing rules
    g_rule_count = 0;
    ZeroMemory(g_process_rules, sizeof(g_process_rules));

    switch (g_db_mode)
    {
    case DB_MODE_REGISTRY:
        return LoadFromRegistry();
    case DB_MODE_FILE:
        return LoadFromFile();
    case DB_MODE_MEMORY:
    default:
        // Start with some default safe processes
        WhitelistProcess("explorer.exe");
        WhitelistProcess("svchost.exe");
        WhitelistProcess("csrss.exe");
        return TRUE;
    }
}

BOOL SaveProcessDatabase()
{
    switch (g_db_mode)
    {
    case DB_MODE_REGISTRY:
        return SaveToRegistry();
    case DB_MODE_FILE:
        return SaveToFile();
    case DB_MODE_MEMORY:
    default:
        return TRUE; // No persistence needed
    }
}

BOOL IsProcessWhitelisted(DWORD pid)
{
    CHAR process_name[MAX_PROCESS_NAME_LEN] = {0};

    if (!GetProcessName(pid, process_name, MAX_PROCESS_NAME_LEN))
    {
        return FALSE;
    }

    for (DWORD i = 0; i < g_rule_count; i++)
    {
        if (_stricmp(g_process_rules[i].name, process_name) == 0)
        {
            return g_process_rules[i].is_whitelisted;
        }
    }

    return FALSE;
}

BOOL IsProcessBlacklisted(DWORD pid)
{
    CHAR process_name[MAX_PROCESS_NAME_LEN] = {0};

    if (!GetProcessName(pid, process_name, MAX_PROCESS_NAME_LEN))
    {
        return FALSE;
    }

    // Check against known ransomware patterns
    if (StrStrIA(process_name, "crypt") ||
        StrStrIA(process_name, "lock") ||
        StrStrIA(process_name, "ransom"))
    {
        return TRUE;
    }

    for (DWORD i = 0; i < g_rule_count; i++)
    {
        if (_stricmp(g_process_rules[i].name, process_name) == 0)
        {
            return g_process_rules[i].is_blacklisted;
        }
    }

    return FALSE;
}

BOOL WhitelistProcess(LPCSTR process_name)
{
    return AddProcessRule(process_name, TRUE, FALSE);
}

BOOL BlacklistProcess(LPCSTR process_name)
{
    return AddProcessRule(process_name, FALSE, TRUE);
}

BOOL RemoveProcess(LPCSTR process_name)
{
    for (DWORD i = 0; i < g_rule_count; i++)
    {
        if (_stricmp(g_process_rules[i].name, process_name) == 0)
        {
            // Shift remaining rules down
            for (DWORD j = i; j < g_rule_count - 1; j++)
            {
                memcpy(&g_process_rules[j], &g_process_rules[j + 1], sizeof(PROCESS_RULE));
            }
            g_rule_count--;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL GetProcessName(DWORD pid, LPSTR buffer, DWORD buffer_size)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                strncpy_s(buffer, buffer_size, pe.szExeFile, _TRUNCATE);
                CloseHandle(hSnapshot);
                return TRUE;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return FALSE;
}

// ================ Internal Helpers ================ //

static BOOL AddProcessRule(LPCSTR name, BOOL whitelist, BOOL blacklist)
{
    if (g_rule_count >= MAX_PROCESS_RULES)
    {
        LogToFile("ProcessDB: Maximum rule count reached");
        return FALSE;
    }

    // Check if already exists
    for (DWORD i = 0; i < g_rule_count; i++)
    {
        if (_stricmp(g_process_rules[i].name, name) == 0)
        {
            g_process_rules[i].is_whitelisted = whitelist;
            g_process_rules[i].is_blacklisted = blacklist;
            return TRUE;
        }
    }

    // Add new rule
    strncpy_s(g_process_rules[g_rule_count].name, MAX_PROCESS_NAME_LEN, name, _TRUNCATE);
    g_process_rules[g_rule_count].is_whitelisted = whitelist;
    g_process_rules[g_rule_count].is_blacklisted = blacklist;
    g_rule_count++;

    return TRUE;
}

static BOOL SaveToRegistry()
{
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, g_storage_path, 0, NULL, 0,
                                  KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        LogToFile("ProcessDB: Failed to create registry key (Error %d)", result);
        return FALSE;
    }

    // Save each rule
    for (DWORD i = 0; i < g_rule_count; i++)
    {
        CHAR value_name[64];
        CHAR value_data[MAX_PROCESS_NAME_LEN + 2]; // name + ",W/B"

        // Replace sprintf_s with snprintf
        snprintf(value_name, sizeof(value_name), "Rule%d", i);
        snprintf(value_data, sizeof(value_data), "%s,%c",
                 g_process_rules[i].name,
                 g_process_rules[i].is_whitelisted ? 'W' : 'B');

        result = RegSetValueExA(hKey, value_name, 0, REG_SZ,
                                (const BYTE *)value_data, (DWORD)strlen(value_data) + 1);
        if (result != ERROR_SUCCESS)
        {
            LogToFile("ProcessDB: Failed to save rule %d (Error %d)", i, result);
            RegCloseKey(hKey);
            return FALSE;
        }
    }

    // Save count
    DWORD count = g_rule_count;
    RegSetValueExA(hKey, "Count", 0, REG_DWORD, (const BYTE *)&count, sizeof(count));

    RegCloseKey(hKey);
    LogToFile("ProcessDB: Saved %d rules to registry", g_rule_count);
    return TRUE;
}

static BOOL LoadFromRegistry()
{
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, g_storage_path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        LogToFile("ProcessDB: Registry key not found");
        return FALSE;
    }

    DWORD count = 0;
    DWORD size = sizeof(count);
    if (RegQueryValueExA(hKey, "Count", NULL, NULL, (LPBYTE)&count, &size) != ERROR_SUCCESS)
    {
        count = 0;
    }

    for (DWORD i = 0; i < count; i++)
    {
        CHAR value_name[64];
        CHAR value_data[MAX_PROCESS_NAME_LEN + 2] = {0};
        DWORD data_size = sizeof(value_data);

        // Replace sprintf_s with snprintf
        snprintf(value_name, sizeof(value_name), "Rule%d", i);

        if (RegQueryValueExA(hKey, value_name, NULL, NULL,
                             (LPBYTE)value_data, &data_size) == ERROR_SUCCESS)
        {
            // Format: "process.exe,W" or "process.exe,B"
            CHAR *comma = strchr(value_data, ',');
            if (comma && (comma[1] == 'W' || comma[1] == 'B'))
            {
                *comma = '\0'; // Split string
                AddProcessRule(value_data, comma[1] == 'W', comma[1] == 'B');
            }
        }
    }

    RegCloseKey(hKey);
    LogToFile("ProcessDB: Loaded %d rules from registry", g_rule_count);
    return TRUE;
}

static BOOL SaveToFile()
{
    HANDLE hFile = CreateFileW(g_storage_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogToFile("ProcessDB: Failed to create file (Error %d)", GetLastError());
        return FALSE;
    }

    DWORD bytesWritten;
    WriteFile(hFile, &g_rule_count, sizeof(g_rule_count), &bytesWritten, NULL);

    for (DWORD i = 0; i < g_rule_count; i++)
    {
        WriteFile(hFile, &g_process_rules[i], sizeof(PROCESS_RULE), &bytesWritten, NULL);
    }

    CloseHandle(hFile);
    LogToFile("ProcessDB: Saved %d rules to file", g_rule_count);
    return TRUE;
}

static BOOL LoadFromFile()
{
    HANDLE hFile = CreateFileW(g_storage_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogToFile("ProcessDB: File not found (Error %d)", GetLastError());
        return FALSE;
    }

    DWORD bytesRead;
    DWORD count = 0;
    ReadFile(hFile, &count, sizeof(count), &bytesRead, NULL);

    for (DWORD i = 0; i < count && i < MAX_PROCESS_RULES; i++)
    {
        PROCESS_RULE rule;
        ReadFile(hFile, &rule, sizeof(rule), &bytesRead, NULL);
        AddProcessRule(rule.name, rule.is_whitelisted, rule.is_blacklisted);
    }

    CloseHandle(hFile);
    LogToFile("ProcessDB: Loaded %d rules from file", g_rule_count);
    return TRUE;
}