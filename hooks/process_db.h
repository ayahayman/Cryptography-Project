#pragma once
#include <Windows.h>

// Process database modes
typedef enum {
    DB_MODE_MEMORY = 0,  // In-memory only
    DB_MODE_REGISTRY,     // Persist to registry
    DB_MODE_FILE          // Persist to file
} DB_MODE;

// Initialize the process database
BOOL InitProcessDatabase(DB_MODE mode, LPCWSTR storage_path);

// Load process rules from storage
BOOL LoadProcessDatabase();

// Save process rules to storage
BOOL SaveProcessDatabase();

// Check if process is whitelisted
BOOL IsProcessWhitelisted(DWORD pid);

// Check if process is blacklisted
BOOL IsProcessBlacklisted(DWORD pid);

// Add process to whitelist
BOOL WhitelistProcess(LPCSTR process_name);

// Add process to blacklist
BOOL BlacklistProcess(LPCSTR process_name);

// Remove process from lists
BOOL RemoveProcess(LPCSTR process_name);

// Get process name from PID
BOOL GetProcessName(DWORD pid, LPSTR buffer, DWORD buffer_size);