#include "hook.h"
#include "logger.h"
#include "process_db.h"
#include "minhook/include/MinHook.h"
#include <windows.h>
#include <winternl.h>

// Global variables
static HMODULE g_hModule = NULL;
static BOOL g_initialized = FALSE;
static CRITICAL_SECTION g_cs; // Thread safety
static DB_MODE g_db_mode = DB_MODE_MEMORY;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // 1. Basic initialization
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);

        // 2. Initialize logging system first
        InitLogger();
        LogToFile("=== Anti-Ransomware DLL Loading ===");
        LogToFile("Module Base: 0x%p", hModule);
        // 3. Initialize process database (in-memory mode)
        if (!InitProcessDatabase(DB_MODE_MEMORY, NULL))
        {
            LogToFile("Failed to initialize process database");
            // Non-critical failure
        }

        // 4. Add critical default rules
        EnterCriticalSection(&g_cs);
        WhitelistProcess("explorer.exe");
        WhitelistProcess("svchost.exe");
        WhitelistProcess("winlogon.exe");
        BlacklistProcess("taskdl.exe"); // Common ransomware
        BlacklistProcess("crypt.exe");
        LeaveCriticalSection(&g_cs);

        // 5. Initialize hooks with error recovery
        MH_STATUS mhStatus;
        for (int attempts = 0; attempts < 3; attempts++)
        {
            if ((mhStatus = MH_Initialize()) == MH_OK)
            {
                if (InitializeNtHooks())
                {
                    g_initialized = TRUE;
                    LogToFile("Hooks initialized successfully");
                    break;
                }
            }
            LogToFile("Hook init attempt %d failed: %d", attempts + 1, mhStatus);
            Sleep(100);
        }

        if (!g_initialized)
        {
            LogToFile("CRITICAL: Failed to initialize hooks");
            MessageBoxA(NULL,
                        "Anti-Ransomware protection failed to initialize.\n"
                        "Check C:\\AntiRansomware\\monitor.log for details.",
                        "Security Error",
                        MB_ICONERROR | MB_SYSTEMMODAL);
            return FALSE;
        }

        // 6. Security self-check
        DWORD currentPid = GetCurrentProcessId();
        CHAR processName[MAX_PATH];
        if (GetProcessName(currentPid, processName, MAX_PATH))
        {
            LogToFile("Protection active in %s (PID: %d)", processName, currentPid);

            EnterCriticalSection(&g_cs);
            BOOL isBlacklisted = IsProcessBlacklisted(currentPid);
            LeaveCriticalSection(&g_cs);

            if (isBlacklisted)
            {
                LogToFile("CRITICAL: Loaded into blacklisted process!");
                // Replace NtTerminateProcess(NtCurrentProcess() with standard function
                TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_DENIED);
                return FALSE;
            }
        }
        break;
    }

    case DLL_PROCESS_DETACH:
    {
        if (g_initialized)
        {
            LogToFile("=== DLL Unloading ===");

            EnterCriticalSection(&g_cs);
            // 1. Save detection data if using persistent storage
            if (g_db_mode != DB_MODE_MEMORY)
            {
                SaveProcessDatabase();
            }

            // 2. Cleanup hooks
            CleanupNtHooks();
            LeaveCriticalSection(&g_cs);

            // 3. Final cleanup
            DeleteCriticalSection(&g_cs);
            LogToFile("Protection unloaded cleanly");
        }
        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // Handled by DisableThreadLibraryCalls
        break;
    }
    return TRUE;
}

// Exported control functions
__declspec(dllexport) BOOL WINAPI EnableProtection(BOOL enable)
{
    EnterCriticalSection(&g_cs);
    BOOL result = FALSE;

    if (enable && !g_initialized)
    {
        result = InitializeNtHooks();
        g_initialized = result;
    }
    else if (!enable && g_initialized)
    {
        CleanupNtHooks();
        g_initialized = FALSE;
        result = TRUE;
    }

    LeaveCriticalSection(&g_cs);
    return result;
}

__declspec(dllexport) BOOL WINAPI AddProtectedProcess(LPCSTR processName)
{
    EnterCriticalSection(&g_cs);
    BOOL result = WhitelistProcess(processName);
    LeaveCriticalSection(&g_cs);

    if (result)
    {
        LogToFile("Added to whitelist: %s", processName);
    }
    else
    {
        LogToFile("Failed to whitelist: %s", processName);
    }

    return result;
}

__declspec(dllexport) BOOL WINAPI AddMaliciousProcess(LPCSTR processName)
{
    EnterCriticalSection(&g_cs);
    BOOL result = BlacklistProcess(processName);
    LeaveCriticalSection(&g_cs);

    if (result)
    {
        LogToFile("Added to blacklist: %s", processName);
    }
    else
    {
        LogToFile("Failed to blacklist: %s", processName);
    }

    return result;
}