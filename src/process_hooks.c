// In process_hooks.c
#include <windows.h>
#include <tlhelp32.h>
#include "hook_system.h"

// Callback for new processes
int OnProcessCreate(void* context) {
    ProcessEvent* evt = (ProcessEvent*)context;
    printf("[PROC] Started: %s (PID: %d)\n", evt->name, evt->pid);
    
    if (strcmp(evt->name, "mimikatz.exe") == 0) {
        printf("[!] Credential dumper detected!\n");
        return 100; // Critical risk
    }
    return 0;
}

// Hook process creation via WMI or Toolhelp
void SetupProcessHooks() {
    RegisterHook(HOOK_PROCESS_CREATE, OnProcessCreate, 5);
    
    // Periodically snapshot processes
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        do {
            ProcessEvent evt;
            evt.pid = entry.th32ProcessID;
            strncpy(evt.name, entry.szExeFile, MAX_PATH);
            TriggerHooks(HOOK_PROCESS_CREATE, &evt);
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}