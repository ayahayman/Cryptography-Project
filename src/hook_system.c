#include "hook_system.h"
#include <windows.h>

HookManager g_hookManager;
HANDLE g_hEventThread = NULL;
BOOL g_bRunning = FALSE;

void InitializeHookSystem() {
    memset(&g_hookManager, 0, sizeof(HookManager));
    InitializeCriticalSection(&g_hookManager.lock);
    
    // Start event processing thread
    g_bRunning = TRUE;
    g_hEventThread = CreateThread(
        NULL, 
        0, 
        EventProcessingThread, 
        NULL, 
        0, 
        NULL
    );
}

void ShutdownHookSystem() {
    g_bRunning = FALSE;
    WaitForSingleObject(g_hEventThread, INFINITE);
    
    // Clean up all hooks
    EnterCriticalSection(&g_hookManager.lock);
    for (int i = 0; i < HookTypeCount; i++) {
        Hook* current = g_hookManager.hooks[i];
        while (current != NULL) {
            Hook* next = current->next;
            free(current);
            current = next;
        }
    }
    LeaveCriticalSection(&g_hookManager.lock);
    
    DeleteCriticalSection(&g_hookManager.lock);
}

// [Rest of the implementations from previous examples...]