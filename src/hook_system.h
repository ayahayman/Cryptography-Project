#ifndef HOOK_SYSTEM_H
#define HOOK_SYSTEM_H

#include "common.h"
#include "events.h"

typedef int (*HookCallback)(void* context);

typedef struct Hook {
    HookType type;
    HookCallback callback;
    int priority;
    struct Hook* next;
} Hook;

typedef struct {
    Hook* hooks[HookTypeCount]; // Array of linked lists
    CRITICAL_SECTION lock;
} HookManager;

// Initialization
void InitializeHookSystem();
void ShutdownHookSystem();

// Registration
void RegisterHook(HookType type, HookCallback callback, int priority);
void UnregisterHook(HookType type, HookCallback callback);

// Execution
int TriggerHooks(HookType type, void* context);

// Thread management
DWORD WINAPI EventProcessingThread(LPVOID lpParam);

#endif // HOOK_SYSTEM_H