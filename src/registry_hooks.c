// In registry_hooks.c
#include <windows.h>

int OnRegistryChange(void* context) {
    RegistryEvent* evt = (RegistryEvent*)context;
    printf("[REG] Modified: %s\\%s\n", evt->hive, evt->key);
    return 5;
}

void MonitorRegistryKey(HKEY hive, const char* subkey) {
    HKEY hKey;
    RegOpenKeyExA(hive, subkey, 0, KEY_NOTIFY, &hKey);
    
    while (1) {
        if (RegNotifyChangeKeyValue(
            hKey,
            TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
            NULL,
            FALSE
        ) == ERROR_SUCCESS) {
            RegistryEvent evt;
            evt.hive = "HKLM";
            strcpy(evt.key, subkey);
            TriggerHooks(HOOK_REGISTRY_CHANGE, &evt);
        }
        Sleep(1000);
    }
}