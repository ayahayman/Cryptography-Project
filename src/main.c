#include "hook_system.h"
#include "file_hooks.h"
#include "process_hooks.h"

int main() {
    // Initialize system
    InitializeHookSystem();
    SetupFileHooks();
    SetupProcessHooks();
    
    printf("Behavioral Monitor Running...\n");
    
    // Main loop
    while (1) {
        // In a real implementation, this would wait for events
        // For demo, we'll just sleep
        Sleep(1000);
        
        // Periodic checks could go here
        CheckSystemState();
    }
    
    // Cleanup
    ShutdownHookSystem();
    return 0;
}