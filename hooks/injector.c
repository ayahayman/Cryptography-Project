#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("Anti-Ransomware DLL Injector\n");
        printf("Usage: injector.exe <PID> <DLL_PATH>\n");
        printf("Example: injector.exe 1234 C:\\AntiRansomware\\antiransom.dll\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    if (pid == 0)
    {
        printf("Error: Invalid process ID\n");
        return 1;
    }

    // Validate DLL path
    if (GetFileAttributesA(argv[2]) == INVALID_FILE_ATTRIBUTES)
    {
        printf("Error: DLL file '%s' not found\n", argv[2]);
        return 1;
    }

    // Open target process
    printf("Attempting to inject into process ID: %d\n", pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        printf("Error: Failed to open process (error code: %d)\n", GetLastError());
        printf("       You might need to run this program as Administrator\n");
        return 1;
    }

    // Allocate memory for DLL path
    size_t dll_path_size = strlen(argv[2]) + 1;
    printf("Allocating %zu bytes for DLL path\n", dll_path_size);

    LPVOID pMem = VirtualAllocEx(hProcess, NULL, dll_path_size,
                                 MEM_COMMIT, PAGE_READWRITE);
    if (!pMem)
    {
        printf("Error: Failed to allocate memory in target process (error code: %d)\n",
               GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write DLL path to process memory
    printf("Writing DLL path to process memory\n");
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pMem, argv[2], dll_path_size, &bytesWritten))
    {
        printf("Error: Failed to write to process memory (error code: %d)\n",
               GetLastError());
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        printf("Error: Failed to get kernel32.dll handle\n");
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    LPVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary)
    {
        printf("Error: Failed to get LoadLibraryA address\n");
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create remote thread to load DLL
    printf("Creating remote thread to load DLL\n");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibrary, pMem, 0, NULL);

    if (!hThread)
    {
        printf("Error: Failed to create remote thread (error code: %d)\n",
               GetLastError());
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for thread to finish
    printf("Waiting for injection to complete...\n");
    DWORD result = WaitForSingleObject(hThread, 10000); // 10 second timeout

    if (result == WAIT_TIMEOUT)
    {
        printf("Warning: Injection timed out but may still succeed\n");
    }
    else if (result == WAIT_OBJECT_0)
    {
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        printf("Injection %s! (Thread exit code: 0x%08X)\n",
               exitCode ? "succeeded" : "failed", exitCode);
    }
    else
    {
        printf("Error: Wait failed (error code: %d)\n", GetLastError());
    }

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("Injection process completed\n");
    return (result == WAIT_OBJECT_0) ? 0 : 1;
}