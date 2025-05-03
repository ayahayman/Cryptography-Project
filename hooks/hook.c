#include "hook.h"
#include "logger.h"
#include "minhook/include/MinHook.h"
#include <stdio.h>
#include <math.h> // For log2()

// Initialize original function pointers
NtCreateFile_t OriginalNtCreateFile = NULL;
NtOpenFile_t OriginalNtOpenFile = NULL;
NtReadFile_t OriginalNtReadFile = NULL;
NtWriteFile_t OriginalNtWriteFile = NULL;
NtDeleteFile_t OriginalNtDeleteFile = NULL;
NtQueryDirectoryFile_t OriginalNtQueryDirectoryFile = NULL;
NtCreateProcess_t OriginalNtCreateProcess = NULL;
NtTerminateProcess_t OriginalNtTerminateProcess = NULL;
NtOpenProcess_t OriginalNtOpenProcess = NULL;
NtCreateThread_t OriginalNtCreateThread = NULL;
NtAllocateVirtualMemory_t OriginalNtAllocateVirtualMemory = NULL;
NtProtectVirtualMemory_t OriginalNtProtectVirtualMemory = NULL;
NtCreateSection_t OriginalNtCreateSection = NULL;
NtMapViewOfSection_t OriginalNtMapViewOfSection = NULL;
NtQuerySystemInformation_t OriginalNtQuerySystemInformation = NULL;
NtCreateKey_t OriginalNtCreateKey = NULL;
NtOpenKey_t OriginalNtOpenKey = NULL;
NtSetValueKey_t OriginalNtSetValueKey = NULL;
NtQueryValueKey_t OriginalNtQueryValueKey = NULL;
NtDeviceIoControlFile_t OriginalNtDeviceIoControlFile = NULL;
NtSetInformationFile_t OriginalNtSetInformationFile = NULL;

// ================= Ransomware Detection Helpers ================= //

static BOOL IsHighEntropy(PVOID buffer, DWORD size)
{
    if (!buffer || size < 16)
        return FALSE;

    double entropy = 0.0;
    BYTE *data = (BYTE *)buffer;
    int freq[256] = {0};

    for (DWORD i = 0; i < size; i++)
        freq[data[i]]++;

    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy > 7.5;
}

static BOOL IsRansomwareExtension(LPCWSTR filename)
{
    const wchar_t *bad_exts[] = {
        L".encrypted", L".locked", L".crypt",
        L".ransom", L".crypto", NULL};

    for (int i = 0; bad_exts[i]; i++)
    {
        if (wcsstr(filename, bad_exts[i]))
        {
            return TRUE;
        }
    }
    return FALSE;
}

// ================= Hook Implementations ================= //

NTSTATUS NTAPI HookedNtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    // Ransom note detection
    if (ObjectAttributes && ObjectAttributes->ObjectName)
    {
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"README_") ||
            wcsstr(ObjectAttributes->ObjectName->Buffer, L"_DECRYPT_"))
        {
            CHAR msg[256];
            snprintf(msg, sizeof(msg),
                     "Ransom note created: %wZ",
                     ObjectAttributes->ObjectName);
            TriggerAlert(ALERT_CRITICAL, "Ransomware", msg);
        }
    }

    return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
                                CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI HookedNtWriteFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    // Mass write detection
    if (Length > 1024 * 1024)
    {
        CHAR filename[MAX_PATH];
        if (GetFinalPathNameByHandleA(FileHandle, filename, MAX_PATH, FILE_NAME_NORMALIZED))
        {
            CHAR msg[256];
            snprintf(msg, sizeof(msg),
                     "Massive write (%lu bytes) to %s",
                     Length, filename);
            TriggerAlert(ALERT_HIGH, "Ransomware", msg);
        }
    }

    // Encryption pattern detection
    if (Length >= 512 && IsHighEntropy(Buffer, (DWORD)min(Length, 4096)))
    {
        TriggerAlert(ALERT_CRITICAL, "Ransomware",
                     "High entropy data detected in file write");
    }

    return OriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
                               IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI HookedNtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
    // Extension change detection
    if (FileInformationClass == FileRenameInformation)
    {
        PFILE_RENAME_INFO renameInfo = (PFILE_RENAME_INFO)FileInformation;
        if (IsRansomwareExtension(renameInfo->FileName))
        {
            CHAR old_name[MAX_PATH];
            if (GetFinalPathNameByHandleA(FileHandle, old_name, MAX_PATH, FILE_NAME_NORMALIZED))
            {
                CHAR msg[512];
                snprintf(msg, sizeof(msg),
                         "Suspicious rename: %s -> %ls",
                         old_name, renameInfo->FileName);
                TriggerAlert(ALERT_CRITICAL, "Ransomware", msg);
            }
        }
    }

    return OriginalNtSetInformationFile(FileHandle, IoStatusBlock,
                                        FileInformation, Length, FileInformationClass);
}

NTSTATUS NTAPI HookedNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
    // Shadow copy deletion detection
    if (ObjectAttributes && ObjectAttributes->ObjectName)
    {
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\VolumeShadowCopy"))
        {
            TriggerAlert(ALERT_CRITICAL, "Ransomware",
                         "Attempted Volume Shadow Copy deletion");
            return STATUS_ACCESS_DENIED; // Block the operation
        }
    }

    return OriginalNtDeleteFile(ObjectAttributes);
}

NTSTATUS NTAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
    printf("[NtQueryDirectoryFile] Handle: 0x%p\n", FileHandle);
    return OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                        IoStatusBlock, FileInformation, Length, FileInformationClass,
                                        ReturnSingleEntry, FileName, RestartScan);
}

// ================= Process/Thread Hooks ================= //

NTSTATUS NTAPI HookedNtCreateProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess,
    BOOLEAN InheritObjectTable, HANDLE SectionHandle,
    HANDLE DebugPort, HANDLE ExceptionPort)
{
    DWORD parentPid = ParentProcess ? GetProcessId(ParentProcess) : 0;
    printf("[NtCreateProcess] Parent PID: %lu\n", parentPid);
    return OriginalNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes,
                                   ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}

NTSTATUS NTAPI HookedNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    printf("[NtTerminateProcess] Handle: 0x%p, Status: 0x%08X\n", ProcessHandle, ExitStatus);
    return OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
}

NTSTATUS NTAPI HookedNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    if (ClientId)
    {
        printf("[NtOpenProcess] PID: %lu\n", (DWORD)ClientId->UniqueProcess);
    }
    return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI HookedNtCreateThread(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PCLIENT_ID ClientId, PCONTEXT ThreadContext,
    PVOID InitialTeb, BOOLEAN CreateSuspended)
{
    printf("[NtCreateThread] Target PID: %lu\n", GetProcessId(ProcessHandle));
    return OriginalNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes,
                                  ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

// ================= Memory Hooks ================= //

NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect)
{
    printf("[NtAllocateVirtualMemory] Process: 0x%p, Size: %zu\n",
           ProcessHandle, *RegionSize);
    return OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress,
                                           ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect,
    PULONG OldProtect)
{
    printf("[NtProtectVirtualMemory] Addr: 0x%p, NewProtect: 0x%08X\n",
           *BaseAddress, NewProtect);
    return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress,
                                          RegionSize, NewProtect, OldProtect);
}

NTSTATUS NTAPI HookedNtCreateSection(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle)
{
    printf("[NtCreateSection] FileHandle: 0x%p\n", FileHandle);
    return OriginalNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                   MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

NTSTATUS NTAPI HookedNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID *BaseAddress, ULONG_PTR ZeroBits,
    SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect)
{
    printf("[NtMapViewOfSection] Process: 0x%p, Size: %zu\n",
           ProcessHandle, *ViewSize);
    return OriginalNtMapViewOfSection(SectionHandle, ProcessHandle,
                                      BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
                                      InheritDisposition, AllocationType, Win32Protect);
}

// ================= Registry Hooks ================= //

NTSTATUS NTAPI HookedNtCreateKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
    PUNICODE_STRING Class, ULONG CreateOptions,
    PULONG Disposition)
{
    if (ObjectAttributes && ObjectAttributes->ObjectName)
    {
        printf("[NtCreateKey] Key: %wZ\n", ObjectAttributes->ObjectName);
    }
    return OriginalNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                               TitleIndex, Class, CreateOptions, Disposition);
}

NTSTATUS NTAPI HookedNtOpenKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    if (ObjectAttributes && ObjectAttributes->ObjectName)
    {
        printf("[NtOpenKey] Key: %wZ\n", ObjectAttributes->ObjectName);
    }
    return OriginalNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS NTAPI HookedNtSetValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
    if (ValueName)
    {
        printf("[NtSetValueKey] Value: %wZ, Size: %lu\n", ValueName, DataSize);
    }
    return OriginalNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

NTSTATUS NTAPI HookedNtQueryValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    if (ValueName)
    {
        printf("[NtQueryValueKey] Value: %wZ\n", ValueName);
    }
    return OriginalNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
                                   KeyValueInformation, Length, ResultLength);
}

// ================= System Hooks ================= //

NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    printf("[NtQuerySystemInformation] Class: %d\n", SystemInformationClass);
    return OriginalNtQuerySystemInformation(SystemInformationClass,
                                            SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtDeviceIoControlFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength)
{
    printf("[NtDeviceIoControlFile] ControlCode: 0x%08X\n", IoControlCode);
    return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine,
                                         ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                                         InputBufferLength, OutputBuffer, OutputBufferLength);
}

// ================= Hook Management ================= //

BOOL CreateHook(LPCSTR name, LPVOID hookFunc, LPVOID *originalFunc)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        printf("Failed to get ntdll handle\n");
        return FALSE;
    }

    LPVOID target = GetProcAddress(hNtdll, name);
    if (!target)
    {
        printf("Failed to find %s\n", name);
        return FALSE;
    }

    if (MH_CreateHook(target, hookFunc, originalFunc) != MH_OK)
    {
        printf("Failed to create hook for %s\n", name);
        return FALSE;
    }

    if (MH_EnableHook(target) != MH_OK)
    {
        printf("Failed to enable hook for %s\n", name);
        return FALSE;
    }

    printf("Successfully hooked %s\n", name);
    return TRUE;
}

BOOL InitializeNtHooks()
{
    if (MH_Initialize() != MH_OK)
    {
        printf("MinHook initialization failed\n");
        return FALSE;
    }

    BOOL success = TRUE;

    // File System Hooks
    success &= CreateHook("NtCreateFile", &HookedNtCreateFile, (LPVOID *)&OriginalNtCreateFile);
    success &= CreateHook("NtOpenFile", &HookedNtOpenFile, (LPVOID *)&OriginalNtOpenFile);
    success &= CreateHook("NtReadFile", &HookedNtReadFile, (LPVOID *)&OriginalNtReadFile);
    success &= CreateHook("NtWriteFile", &HookedNtWriteFile, (LPVOID *)&OriginalNtWriteFile);
    success &= CreateHook("NtDeleteFile", &HookedNtDeleteFile, (LPVOID *)&OriginalNtDeleteFile);
    success &= CreateHook("NtSetInformationFile", &HookedNtSetInformationFile, (LPVOID *)&OriginalNtSetInformationFile);
    success &= CreateHook("NtQueryDirectoryFile", &HookedNtQueryDirectoryFile, (LPVOID *)&OriginalNtQueryDirectoryFile);

    // Process/Thread Hooks
    success &= CreateHook("NtCreateProcess", &HookedNtCreateProcess, (LPVOID *)&OriginalNtCreateProcess);
    success &= CreateHook("NtTerminateProcess", &HookedNtTerminateProcess, (LPVOID *)&OriginalNtTerminateProcess);
    success &= CreateHook("NtOpenProcess", &HookedNtOpenProcess, (LPVOID *)&OriginalNtOpenProcess);
    success &= CreateHook("NtCreateThread", &HookedNtCreateThread, (LPVOID *)&OriginalNtCreateThread);

    // Memory Hooks
    success &= CreateHook("NtAllocateVirtualMemory", &HookedNtAllocateVirtualMemory, (LPVOID *)&OriginalNtAllocateVirtualMemory);
    success &= CreateHook("NtProtectVirtualMemory", &HookedNtProtectVirtualMemory, (LPVOID *)&OriginalNtProtectVirtualMemory);
    success &= CreateHook("NtCreateSection", &HookedNtCreateSection, (LPVOID *)&OriginalNtCreateSection);
    success &= CreateHook("NtMapViewOfSection", &HookedNtMapViewOfSection, (LPVOID *)&OriginalNtMapViewOfSection);

    // Registry Hooks
    success &= CreateHook("NtCreateKey", &HookedNtCreateKey, (LPVOID *)&OriginalNtCreateKey);
    success &= CreateHook("NtOpenKey", &HookedNtOpenKey, (LPVOID *)&OriginalNtOpenKey);
    success &= CreateHook("NtSetValueKey", &HookedNtSetValueKey, (LPVOID *)&OriginalNtSetValueKey);
    success &= CreateHook("NtQueryValueKey", &HookedNtQueryValueKey, (LPVOID *)&OriginalNtQueryValueKey);

    // System Hooks
    success &= CreateHook("NtQuerySystemInformation", &HookedNtQuerySystemInformation, (LPVOID *)&OriginalNtQuerySystemInformation);
    success &= CreateHook("NtDeviceIoControlFile", &HookedNtDeviceIoControlFile, (LPVOID *)&OriginalNtDeviceIoControlFile);

    if (!success)
    {
        CleanupNtHooks();
        return FALSE;
    }

    printf("All NT hooks initialized successfully\n");
    return TRUE;
}

void CleanupNtHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    printf("All hooks disabled and cleaned up\n");
}