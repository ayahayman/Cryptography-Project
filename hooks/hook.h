#pragma once
#include <Windows.h>
#include <winternl.h>

// Alert levels
typedef enum
{
    ALERT_LOW = 0,
    ALERT_MEDIUM,
    ALERT_HIGH,
    ALERT_CRITICAL
} ALERT_LEVEL;

// NTSTATUS definitions
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef KEY_VALUE_INFORMATION_CLASS
typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64
} KEY_VALUE_INFORMATION_CLASS;
#endif

// Original function typedefs
typedef NTSTATUS(NTAPI *NtCreateFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS(NTAPI *NtOpenFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    ULONG, ULONG);

typedef NTSTATUS(NTAPI *NtReadFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

typedef NTSTATUS(NTAPI *NtWriteFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

// Add NtSetInformationFile definition
typedef NTSTATUS(NTAPI *NtSetInformationFile_t)(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS(NTAPI *NtDeleteFile_t)(
    POBJECT_ATTRIBUTES);

typedef NTSTATUS(NTAPI *NtQueryDirectoryFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

typedef NTSTATUS(NTAPI *NtCreateProcess_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN,
    HANDLE, HANDLE, HANDLE);

typedef NTSTATUS(NTAPI *NtTerminateProcess_t)(
    HANDLE, NTSTATUS);

typedef NTSTATUS(NTAPI *NtOpenProcess_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

typedef NTSTATUS(NTAPI *NtCreateThread_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID,
    PCONTEXT, PVOID, BOOLEAN);

typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS(NTAPI *NtProtectVirtualMemory_t)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS(NTAPI *NtCreateSection_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE);

typedef NTSTATUS(NTAPI *NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI *NtCreateKey_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING,
    ULONG, PULONG);

typedef NTSTATUS(NTAPI *NtOpenKey_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS(NTAPI *NtSetValueKey_t)(
    HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS(NTAPI *NtQueryValueKey_t)(
    HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS,
    PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI *NtDeviceIoControlFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG,
    PVOID, ULONG, PVOID, ULONG);

// Function declarations
NTSTATUS NTAPI HookedNtOpenFile(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    ULONG, ULONG);

NTSTATUS NTAPI HookedNtReadFile(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

NTSTATUS NTAPI HookedNtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

// Hook management
BOOL InitializeNtHooks();
void CleanupNtHooks();

// Original function pointers
extern NtCreateFile_t OriginalNtCreateFile;
extern NtOpenFile_t OriginalNtOpenFile;
extern NtReadFile_t OriginalNtReadFile;
extern NtWriteFile_t OriginalNtWriteFile;
extern NtDeleteFile_t OriginalNtDeleteFile;
extern NtQueryDirectoryFile_t OriginalNtQueryDirectoryFile;
extern NtCreateProcess_t OriginalNtCreateProcess;
extern NtTerminateProcess_t OriginalNtTerminateProcess;
extern NtOpenProcess_t OriginalNtOpenProcess;
extern NtCreateThread_t OriginalNtCreateThread;
extern NtAllocateVirtualMemory_t OriginalNtAllocateVirtualMemory;
extern NtProtectVirtualMemory_t OriginalNtProtectVirtualMemory;
extern NtCreateSection_t OriginalNtCreateSection;
extern NtMapViewOfSection_t OriginalNtMapViewOfSection;
extern NtQuerySystemInformation_t OriginalNtQuerySystemInformation;
extern NtCreateKey_t OriginalNtCreateKey;
extern NtOpenKey_t OriginalNtOpenKey;
extern NtSetValueKey_t OriginalNtSetValueKey;
extern NtQueryValueKey_t OriginalNtQueryValueKey;
extern NtDeviceIoControlFile_t OriginalNtDeviceIoControlFile;
extern NtSetInformationFile_t OriginalNtSetInformationFile;
