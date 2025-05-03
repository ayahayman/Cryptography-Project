#pragma once
#include <windows.h>
#include <winternl.h>

// Include hook.h for ALERT_LEVEL definition to avoid duplication
#include "hook.h"

void InitLogger();
void TriggerAlert(ALERT_LEVEL level, const char *process_name, const char *action);
void LogToFile(const char *format, ...);
void UploadToServer(const char *data); // For C2 reporting

// Declare GetFinalPathNameByHandleA to avoid redeclaration issues
DWORD GetFinalPathNameByHandleA(HANDLE hFile, LPSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);