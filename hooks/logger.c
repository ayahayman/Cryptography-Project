#include "hook.h"
#include "logger.h"
#include <stdio.h>
#include <time.h>
#include <Windows.h>
#include <stdarg.h>

static CRITICAL_SECTION log_cs;
static BOOL initialized = FALSE;

void InitLogger()
{
    InitializeCriticalSection(&log_cs);
    initialized = TRUE;
}

void LogToFile(const char *format, ...)
{
    if (!initialized)
        InitLogger();

    EnterCriticalSection(&log_cs);

    FILE *f = fopen("C:\\AntiRansomware\\monitor.log", "a");
    if (f)
    {
        // Timestamp
        time_t now;
        time(&now);
        struct tm *tm_info = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ",
                tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
                tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);

        // Log message
        va_list args;
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);

        fputc('\n', f);
        fclose(f);
    }

    LeaveCriticalSection(&log_cs);
}

void TriggerAlert(ALERT_LEVEL level, const char *process_name, const char *action)
{
    const char *level_str[] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
    char alert_msg[1024];

    snprintf(alert_msg, sizeof(alert_msg),
             "[%s] %s: %s",
             level_str[level], process_name, action);

    // Fix: Create proper string pointer for ReportEventA
    const char *strings[1];
    strings[0] = alert_msg;

    if (level >= ALERT_HIGH)
    {
        HANDLE hEventLog = RegisterEventSourceA(NULL, "AntiRansomware");
        if (hEventLog)
        {
            ReportEventA(hEventLog, EVENTLOG_WARNING_TYPE, 0, 0, NULL, 1, 0, strings, NULL);
            DeregisterEventSource(hEventLog);
        }
    }

    LogToFile("ALERT: %s", alert_msg);
}

DWORD GetFinalPathNameByHandleA(HANDLE hFile, LPSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags)
{
    static HMODULE hKernel32 = NULL;
    static DWORD(WINAPI * pfn)(HANDLE, LPSTR, DWORD, DWORD) = NULL;

    if (!hKernel32)
        hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!pfn)
        pfn = (DWORD(WINAPI *)(HANDLE, LPSTR, DWORD, DWORD))GetProcAddress(hKernel32, "GetFinalPathNameByHandleA");

    return pfn ? pfn(hFile, lpszFilePath, cchFilePath, dwFlags) : 0;
}