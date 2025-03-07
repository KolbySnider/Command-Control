#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "../include/network.h"

char* extract_body(char *response) {
    char *body = strstr(response, "\r\n\r\n");
    return body ? body + 4 : NULL;
}

int send_http_post(const char *host, int port, const char *path,
const char *data, char *response, size_t resp_size) {
    SOCKET sockfd;
    struct sockaddr_in server_addr;
    int bytes;
    char request[BUFFER_SIZE];

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation error: %d\n", WSAGetLastError());
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Connection failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        return -1;
    }

    // Build HTTP request
    int content_length = data ? strlen(data) : 0;
    snprintf(request, BUFFER_SIZE,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n\r\n"
        "%s",
        path, host, port, USER_AGENT, content_length, data ? data : "");

    // Send request
    if (send(sockfd, request, strlen(request), 0) == SOCKET_ERROR) {
        printf("Send failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        return -1;
    }

    // Read complete response
    int total_bytes = 0;
    while (total_bytes < (int)(resp_size - 1)) {
        bytes = recv(sockfd, response + total_bytes, resp_size - total_bytes - 1, 0);
        if (bytes == SOCKET_ERROR) {
            printf("Receive failed: %d\n", WSAGetLastError());
            break;
        }
        if (bytes == 0) break;  // Connection closed
        total_bytes += bytes;
    }
    response[total_bytes] = '\0';

    closesocket(sockfd);
    return (bytes == SOCKET_ERROR) ? -1 : 0;
}