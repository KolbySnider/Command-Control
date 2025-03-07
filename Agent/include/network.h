#ifndef NETWORK_H
#define NETWORK_H
#define BUFFER_SIZE 4096
#define USER_AGENT "Agent/1.0"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5000
#define BUFFER_SIZE 4096

int send_http_post(const char *host, int port, const char *path,
                    const char *data, char *response, size_t resp_size);
char* extract_body(char *response);


#endif