#ifndef COMMANDS_H
#define COMMANDS_H
#define MAX_FILE_SIZE (5 * 1024 * 1024)  // 5MB limit

void execute_command(const char *command, char *output, size_t output_size, const char *agent_id);
void download_file(const char *remote_path, const char *agent_id, char *output, size_t output_size);

#endif
