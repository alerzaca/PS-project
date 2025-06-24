#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

int file_exists(const char *filename);
void ensure_shared_folders(const char *server_name);
void get_current_datetime(char *buf, size_t len);
void generate_id(char *id, size_t size);

#endif