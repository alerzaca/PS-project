#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <stddef.h>

void get_user_credentials(char *username, size_t ulen, char *password, size_t plen);
void hash_password(const char *password, unsigned char *output);
void hash_password_hex(const char *password, char *hash_str);

#endif
