#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "credentials.h"

// Funkcja do pobrania nazwy użytkownika i hasła
void get_user_credentials(char *username, size_t ulen, char *password, size_t plen) {
    printf("Username: ");
    fgets(username, ulen, stdin);
    username[strcspn(username, "\n")] = '\0';
    char *password_ptr = getpass("Password: ");
    strncpy(password, password_ptr, plen - 1);
    password[plen - 1] = '\0';
}

// Funkcja hashująca hasło użytkownika przed przesłaniem przez sieć
void hash_password(const char *password, unsigned char *output) {
    SHA256((unsigned char*)password, strlen(password), output);
}

// Funkcja do hashowania hasła na format szesnastkowy
void hash_password_hex(const char *password, char *hash_str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hash_str + i * 2, "%02x", hash[i]);
    hash_str[SHA256_DIGEST_LENGTH * 2] = '\0';
}

