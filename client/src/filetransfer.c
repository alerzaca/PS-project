#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#include "filetransfer.h"
#include "credentials.h"
#include "network.h"

// Logika logowania do serwera plików
int login_to_file_server(int sock, char *username, char *password, char *buffer) {
    char hash_str[SHA256_DIGEST_LENGTH*2 + 1];
    hash_password_hex(password, hash_str);
    snprintf(buffer, BUFFER_SIZE, "LOGIN %s %s\n", username, hash_str);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE-1, 0);
    if (n <= 0 || strncmp(buffer, "LOGIN_OK\n", 9) != 0) {
        printf("Login failed\n");
        return 1;
    }
    return 0;
}

// Logika przesyłania plików
int upload_file(int sock, const char *filename, char *buffer) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    int filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    snprintf(buffer, BUFFER_SIZE, "UPLOAD %s %d\n", filename, filesize);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE-1, 0);
    if (n <= 0 || strncmp(buffer, "UPLOAD_OK", 9) != 0) {
        printf("Upload failed\n");
        fclose(file);
        return 1;
    }
    while ((n = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send(sock, buffer, n, 0);
    }
    fclose(file);
    printf("File uploaded successfully\n");
    return 0;
}

// Logika pobierania plików
int download_file(int sock, const char *filename, char *buffer) {
    snprintf(buffer, BUFFER_SIZE, "DOWNLOAD %s\n", filename);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE-1, 0);
    if (n <= 0) {
        printf("Download failed\n");
        return 1;
    }
    int filesize;
    if (sscanf(buffer, "DOWNLOAD %d", &filesize) != 1) {
        printf("Download failed\n");
        return 1;
    }
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    int total = 0;
    while (total < filesize) {
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n <= 0) break;
        fwrite(buffer, 1, n, file);
        total += n;
    }
    fclose(file);
    printf("File downloaded successfully\n");
    return 0;
}

