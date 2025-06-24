#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Funkcja sprawdzająca, czy plik istnieje
int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

// Funkcja sprawdzająca, czy istnieje odpowiednia struktura folderu wspłdzielonego
void ensure_shared_folders(const char *server_name) {
    struct stat st = {0};
    if (stat("shared", &st) == -1) {
        mkdir("shared", 0755);
    }
    char shared_dir[512];
    snprintf(shared_dir, sizeof(shared_dir), "shared/%s", server_name);
    if (stat(shared_dir, &st) == -1) {
        mkdir(shared_dir, 0755);
    }
}

// Funkcja do pobierania aktualnej daty i czasu w formacie YYYY-MM-DD HH:MM:SS
void get_current_datetime(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", t);
}

// Generowanie prostego unikalnego ID na podstawie czasu i PID
void generate_id(char *id, size_t size) {
    unsigned int hash = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    snprintf(id, size, "%06X", hash % 0xFFFFFF); // np. "A1B2C3"
}
