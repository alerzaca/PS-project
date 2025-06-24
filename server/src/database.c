#include "database.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/socket.h>

// Tworzenie bazy danych i tabeli serwera
int create_database(const char *dbfile, const char *server_name) {

    // Sprawdzenie, czy plik bazy danych istnieje
    // Jeśli tak, to nie można utworzyć nowej bazy danych o tej same
    if (file_exists(dbfile)) {
        fprintf(stderr, "Database '%s' already exists. Run server using './server start %s' or choose other name.\n", dbfile, server_name);
        return -1;
    }

    // Tworzenie bazy danych SQLite
    sqlite3 *db;
    if (sqlite3_open(dbfile, &db) != SQLITE_OK) {
        fprintf(stderr, "create database error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Tworzenie tabeli informacyjnej
    const char *sql =
        "CREATE TABLE server_info ("
        "id TEXT PRIMARY KEY,"      // Unikalne ID serwera
        "name TEXT,"                // Nazwa serwera
        "created TEXT"              // Data utworzenia serwera
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, sql, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL query error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }

    // Tworzenie tabeli z użytkownikami
    const char *sql_users =
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"         // nazwa użytkownika
        "password TEXT NOT NULL"             // hasło użytkownika
        ");";
    if (sqlite3_exec(db, sql_users, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL query error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }

    // Tworzrenie tabeli z historią czatu
    const char *sql_chat_history =
        "CREATE TABLE IF NOT EXISTS chat_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT,"
        "message TEXT NOT NULL,"
        "timestamp TEXT NOT NULL"
        ");";
    if (sqlite3_exec(db, sql_chat_history, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL query error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }

    // Wygenerowanie unikalnego ID serwera
    char server_id[SERVER_ID_LEN];
    generate_id(server_id, sizeof(server_id));

    // Pobranie daty i czasu utworzenia serwera
    char created[32];
    get_current_datetime(created, sizeof(created));

    // Wstawianie rekordów do tabeli informacyjnej
    char insert[512];
    snprintf(insert, sizeof(insert),
        "INSERT INTO server_info (id, name, created) VALUES ('%s', '%s', '%s');", server_id, server_name, created);
    if (sqlite3_exec(db, insert, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL query error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }

    printf("Created database for server with name '%s'. New server ID is: %s\n", dbfile, server_id);
    sqlite3_close(db);
    return 0;
}

// Funkcja do pobierania informacji o serwerze z bazy danych (do zmiany)
int get_server_info(const char *dbfile, char *server_id, char *created) {

    // Sprawdzenie, czy plik bazy danych istnieje
    // Jeśli nie, to informacja o tym, że serwer nie istnieje i należy go utworzyć
    if (!file_exists(dbfile)) {
        fprintf(stderr, "Database for server (%s) does not exist. Use './server create <name>'\n", dbfile);
        return -1;
    }

    // Przygotowanie pliku bazy danych
    sqlite3 *db;
    if (sqlite3_open(dbfile, &db) != SQLITE_OK) {
        fprintf(stderr, "open database error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    const char *sql = "SELECT id, created FROM server_info LIMIT 1;";
    sqlite3_stmt *stmt;
    int result = 0;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            strncpy(server_id, (const char*)sqlite3_column_text(stmt, 0), SERVER_ID_LEN-1);
            strncpy(created, (const char*)sqlite3_column_text(stmt, 1), sizeof(created)-1);
        } else {
            fprintf(stderr, "database error: not enough records\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "SQL database read error\n");
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    return result;
}

// Rejestracja użytkownika
int register_user(sqlite3 *db, const char *username, const char *hash_str, int sd) {
    
    // Sprawdzenie, czy użytkownik już istnieje
    sqlite3_stmt *stmt;
    const char *sql = "SELECT username FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        send(sd, "REGISTER_FAIL\n", 14, 0);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        send(sd, "REGISTER_EXISTS\n", 16, 0);
        sqlite3_finalize(stmt);
        return 1;
    }
    sqlite3_finalize(stmt);

    // Dodanie nowego użytkownika
    sql = "INSERT INTO users (username, password) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        send(sd, "REGISTER_FAIL\n", 14, 0);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash_str, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        send(sd, "REGISTER_OK\n", 12, 0);
        return 0;
    } else {
        send(sd, "REGISTER_FAIL\n", 14, 0);
        return -1;
    }
}

// Logowanie użytkownika
int login_user(sqlite3 *db, const char *username, const char *hash_str, int sd) {
    
    // Sprawdzenie w bazie danych
    sqlite3_stmt *stmt;
    const char *sql = "SELECT password FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        send(sd, "LOGIN_FAIL\n", 11, 0);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *db_pass = (const char*)sqlite3_column_text(stmt, 0);
        if (strcmp(db_pass, hash_str) == 0) {
            send(sd, "LOGIN_OK\n", 9, 0);
            sqlite3_finalize(stmt);
            return 0;
        }
    }

    send(sd, "LOGIN_FAIL\n", 11, 0);
    sqlite3_finalize(stmt);
    return -1;
}

// Funkcja do zapisywania wiadomości czatu w bazie danych
int save_message(sqlite3 *db, const char *username, const char *message) {
    char timestamp[32];
    get_current_datetime(timestamp, sizeof(timestamp)); // zakładam, że masz już taką funkcję

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO chat_history (username, message, timestamp) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, username ? username : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, timestamp, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// Funkcja do pobierania ostatnich wiadomości czatu z bazy danych
int get_last_messages(sqlite3 *db, char *output, size_t output_size, int limit) {
   
    // Pobierz do 10 ostatnich wiadomości, od najstarszej do najnowszej
    const char *sql =
        "SELECT username, message FROM ("
        "SELECT username, message, id FROM chat_history ORDER BY id DESC LIMIT ?"
        ") ORDER BY id ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, limit);

    size_t offset = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *username = (const char*)sqlite3_column_text(stmt, 0);
        const char *message = (const char*)sqlite3_column_text(stmt, 1);
        int n = snprintf(output + offset, output_size - offset, "[%s]: %s", username, message);
        if (n < 0 || (size_t)n >= output_size - offset) break;
        offset += n;
    }
    sqlite3_finalize(stmt);
    return 0;
}

