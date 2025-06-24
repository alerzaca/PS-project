#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

#define SERVER_ID_LEN 7         // 6 znaków heksadecymalnych + '\0'

int create_database(const char *dbfile, const char *server_name);
int get_server_info(const char *dbfile, char *server_id, char *created);
int register_user(sqlite3 *db, const char *username, const char *hash_str, int sd);
int login_user(sqlite3 *db, const char *username, const char *hash_str, int sd);

#endif