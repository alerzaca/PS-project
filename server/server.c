#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <string.h>

#define MULTICAST_GROUP "239.0.0.1" // Adres grupy multicast, na której serwer będzie się ogłaszał
#define MULTICAST_PORT 12345        // Port UDP multicast, na którym serwer będzie się ogłaszał
#define TCP_PORT 8080               // Port TCP, na którym serwer będzie obsługiwał chat

#define BACKLOG 3                   // Maksymalna liczba oczekujących połączeń
#define MAX_CLIENTS 10              // Maksymalna liczba jednocześnie połączonych klientów
#define BUFFER_SIZE 1024            // Rozmiar bufora do odbierania wiadomości
#define SERVER_ID_LEN 7             // 6 znaków heksadecymalnych + '\0'


// Funkcja sprawdzająca, czy plik istnieje
int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
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

// Struktura argumentów dla wątku multicast
struct thread_args {
    char server_name[128];
    char server_id[SERVER_ID_LEN];
    char ip[INET_ADDRSTRLEN];
};

// Wątek rozgłaszania multicast
void* multicast_broadcast(void *arg) {
    struct thread_args *targs = (struct thread_args*)arg;
    char *server_name = targs->server_name;
    char *server_id = targs->server_id;
    targs->server_id[SERVER_ID_LEN-1] = '\0'; // Dzięki temu nigdy nie dojdzie do sytuacji sklejania id i IP przy generowaniu message
    char *ip = targs->ip;

    int sock;
    struct sockaddr_in addr;
    char message[256];

    // Tworzenie gniazda UDP
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket error");
        pthread_exit(NULL);
    }

    // Konfiguracja adresu multicast
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
    addr.sin_port = htons(MULTICAST_PORT);

    // Rozgłaszanie informacji o serwerze co 5 sekund
    while(1) {
        // Przygotowanie wiadomości do rozgłoszenia
        // Format: <ID>:<Name>:<IP>:<Port>
        snprintf(message, sizeof(message), "%s:%s:%s:%d", server_id, server_name, ip, TCP_PORT);

        if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("sendto error");
            close(sock);
            pthread_exit(NULL);
        }
        
        // Można odkomentować poniższą linię, aby zobaczyć wysyłane wiadomości, ale szybko może to zapełnić konsolę
        //printf("[Multicast message]: '%s'\n", message);
        sleep(5);
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "create") == 0) {
        char server_name[128] = "";
        strncpy(server_name, argv[2], sizeof(server_name)-1);

        char dbfile[256];
        snprintf(dbfile, sizeof(dbfile), "%s.db", server_name);

        if (file_exists(dbfile)) {
            char dbfile_wout_db[256];
            int len = strlen(dbfile);
            strncpy(dbfile_wout_db, dbfile, len - 3);
            dbfile_wout_db[len - 3] = '\0';
            fprintf(stderr, "Database '%s' already exists. Run server using './server start %s' or choose other name for your new server instance.\n", dbfile, dbfile_wout_db);
            exit(1);
        }

        // Tworzenie bazy danych SQLite
        sqlite3 *db;
        if (sqlite3_open(dbfile, &db) != SQLITE_OK) {
            fprintf(stderr, "create database error: %s\n", sqlite3_errmsg(db));
            exit(1);
        }

        // Tworzenie folderu wspłdzielonego
        char shared_dir[512];
        snprintf(shared_dir, sizeof(shared_dir), "shared/%s", server_name);
        mkdir(shared_dir, 0755);

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
            exit(1);
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
            exit(1);
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
            exit(1);
        }

        printf("Created database for server with name '%s'. New server ID is: %s\n", dbfile, server_id);
        sqlite3_close(db);
        exit(0);
    }

    else if (argc == 4 && strcmp(argv[1], "start") == 0) {
        char server_name[128] = "";
        strncpy(server_name, argv[2], sizeof(server_name)-1);

        char *ifname = argv[3];
        char ip[INET_ADDRSTRLEN] = "0.0.0.0";

        char dbfile[256];
        snprintf(dbfile, sizeof(dbfile), "%s.db", server_name);

        // Sprawdzenie, czy plik bazy danych istnieje
        if (!file_exists(dbfile)) {
            char dbfile_wout_db[256];
            int len = strlen(dbfile);
            strncpy(dbfile_wout_db, dbfile, len - 3);
            dbfile_wout_db[len - 3] = '\0';
            fprintf(stderr, "Database for server (%s) does not exist. To create a new server with that name use './server create %s'\n", dbfile, dbfile_wout_db);
            exit(1);
        }

        // Przygotowanie nazwy pliku bazy danych
        sqlite3 *db;
        if (sqlite3_open(dbfile, &db) != SQLITE_OK) {
            fprintf(stderr, "open database error: %s\n", sqlite3_errmsg(db));
            exit(1);
        }

        // Pobieranie informacji o serwerze z bazy danych
        char server_id[SERVER_ID_LEN] = "";
        char created[32] = "";
        const char *sql = "SELECT id, created FROM server_info LIMIT 1;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                strncpy(server_id, (const char*)sqlite3_column_text(stmt, 0), SERVER_ID_LEN-1);
                strncpy(created, (const char*)sqlite3_column_text(stmt, 1), sizeof(created)-1);
            } else {
                fprintf(stderr, "database error: not enough records\n");
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_finalize(stmt);
        } else {
            fprintf(stderr, "SQL database read error\n");
            sqlite3_close(db);
            exit(1);
        }

        // Informacja o pomyślnym odczytaniu danych i startowanie faktcznego serwera
        printf("Starting serwer %s [ID: %s, created: %s] ...\n", server_name, server_id, created);

        // Pobieranie adresu IP interfejsu sieciowego
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs error");
            exit(EXIT_FAILURE);
        }
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, ifname) == 0) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                break;
            }
        }
        freeifaddrs(ifaddr);

        // Przygotowanie argumentów do wątku multicast
        struct thread_args *targs = malloc(sizeof(struct thread_args));
        strncpy(targs->server_name, server_name, sizeof(targs->server_name)-1);
        strncpy(targs->server_id, server_id, sizeof(targs->server_id)-1);
        strncpy(targs->ip, ip, INET_ADDRSTRLEN);

        // Uruchomienie nowego wątku multicast
        pthread_t multicast_thread;
        if (pthread_create(&multicast_thread, NULL, multicast_broadcast, targs) != 0) {
            perror("pthread_create error");
            free(targs);
            return 1;
        }

        // Inicjalizacja gniazda TCP
        int server_fd, max_sd, activity, new_socket;
        struct sockaddr_in server_addr;
        int opt = 1;
        char buffer[BUFFER_SIZE] = {0};
        fd_set readfds;
        
        int client_sockets[MAX_CLIENTS] = {0};
        struct sockaddr_in client_addresses[MAX_CLIENTS];

        // Tworzenie gniazda
        // AF_INET - IPv4, SOCK_STREAM - TCP, 0 - domyślny protokół
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("TCP socket error");
            exit(EXIT_FAILURE);
        }

        // Ustawianie opcji gniazda
        // SO_REUSEADDR - pozwala na ponowne użycie adresu (przy restartach serwera)
        // SO_REUSEPORT - pozwala wielu procesom na nasłuchiwanie na tym samym porcie
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            perror("setsockopt error");
            exit(EXIT_FAILURE);
        }

        // Konfiguracja adresu serwera
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(TCP_PORT);

        // Bind - przypisanie gniazda do adresu i portu
        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("bind error");
            exit(EXIT_FAILURE);
        }

        printf("Server opened as %s [ID: %s] on port %d \n", server_name, server_id, TCP_PORT);

        // Listen
        if (listen(server_fd, BACKLOG) < 0) {
            perror("listen error");
            exit(EXIT_FAILURE);
        }

        // Główna pętla serwera
        while (1) {
            // Zerowanie zbioru fd_set i ustawianie gniazda serwera
            FD_ZERO(&readfds);
            FD_SET(server_fd, &readfds);
            max_sd = server_fd; // maksymalne gniazdo do monitorowania

            // Dodawanie gniazd klientów do zbioru fd_set
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] > 0) {
                    FD_SET(client_sockets[i], &readfds);
                    if (client_sockets[i] > max_sd) max_sd = client_sockets[i];
                }
            }

            // Czekanie na aktywność na gniazdach
            activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
            if ((activity < 0) && (errno != EINTR)) {
                perror("select error");
            }

            // Nowe połączenie
            // FD_ISSET sprawdza, czy gniazdo serwera jest gotowe do odczytu
            if (FD_ISSET(server_fd, &readfds)) {
                
                // Akceptacja nowego połączenia, pobranie adresu klienta
                struct sockaddr_in client_addr;
                socklen_t client_addrlen = sizeof(client_addr);
                
                if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t*)&client_addrlen)) < 0) {
                    perror("accept error");
                    continue;
                }

                // Dodanie nowego klienta do listy aktywnych gniazd
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_sockets[i] == 0) {
                        // Znalezienie pierwszego wolnego gniazda klienta
                        client_sockets[i] = new_socket;
                        memcpy(&client_addresses[i], &client_addr, sizeof(client_addr));
                        
                        // Pobranie adresu IP klienta i portu
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                        
                        // Konwersja portu klienta na liczbę całkowitą i wyświetlenie informacji o nowym połączeniu
                        int client_port = ntohs(client_addr.sin_port);
                        printf("New connection from %s:%d\n", client_ip, client_port);
                        break;
                    }
                }
            }

            // Sprawdzenie aktywności na gniazdach klientów
            for (int i = 0; i < MAX_CLIENTS; i++) {
                int sd = client_sockets[i];

                // FD_ISSET sprawdza, czy gniazdo klienta jest gotowe do odczytu        
                if (sd > 0 && FD_ISSET(sd, &readfds)) {
                    int valread = read(sd, buffer, sizeof(buffer)-1);
                    
                    if (valread <= 0) {
                        // valread <= 0 oznacza, że klient rozłączył się lub wystąpił błąd

                        // Pobranie adresu IP klienta i portu
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &client_addresses[i].sin_addr, client_ip, INET_ADDRSTRLEN);
                        int client_port = ntohs(client_addresses[i].sin_port);

                        // Wyświetlenie informacji o rozłączeniu
                        printf("Client %s:%d disconnected\n", client_ip, client_port);
                        
                        // Zamknięcie gniazda klienta i usunięcie go z listy aktywnych gniazd
                        close(sd);
                        client_sockets[i] = 0;
                    } else {
                        // valread > 0 oznacza, że odczytano dane od klienta

                        // Rejestracja użytkownika
                        if (strncmp(buffer, "REGISTER ", 9) == 0) {
                            char username[64], password[64];
                            if (sscanf(buffer + 9, "%63s %63s", username, password) != 2) {
                                send(sd, "REGISTER_FAIL\n", 14, 0);
                                continue;
                            }

                            // Sprawdzenie, czy użytkownik już istnieje
                            sqlite3_stmt *stmt;
                            const char *sql = "SELECT username FROM users WHERE username = ?;";
                            if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
                                send(sd, "REGISTER_FAIL\n", 14, 0);
                                continue;
                            }
                            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

                            if (sqlite3_step(stmt) == SQLITE_ROW) {
                                send(sd, "REGISTER_EXISTS\n", 16, 0);
                                sqlite3_finalize(stmt);
                                continue;
                            }
                            sqlite3_finalize(stmt);

                            // Dodanie nowego użytkownika
                            sql = "INSERT INTO users (username, password) VALUES (?, ?);";
                            if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
                                send(sd, "REGISTER_FAIL\n", 14, 0);
                                continue;
                            }
                            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

                            if (sqlite3_step(stmt) == SQLITE_DONE) {
                                send(sd, "REGISTER_OK\n", 12, 0);
                            } else {
                                send(sd, "REGISTER_FAIL\n", 14, 0);
                            }
                            sqlite3_finalize(stmt);
                            continue;
                        }

                        // Logowanie
                        if (strncmp(buffer, "LOGIN ", 6) == 0) {
                            char username[64], password[64];
                            if (sscanf(buffer + 6, "%63s %63s", username, password) != 2) {
                                send(sd, "LOGIN_FAIL\n", 11, 0);
                                continue;
                            }

                            // Sprawdzenie w bazie danych
                            sqlite3_stmt *stmt;
                            const char *sql = "SELECT password FROM users WHERE username = ?;";
                            if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
                                send(sd, "LOGIN_FAIL\n", 11, 0);
                                continue;
                            }
                            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

                            int rc = sqlite3_step(stmt);
                            if (rc == SQLITE_ROW) {
                                const char *db_pass = (const char*)sqlite3_column_text(stmt, 0);
                                if (strcmp(db_pass, password) == 0) {
                                    send(sd, "LOGIN_OK\n", 9, 0);
                                } else {
                                    send(sd, "LOGIN_FAIL\n", 11, 0);
                                }
                            } else {
                                send(sd, "LOGIN_FAIL\n", 11, 0);
                            }
                            sqlite3_finalize(stmt);
                            continue;
                        }

                        // Wysłanie pliku na serwer
                        if (strncmp(buffer, "UPLOAD ", 7) == 0) {
                            char filename[256];
                            int filesize;
                            if (sscanf(buffer + 7, "%255s %d", filename, &filesize) != 2) {
                                send(sd, "UPLOAD_FAIL\n", 12, 0);
                                continue;
                            }
                            char filepath[512];
                            snprintf(filepath, sizeof(filepath), "shared/%s/%s", server_name, filename);
                            FILE *file = fopen(filepath, "wb");
                            if (!file) {
                                send(sd, "UPLOAD_FAIL\n", 12, 0);
                                continue;
                            }
                            send(sd, "UPLOAD_OK\n", 10, 0);
                            
                            // Odbierz plik
                            int total = 0;
                            while (total < filesize) {
                                int n = read(sd, buffer, BUFFER_SIZE);
                                if (n <= 0) break;
                                fwrite(buffer, 1, n, file);
                                total += n;
                            }
                            fclose(file);
                            send(sd, "UPLOAD_OK\n", 10, 0);
                        }
                        
                        // Pobranie pliku z serwera
                        if (strncmp(buffer, "DOWNLOAD ", 9) == 0) {
                            char filename[256];
                            if (sscanf(buffer + 9, "%255s", filename) != 1) {
                                send(sd, "DOWNLOAD_FAIL\n", 14, 0);
                                continue;
                            }
                            char filepath[512];
                            snprintf(filepath, sizeof(filepath), "shared/%s/%s", server_name, filename);
                            FILE *file = fopen(filepath, "rb");
                            if (!file) {
                                send(sd, "DOWNLOAD_FAIL\n", 14, 0);
                                continue;
                            }
                            // Pobierz rozmiar pliku
                            fseek(file, 0, SEEK_END);
                            int filesize = ftell(file);
                            fseek(file, 0, SEEK_SET);
                            // Wyślij rozmiar pliku
                            snprintf(buffer, BUFFER_SIZE, "DOWNLOAD %d\n", filesize);
                            send(sd, buffer, strlen(buffer), 0);
                            // Wyślij plik
                            int n;
                            while ((n = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
                                send(sd, buffer, n, 0);
                            }
                            fclose(file);
                        }

                        // Pobranie adresu IP klienta i portu
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &client_addresses[i].sin_addr, client_ip, INET_ADDRSTRLEN);
                        int client_port = ntohs(client_addresses[i].sin_port);

                        // Przygotowanie wiadomości do wyświetlenia
                        buffer[valread] = '\0';
                        char message[BUFFER_SIZE + INET_ADDRSTRLEN + 16];

                        // Format: [IP:Port] Wiadomość
                        snprintf(message, sizeof(message), "[%s:%d] %s", client_ip, client_port, buffer);

                        // Wyświetlenie wiadomości na serwerze  
                        printf("%s", message);

                        // Rozsyłanie do innych klientów
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            int dest_sd = client_sockets[j];
                            if (dest_sd > 0 && dest_sd != sd) {
                                send(dest_sd, message, strlen(message), 0);
                            }
                        }
                    }
                }
            }


        }

        // Sprzątanie końcowe: zamknięcie gniazda i zakończenie wątku multicast
        pthread_cancel(multicast_thread);
        pthread_join(multicast_thread, NULL);
        close(server_fd);
        free(targs);
        return 0;
    }

    else {
        printf("Usage:\n");
        printf("  %s create <name>\n", argv[0]);
        printf("  %s start <name> <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 
}
