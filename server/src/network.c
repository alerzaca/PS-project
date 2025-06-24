#include "network.h"
#include "database.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netdb.h>

// Tablica przechowująca nazwy aktywnych klientów
char *client_usernames[MAX_CLIENTS] = {0};

// Pomocnicza funkcja do wysyłania powitania i historii czatu
void send_welcome_and_history(int sd, const char *dbfile, const char *server_name) {
    char welcome[256];
    snprintf(welcome, sizeof(welcome), "===== Welcome to server %s! =====\n", server_name);

    char history[4096] = "";
    sqlite3 *db2;
    if (sqlite3_open(dbfile, &db2) == SQLITE_OK) {
        get_last_messages(db2, history, sizeof(history), 10);
        sqlite3_close(db2);
    }

    // Separator historii
    const char *separator = "...\n";

    // Połącz powitanie, historię i separator w jeden bufor
    char all[8192];
    if (strlen(history) > 0)
        snprintf(all, sizeof(all), "%s%s%s", welcome, history, separator);
    else
        snprintf(all, sizeof(all), "%s%s", welcome, separator);

    // Wyślij długość powitania/historii jako uint32_t (sieciowo - big endian)
    uint32_t len = htonl(strlen(all));
    send(sd, &len, sizeof(len), 0);
    send(sd, all, strlen(all), 0);
}

// Funkcja do obsługi przesyłania plików
int handle_upload(int sd, const char *server_name, char *buffer) {
    char filename[256];
    int filesize;
    if (sscanf(buffer + 7, "%255s %d", filename, &filesize) != 2) {
        send(sd, "UPLOAD_FAIL\n", 12, 0);
        return -1;
    }
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "shared/%s/%s", server_name, filename);
    FILE *file = fopen(filepath, "wb");
    if (!file) {
        send(sd, "UPLOAD_FAIL\n", 12, 0);
        return -1;
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
    return 0;
}

// Funkcja do obsługi pobierania plików
int handle_download(int sd, const char *server_name, char *buffer) {
    char filename[256];
    if (sscanf(buffer + 9, "%255s", filename) != 1) {
        send(sd, "DOWNLOAD_FAIL\n", 14, 0);
        return -1;
    }
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "shared/%s/%s", server_name, filename);
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        send(sd, "DOWNLOAD_FAIL\n", 14, 0);
        return -1;
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
    return 0;
}

// Funkcja do obsługi klienta - wysyłanie/odbieranie wiadomości, rejestracja, logowanie, przesyłanie plików
void handle_client(
    int i,
    int sd,
    const char *dbfile,
    const char *server_name,
    int *client_sockets,
    struct sockaddr_in *client_addresses,
    char *buffer,
    int valread
) {
    // Przygotowanie pliku bazy danych
    sqlite3 *db;
    if (sqlite3_open(dbfile, &db) != SQLITE_OK) {
        fprintf(stderr, "open database error: %s\n", sqlite3_errmsg(db));
        return;
    }
    
    // Obsługa rozłączenia klienta
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
        sqlite3_close(db);
        return;
    }

    // Obsługa polecenia REGISTER
    if (strncmp(buffer, "REGISTER ", 9) == 0) {
        // Sprawdzenie poprawności formatu polecenia
        char username[64], hash_str[64];
        if (sscanf(buffer + 9, "%63s %63s", username, hash_str) != 2) {
            send(sd, "REGISTER_FAIL\n", 14, 0);
            sqlite3_close(db);
            return;
        }

        // Rejestracja użytkownika w bazie danych
        int reg_result = register_user(db, username, hash_str, sd);
        if (reg_result == 0) {
            // Sukces rejestracji, przypisanie username do obecnego połączenia
            if (client_usernames[i]) free(client_usernames[i]);
            client_usernames[i] = strdup(username);
            printf("User %s connected\n", username);

            // Wysyłka powitania i historii
            send_welcome_and_history(sd, dbfile, server_name);
        }
        sqlite3_close(db);
        return;
    }

    // Obsługa polecenia LOGIN
    if (strncmp(buffer, "LOGIN ", 6) == 0) {
        // Sprawdzenie poprawności formatu polecenia
        char username[64], hash_str[64];
        if (sscanf(buffer + 6, "%63s %63s", username, hash_str) != 2) {
            send(sd, "LOGIN_FAIL\n", 11, 0);
            sqlite3_close(db);
            return;
        }

        // Logowanie użytkownika w bazie danych
        int login_result = login_user(db, username, hash_str, sd);
        if (login_result == 0) {
            // Sukces logowania, przypisanie username do obecnego połączenia
            if (client_usernames[i]) free(client_usernames[i]);
            client_usernames[i] = strdup(username);
            printf("User %s connected\n", username);

            // Wysyłka powitania i historii
            send_welcome_and_history(sd, dbfile, server_name);            
        }
        sqlite3_close(db);
        return;
    }

    // Obsługa polecenia UPLOAD
    if (strncmp(buffer, "UPLOAD ", 7) == 0) {
        handle_upload(sd, server_name, buffer);
        // Dodać funkcję "<username> uploaded <filename>" do logów
        sqlite3_close(db);
        return;
    }

    // Obsługa polecenia DOWNLOAD
    if (strncmp(buffer, "DOWNLOAD ", 9) == 0) {
        handle_download(sd, server_name, buffer);
        // Dodać funkcję "<username> downloaded <filename>" do logów
        sqlite3_close(db);
        return;
    }

    // Pobranie adresu IP klienta i portu - już niepotrzebne, teraz rozpoznajemy klienta po jego nazwie użytkownika
    //char client_ip[INET_ADDRSTRLEN];
    //inet_ntop(AF_INET, &client_addresses[i].sin_addr, client_ip, INET_ADDRSTRLEN);
    //int client_port = ntohs(client_addresses[i].sin_port);

    // Obsługa wiadomości czatowych
    if (client_usernames[i]) {
        
        // Formatowanie wiadomości: [username]: <message>
        buffer[valread] = '\0';
        char message[BUFFER_SIZE + MAX_USERNAME_LEN + 8];
        snprintf(message, sizeof(message), "[%s]: %s", client_usernames[i], buffer);

        // Wyświetlenie na serwerze
        printf("%s", message);

        // Zapis do historii czatu (funkcja save_chat_message powinna być zaimplementowana w database.c)
        save_message(db, client_usernames[i], buffer);

        // Rozsyłanie do innych klientów
        for (int j = 0; j < MAX_CLIENTS; j++) {
            int dest_sd = client_sockets[j];
            if (dest_sd > 0 && dest_sd != sd) {
                send(dest_sd, message, strlen(message), 0);
            }
        }
    } else {
        // Jeśli klient nie jest zalogowany, wysyłamy komunikat o błędzie (to nie powinno się nigdy zdarzyć)
        send(sd, "USER NOT LOGGED IN\n", 14, 0);
    }  

    sqlite3_close(db);
}

// Główna pętla serwera - dodawanie aktywnych gniazd klientów i obsługa połączeń
void server_main_loop(int server_fd, const char *dbfile, const char *server_name) {
    
    // Tablica do przechowywania aktywnych gniazd klientów
    int client_sockets[MAX_CLIENTS] = {0};
    struct sockaddr_in client_addresses[MAX_CLIENTS];
    char buffer[BUFFER_SIZE];

    fd_set readfds;
    int max_sd, activity, new_socket;

    // Listen
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }

    // Zerowanie tablicy nazw klientów
    for (int i = 0; i < MAX_CLIENTS; i++) client_usernames[i] = NULL;

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
                    
                    // Konwersja portu klienta na liczbę całkowitą i wyświetlenie informacji o nowym oczekującym połączeniu
                    int client_port = ntohs(client_addr.sin_port);
                    printf("Incoming connection from %s:%d\n", client_ip, client_port);
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
                handle_client(i, sd, dbfile, server_name, client_sockets, client_addresses, buffer, valread);
            }
        }
    }
}

// Wątek rozgłaszania multicast
void* multicast_broadcast(void *arg) {
    struct thread_args *targs = (struct thread_args*)arg;
    char *server_name = targs->server_name;
    char *server_id = targs->server_id;
    int tcp_port = targs->tcp_port;
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
        snprintf(message, sizeof(message), "%s:%s:%s:%d", server_id, server_name, ip, tcp_port);

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

// Inicjalizacja gniazda TCP i uruchomienie serwera
void run_tcp_server(const char *dbfile, const char *server_name, char *server_id, int tcp_port) {
    int server_fd;
    struct sockaddr_in server_addr;
    int opt = 1;

    // Tworzenie gniazda
    // AF_INET - IPv4, SOCK_STREAM - TCP, 0 - domyślny protokół
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("TCP socket error");
        exit(EXIT_FAILURE);
    }

    // Ustawianie opcji gniazda
    // SO_REUSEADDR - pozwala na ponowne użycie adresu (przy restartach serwera)
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt error");
        exit(EXIT_FAILURE);
    }

    // Konfiguracja adresu serwera
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(tcp_port);

    // Bind - przypisanie gniazda do adresu i portu
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind error");
        exit(EXIT_FAILURE);
    }

    // Wyświetlenie kontrolnej informacji o otwarciu serwera
    printf("Server opened as %s [ID: %s] on port %d \n", server_name, server_id, tcp_port);

    // Uruchomienie głównej pętli serwera
    server_main_loop(server_fd, dbfile, server_name);

    // Sprzątanie końcowe: zamknięcie gniazda
    close(server_fd);
}


