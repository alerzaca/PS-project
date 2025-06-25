#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>

#include "utils.h"
#include "database.h"
#include "network.h"

#define SERVER_NAME_MAX 128
#define DBFILE_MAX 256

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "create") == 0) {
        char server_name[SERVER_NAME_MAX] = "";
        strncpy(server_name, argv[2], sizeof(server_name)-1);

        char dbfile[DBFILE_MAX];
        struct stat st = {0};
        if (stat("database", &st) == -1) {
            mkdir("database", 0755);
        }
        snprintf(dbfile, sizeof(dbfile), "database/%s.db", server_name);

        // Utworzenie bazy danych i tabeli serwera
        create_database(dbfile, server_name);
    }

    else if (argc == 5 && strcmp(argv[1], "start") == 0) {
        char server_name[SERVER_NAME_MAX] = "";
        strncpy(server_name, argv[2], sizeof(server_name)-1);

        char *ifname = argv[3];
        char ip[INET_ADDRSTRLEN] = "0.0.0.0";
        
        // Sprawdzenie, czy port jest poprawny
        // Ewentualnie dodać: jeśli nie podano portu, wybierany jest domyślny port TCP_PORT = 8080
        int tcp_port = atoi(argv[4]);
        if (tcp_port <= 0 || tcp_port > 65535) {
            fprintf(stderr, "Invalid TCP port number: %d. It should be between 1 and 65535.\n", tcp_port);
            exit(1);
        }

        char dbfile[DBFILE_MAX];
        snprintf(dbfile, sizeof(dbfile), "database/%s.db", server_name);

        // Pobieranie informacji o serwerze z bazy danych
        char server_id[SERVER_ID_LEN] = "";
        char created[32] = "";
        if (get_server_info(dbfile, server_id, created) != 0) {
            fprintf(stderr, "get info from fatabase error\n");
            exit(1);
        }

        // Przygotowanie folderu wspłdzielonego
        ensure_shared_folders(server_name);

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
        targs->tcp_port = tcp_port;

        // Uruchomienie nowego wątku multicast
        pthread_t multicast_thread;
        if (pthread_create(&multicast_thread, NULL, multicast_broadcast, targs) != 0) {
            perror("pthread_create error");
            free(targs);
            return 1;
        }

        // Uruchomienie serwera TCP
        run_tcp_server(dbfile, server_name, server_id, tcp_port);

        // Po zakończeniu działania serwera, zamknięcie wątku multicast i bazy danych
        pthread_cancel(multicast_thread);
        pthread_join(multicast_thread, NULL);
        
        free(targs);
        return 0;
    }

    else {
        printf("Usage:\n");
        printf("  %s create <name>\n", argv[0]);
        printf("  %s start <name> <interface> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 
}
