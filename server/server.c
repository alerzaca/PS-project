#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define TCP_PORT 8080               // Port TCP, na którym serwer będzie obsługiwał chat
#define MULTICAST_PORT 12345        // Port UDP multicast, na którym serwer będzie się ogłaszał
#define MULTICAST_GROUP "239.0.0.1" // Adres grupy multicast, na której serwer będzie się ogłaszał
#define ROOM_NAME "Chatroom"         // Nazwa pokoju czatu, docelowo będzie podawana jako argument wywołania programu serwera

#define BACKLOG 3                   // Maksymalna liczba oczekujących połączeń
#define MAX_CLIENTS 10              // Maksymalna liczba jednocześnie połączonych klientów

void multicast_broadcast(void *arg) {
    int sock;
    struct sockaddr_in addr;
    char message[256];

    // Przygotowanie wiadomości o serwerze do rozgłoszenia
    char ip[INET_ADDRSTRLEN];
    struct in_addr local_addr;
    local_addr.s_addr = htonl(INADDR_ANY); // dodać tu rzeczywisty adres IP serwera
    inet_ntop(AF_INET, &local_addr, ip, INET_ADDRSTRLEN);
    sprintf(message, "Room %s is online on address %s:%d", ROOM_NAME, ip, TCP_PORT);

    // Tworzenie gniazda UDP
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket error");
        exit(EXIT_FAILURE);
    }

    // Konfiguracja adresu multicast
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
    addr.sin_port = htons(MULTICAST_PORT);

    // Rozgłaszanie informacji o serwerze co 5 sekund
    while(1) {
        if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("sendto error");
            close(sock);
            exit(EXIT_FAILURE);
        }
        printf("Broadcasting message: \'%s\'\n", message);
        sleep(5);
    }

    close(sock);
    exit(EXIT_SUCCESS);
}

int main() {
    int server_fd, new_socket;              // deskryptory gniazd: serwer i klient
    int activity, i, valread, sd;           // zmienne do obsługi aktywności gniazd
    struct sockaddr_in address;             // struktura przechowująca adres IP i port
    int opt = 1;                            // wartość do ustawienia opcji gniazda
    int addrlen = sizeof(address);          // długość struktury adresu
    char buffer[1024] = {0};                // bufor do przechowywania odebranych danych
    int client_socket[MAX_CLIENTS] = {0};   // tablica do przechowywania deskryptorów gniazd klientów

    fd_set readfds;     // zbiór deskryptorów gniazd do monitorowania przez select

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
    memset(&address, 0, sizeof(address));   // zerowanie struktury adresu na wszelki wypadek
    address.sin_family = AF_INET;           // rodzina adresów IPv4
    address.sin_addr.s_addr = INADDR_ANY;   // akceptowanie połączeń na dowolnym interfejsie
    address.sin_port = htons(PORT);         // port w formacie sieciowym (big-endian)

    // Bind - przypisanie gniazda do adresu i portu
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind error");
        exit(EXIT_FAILURE);
    }

    // Uruchomienie wątku do rozgłaszania informacji o serwerze
    pthread_t multicast_thread;

    if (pthread_create(&multicast_thread, NULL, (void *)multicast_broadcast, NULL) != 0) {
        perror("pthread_create error");
        exit(EXIT_FAILURE);
    }

    // Listen - nasłuchiwanie na połączenia przychodzące
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }

    printf("Chatroom opened on address %s and port %d\n", inet_ntoa(address.sin_addr), PORT);

    // Główna pętla serwera
    while(1) {
        FD_ZERO(&readfds);            // zerowanie zbioru deskryptorów
        FD_SET(server_fd, &readfds);  // dodanie gniazda serwera do zbioru do monitorowania
        int max_sd = server_fd;       // maksymalny deskryptor gniazda, początkowo serwer

        // Dodanie deskryptorów klientów do monitorowego zbioru
        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;       // aktualizacja maksymalnego deskryptora
        }

        // Czekanie na aktywność w którymkolwiek z gniazd (operacja blokująca)
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            perror("select error");
        }

        // Aktywność na gnieździe serwera oznacza nowe połączenie
        // FD_ISSET sprawdza, czy deskryptor gniazda serwera jest gotowy do odczytu, jeśli tak, to akceptujemy to połączenie
        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept error");
                exit(EXIT_FAILURE);
            }

            printf("New connection from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            // Dodanie nowego klienta do tablicy deskryptorów
            for (i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    printf("Client added on index %d\n", i);
                    break;
                }
            }
        }

        // Obsługa aktywnych klientów
        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];

            if (FD_ISSET(sd, &readfds)) {
                
                // Odbieranie danych od klienta
                if((valread = read(sd, buffer, sizeof(buffer))) == 0) {
                    
                    // Połączenie zamknięte przez klienta
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    printf("Connection closed on %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                   
                    close(sd);                  // zamknięcie gniazda klienta
                    client_socket[i] = 0;       // usunięcie klienta z tablicy
               
                } else {
                    
                    // Dane odebrano pomyślnie
                    buffer[valread] = '\0';     // zakończenie ciągu znaków
                    printf("Data from %d: \'%s\'\n", sd, buffer);

                    // Podanie wiadomości dalej do wszystkich klientów z wyjątkiem nadawcy
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (client_socket[j] > 0 && client_socket[j] != sd) {
                            send(client_socket[j], buffer, strlen(buffer), 0);
                        }
                    }
                }
            }

        }
    }

    pthread_join(multicast_thread, NULL);
    return 0;
}
