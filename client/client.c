#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TCP_PORT 8080               // Port TCP, na którym serwer będzie obsługiwał chat
#define MULTICAST_PORT 12345        // Port UDP multicast, na którym serwer będzie się ogłaszał
#define MULTICAST_GROUP "239.0.0.1" // Adres grupy multicast, na której serwer będzie się ogłaszał

#define MAX_ROOMS 10                // Maksymalna liczba buforowanych pokoi czatu
#define BUFFER_SIZE 1024            // Rozmiar bufora do odbierania wiadomości

struct room {
    char name[50];                  // Nazwa pokoju
    char address[INET_ADDRSTRLEN];  // Adres IP serwera czatu
    int port;                       // Port serwera czatu
};

int room_count = 0;                // Liczba pokoi czatu

void listen_for_rooms() {}

void connect_to_room() {}

void chat_in_room() {}

int main() {
    listen_for_rooms();
    int room_id = choose_room();
    if (room_id >= 0) {
        chat_with_room(room_id);
    }
    return 0;
}
