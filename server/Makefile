# Makefile dla serwera
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LIBS = -lpthread -lsqlite3

# Pliki źródłowe
SRC = src/main.c \
      src/utils.c \
      src/database.c \
      src/network.c

# Plik wynikowy
TARGET = server

# Domyślna reguła kompilacji programu
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Czyszczenie plików wynikowych
clean:
	rm -f $(TARGET)