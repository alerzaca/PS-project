# Makefile dla clienta
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LIBS = -lssl -lcrypto

# Pliki źródłowe
SRC = src/main.c \
      src/credentials.c \
      src/filetransfer.c \
      src/network.c

# Plik wynikowy
TARGET = client

# Domyślna reguła kompilacji programu
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Czyszczenie plików wynikowych
clean:
	rm -f $(TARGET)
