#ifndef FILETRANSFER_H
#define FILETRANSFER_H

int login_to_file_server(int sock, char *username, char *password, char *buffer);
int upload_file(int sock, const char *filename, char *buffer);
int download_file(int sock, const char *filename, char *buffer);

#endif
