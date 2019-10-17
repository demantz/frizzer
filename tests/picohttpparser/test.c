#include<sys/socket.h> 
#include<netinet/in.h> 
#include<stdio.h> 
#include<string.h>
#include<stdlib.h> 
#include <arpa/inet.h>
#include <unistd.h>

#include"picohttpparser.h"


void crash() {
    char a[10];
    strcpy(a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return;
}

void handleClient(char* buf) {
    char *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    ssize_t rret;
    printf("buf: %s\n", buf);

    buflen = strlen(buf);
    prevbuflen = buflen;
    num_headers = sizeof(headers) / sizeof(headers[0]);
    pret = phr_parse_request(buf, buflen, &method, &method_len, &path, &path_len,
                             &minor_version, headers, &num_headers, prevbuflen);
    printf("method=%s path=%s minor_version=%d num_headers=%d\n", method, path, minor_version, num_headers);
}

int main(int argc, char** argv) {
    char buf[1000]; 
    socklen_t len; 
    int sock_desc,temp_sock_desc; 
    struct sockaddr_in client,server; 
    memset(&client,0,sizeof(client)); 
    memset(&server,0,sizeof(server)); 
    sock_desc = socket(AF_INET,SOCK_STREAM,0); 
    server.sin_family = AF_INET; server.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    server.sin_port = htons(7777); 
    bind(sock_desc,(struct sockaddr*)&server,sizeof(server)); 
    listen(sock_desc,20); len = sizeof(client);
    while(1)
    {
        temp_sock_desc = -1;
        memset(buf, 0, 1000);
        temp_sock_desc = accept(sock_desc,(struct sockaddr*)&client,&len);
        recv(temp_sock_desc,buf,1000,0);
        handleClient(buf);
        close(temp_sock_desc); 
    }
    close(sock_desc); 
    return 0; 

}
