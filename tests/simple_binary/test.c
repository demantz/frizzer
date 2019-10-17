#include<sys/socket.h> 
#include<netinet/in.h> 
#include<stdio.h> 
#include<string.h>
#include<stdlib.h> 
#include <arpa/inet.h>
#include <unistd.h>


void crash() {
    char a[10];
    strcpy(a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return;
}

void handleClient(char* buf) {
    if(buf[0]%5 == 1) {
        puts("--A--");
        if(buf[1]%6 == 1) {
            puts("--AB--");
            if(buf[2]%7 == 1) {
                puts("--ABC--");
                if(buf[3]%8 == 1) {
                    puts("--ABCD--");
                    if(buf[4]%9 == 1) {
                        puts("--ABCDE--");
                        if(buf[5]%10 == 1) {
                            puts("--ABCDEF--");
                            if(buf[6]%11 == 1) {
                                puts("--CRASH--");
                                crash();
                            }
                        }
                    }
                }
            }
        }
    }
    printf("%s",buf); 
}

int main(int argc, char** argv) {
    char buf[100]; 
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
        memset(buf, 0, 100);
        temp_sock_desc = accept(sock_desc,(struct sockaddr*)&client,&len);
        recv(temp_sock_desc,buf,100,0);
        handleClient(buf);
        close(temp_sock_desc); 
    }
    close(sock_desc); 
    return 0; 

}
