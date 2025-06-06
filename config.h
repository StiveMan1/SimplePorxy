#ifndef ALISA_PROXY_CONFIG_H
#define ALISA_PROXY_CONFIG_H

#include "unistd.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "pthread.h"

#define socket_t int


struct proxy_server {
    socket_t socket;
    socket_t epoll;

    struct clients_list {
        struct proxy_client **data;
        size_t mx_size;
        size_t size;
    } clients;

    struct proxy_config {
        int domain; // AF_INET
        int service; // SOCK_STREAM
        int protocol; // IPPROTO_TCP
        int interface; // INADDR_ANY
        int port;

        const char *dest_server;
        int dest_port;
    } config;
};


struct proxy_client {
    socket_t cli_socket;
    socket_t des_socket;
};

struct list_threads {
    struct list_threads_elm {
        pthread_t thread;
        struct proxy_server *serv;
        struct list_threads_elm *next;
    } *first, *last;
};

extern volatile int running;


#endif //ALISA_PROXY_CONFIG_H
