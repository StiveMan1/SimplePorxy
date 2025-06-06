#include "config.h"

#include "libconfig.h"

#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define packet_size 1024 * 1024
char buffer[packet_size];
char *config_file = "/etc/alisa_proxy/config.cfg";

void parse_args(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        if (argv[i][0] == '-' && strlen(argv[i]) == 2 && i + 1 < argc) {
            switch (argv[i][1]) {
                case 'f':
                    config_file = argv[i + 1];
                    break;
            }
        }
    }
}
struct proxy_client *new_client(socket_t cli_socket, socket_t des_socket) {
    struct proxy_client *client = calloc(1, sizeof(*client));
    client->cli_socket = cli_socket;
    client->des_socket = des_socket;
    return client;
}

void close_client(struct proxy_client *cli) {
    close(cli->cli_socket);
    close(cli->des_socket);
}

void proxy_clients_resize(struct clients_list *res, size_t size) {
    if (res->data == NULL && size) {
        res->mx_size = size;
        res->data = malloc(size * sizeof(struct proxy_client *));
        if (res->data != NULL) for (size_t i = 0; i < size + 1; i++) res->data[i] = NULL;
    } else if (res->mx_size < size) {
        res->data = realloc(res->data, size * 2 * sizeof(struct proxy_client *));
        if (res->data != NULL) for (size_t i = res->mx_size, l = size * 2; i < l + 1; i++) res->data[i] = NULL;
        res->mx_size = size * 2;
    }
    if (res->size > size)
        for (size_t i = size, l = res->size; i < l; i++) {
            close_client(res->data[i]);
            res->data[i] = NULL;
        }
    res->size = size;
}

void proxy_clients_add(struct clients_list *clients, struct proxy_client *cli) {
    proxy_clients_resize(clients, clients->size + 1);
    clients->data[clients->size - 1] = cli;
}

void proxy_clients_rem(struct clients_list *clients, struct proxy_client *cli) {
    size_t pos = 0, size = clients->size;
    for (; pos < size && cli != clients->data[pos]; pos++);
    if (pos == size) return;

    for (; pos < size - 1; pos++) clients->data[pos] = clients->data[pos + 1];
    clients->data[size] = cli;
    proxy_clients_resize(clients, size - 1);
}

struct proxy_client *proxy_clients_find(struct clients_list *clients, int fd) {
    for (size_t pos = 0, size = clients->size; pos < size; pos++) {
        if (clients->data[pos]->cli_socket == fd) return clients->data[pos];
        if (clients->data[pos]->des_socket == fd) return clients->data[pos];
    }
    return NULL;
}

void server_close(struct proxy_server *serv) {
    if (serv->socket >= 0)
        close(serv->socket);
    if (serv->epoll >= 0)
        close(serv->epoll);

    serv->socket = -1;
    serv->epoll = -1;

    proxy_clients_resize(&serv->clients, 0);
}

int server_open(struct proxy_server *serv) {
    serv->epoll = epoll_create(1);
    serv->socket = socket(serv->config.domain, serv->config.service, serv->config.protocol);

    int option = 1;
    setsockopt(serv->socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    struct epoll_event ev = {EPOLLIN, {.fd = serv->socket}};
    struct sockaddr_in server_address = {serv->config.domain, htons(serv->config.port),
                                         {serv->config.interface}};

    if (bind(serv->socket, (struct sockaddr *) &server_address, sizeof(server_address)) != 0) goto bad_end;
    if ((listen(serv->socket, 128)) < 0) goto bad_end;
    if (epoll_ctl(serv->epoll, EPOLL_CTL_ADD, serv->socket, &ev) == -1) goto bad_end;
    return 0;

    bad_end:
    close(serv->socket);
    serv->socket = -1;
    return -1;
}


socket_t destination_socket(struct proxy_server *serv) {
    socket_t sock = socket(serv->config.domain, serv->config.service, serv->config.protocol);

    struct sockaddr_in server_address = {serv->config.domain, htons(serv->config.dest_port)};
    inet_pton(serv->config.domain, serv->config.dest_server, &server_address.sin_addr);
    int _con = connect(sock, (struct sockaddr *) &server_address, sizeof(server_address));
    return (_con == 0) ? sock : -1;
}

ssize_t do_client(struct proxy_client *cli, socket_t fd) {
    socket_t to_fd = (cli->cli_socket == fd) ? cli->des_socket : cli->cli_socket;
    ssize_t size = packet_size, x = 1;
    for (; size == packet_size && x > 0;) {
        size = recv(fd, buffer, size, 0);
        for (ssize_t snd = 0; snd < size && (x = send(to_fd, buffer + snd, size - snd, 0)) > 0; snd += x);
    }
    return (size < x) ? size : x;
}

void *do_server(void *arg) {
    struct proxy_server *server = arg;
    struct epoll_event ev;
    struct proxy_client *cli;
    socket_t nfds, cli_socket, des_socket;

    server_open(server);
    while (server->socket != -1) {
        nfds = epoll_wait(server->epoll, &ev, 1, -1);
        if (nfds <= 0) continue;

        if (ev.data.fd == server->socket) {
            cli_socket = accept(server->socket, NULL, NULL);
            des_socket = destination_socket(server);

            if (cli_socket == -1 || des_socket == -1) {
                if (cli_socket != -1) close(cli_socket);
                if (des_socket != -1) close(des_socket);
                continue;
            }

            ev = (struct epoll_event) {EPOLLIN, {.fd = cli_socket}};
            epoll_ctl(server->epoll, EPOLL_CTL_ADD, cli_socket, &ev);
            ev = (struct epoll_event) {EPOLLIN, {.fd = des_socket}};
            epoll_ctl(server->epoll, EPOLL_CTL_ADD, des_socket, &ev);

            proxy_clients_add(&server->clients, new_client(cli_socket, des_socket));
        } else {
            cli = proxy_clients_find(&server->clients, ev.data.fd);
            if (cli == NULL || do_client(cli, ev.data.fd) != 0) continue;

            epoll_ctl(server->epoll, EPOLL_CTL_DEL, cli->cli_socket, NULL);
            epoll_ctl(server->epoll, EPOLL_CTL_DEL, cli->des_socket, NULL);
            proxy_clients_rem(&server->clients, cli);
        }
    }
    return NULL;
}


struct proxy_server *parse_server(config_setting_t *proxy) {
    struct proxy_server *serv = calloc(1, sizeof(*serv));
    memset(serv, 0, sizeof(*serv));
    serv->socket = -1;
    serv->epoll = -1;

    config_setting_lookup_int(proxy, "domain", &serv->config.domain);
    config_setting_lookup_int(proxy, "service", &serv->config.service);
    config_setting_lookup_int(proxy, "protocol", &serv->config.protocol);
    config_setting_lookup_int(proxy, "interface", &serv->config.interface);
    config_setting_lookup_int(proxy, "port", &serv->config.port);

    config_setting_t *destination = config_setting_lookup(proxy, "destination");
    config_setting_lookup_string(destination, "address", &serv->config.dest_server);
    config_setting_lookup_int(destination, "port", &serv->config.dest_port);
    return serv;
}

void start_new_server(struct list_threads *threads, struct proxy_server *serv) {
    struct list_threads_elm *elm = malloc(sizeof(*elm));
    *elm = (struct list_threads_elm){0, serv, NULL};
    pthread_create(&elm->thread, NULL, do_server, serv);

    if (threads->first == NULL) threads->first = elm;
    else threads->last->next = elm;
    threads->last = elm;
}

void join_thread_list(struct list_threads *threads) {
    for (struct list_threads_elm *elm = threads->first, *next; elm != NULL; ) {
        pthread_join(elm->thread, NULL);
        next = elm->next;
        free(elm->serv);
        free(elm);
        elm = next;
    }
}

int main(int argc, char **argv) {
    parse_args(argc - 1, argv + 1);

    struct list_threads threads = {NULL};
    config_setting_t *setting, *proxy;
    config_t cfg;

    config_init(&cfg);
    if (!config_read_file(&cfg, config_file)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return (EXIT_FAILURE);
    }

    setting = config_lookup(&cfg, "proxy_servers");
    int count = config_setting_length(setting);
    printf("Length : %d\n", count);

    for (int i = 0; i < count; i++)
        start_new_server(&threads, parse_server(config_setting_get_elem(setting, i)));
    join_thread_list(&threads);
}

