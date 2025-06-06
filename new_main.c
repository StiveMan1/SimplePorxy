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
#include <errno.h> // For errno
#include <signal.h> // For signal handling

#define packet_size 1024 * 1024
char buffer[packet_size];
char *config_file = "/etc/simple-proxy/config.cfg";

// Global flag for graceful shutdown
volatile int running = 1;

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

// Signal handler for graceful shutdown
void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        fprintf(stderr, "Received signal %d. Initiating graceful shutdown...\n", signo);
        running = 0; // Set the global flag to stop loops
    }
}

struct proxy_client *new_client(socket_t cli_socket, socket_t des_socket) {
    struct proxy_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        perror("Failed to allocate new proxy_client");
        return NULL;
    }
    client->cli_socket = cli_socket;
    client->des_socket = des_socket;
    return client;
}

void close_client(struct proxy_client *cli) {
    if (cli == NULL) return;
    if (cli->cli_socket >= 0) {
        close(cli->cli_socket);
        cli->cli_socket = -1; // Invalidate socket
    }
    if (cli->des_socket >= 0) {
        close(cli->des_socket);
        cli->des_socket = -1; // Invalidate socket
    }
    // Free the client structure
    free(cli);
}

void proxy_clients_resize(struct clients_list *res, size_t size) {
    if (res->data == NULL && size > 0) {
        res->mx_size = size;
        res->data = malloc(size * sizeof(struct proxy_client *));
        if (res->data == NULL) {
            perror("Failed to allocate clients_list data");
            res->mx_size = 0;
            res->size = 0;
            return;
        }
        for (size_t i = 0; i < size; i++) res->data[i] = NULL; // Initialize new elements
    } else if (res->mx_size < size) {
        // Resize to a larger capacity (e.g., double)
        size_t new_mx_size = size * 2;
        if (new_mx_size < size) new_mx_size = size; // Handle potential overflow if size is very large
        struct proxy_client **new_data = realloc(res->data, new_mx_size * sizeof(struct proxy_client *));
        if (new_data == NULL) {
            perror("Failed to reallocate clients_list data");
            // If realloc fails, we keep the old data and size, cannot resize
            return;
        }
        res->data = new_data;
        for (size_t i = res->mx_size; i < new_mx_size; i++) res->data[i] = NULL; // Initialize new elements
        res->mx_size = new_mx_size;
    }

    if (res->size > size) {
        // If shrinking, free excess clients
        for (size_t i = size; i < res->size; i++) {
            close_client(res->data[i]); // Frees the client struct and closes sockets
            res->data[i] = NULL;
        }
    }
    res->size = size;
}

void proxy_clients_add(struct clients_list *clients, struct proxy_client *cli) {
    if (cli == NULL) return;
    proxy_clients_resize(clients, clients->size + 1);
    if (clients->data != NULL && clients->size > 0) {
        clients->data[clients->size - 1] = cli;
    } else {
        // If resize failed, clean up the client
        close_client(cli);
    }
}

void proxy_clients_rem(struct clients_list *clients, struct proxy_client *cli) {
    if (cli == NULL) return;

    size_t pos = 0;
    size_t current_size = clients->size;

    for (; pos < current_size && cli != clients->data[pos]; pos++);

    if (pos == current_size) { // Client not found
        return;
    }

    // Shift elements to the left to fill the gap
    for (size_t i = pos; i < current_size - 1; i++) {
        clients->data[i] = clients->data[i + 1];
    }
    clients->data[current_size - 1] = NULL; // Clear the last element position

    // Close and free the client that was removed
    close_client(cli);

    // Shrink the list
    proxy_clients_resize(clients, current_size - 1);
}

struct proxy_client *proxy_clients_find(struct clients_list *clients, int fd) {
    for (size_t pos = 0, size = clients->size; pos < size; pos++) {
        if (clients->data[pos] == NULL) continue; // Skip NULL entries
        if (clients->data[pos]->cli_socket == fd) return clients->data[pos];
        if (clients->data[pos]->des_socket == fd) return clients->data[pos];
    }
    return NULL;
}

void server_close(struct proxy_server *serv) {
    if (serv == NULL) return;

    if (serv->socket >= 0) {
        close(serv->socket);
        serv->socket = -1; // Invalidate socket
    }
    if (serv->epoll >= 0) {
        close(serv->epoll);
        serv->epoll = -1; // Invalidate epoll fd
    }

    // Close and free all associated clients
    proxy_clients_resize(&serv->clients, 0); // This will free all clients
    if (serv->clients.data != NULL) {
        free(serv->clients.data);
        serv->clients.data = NULL;
    }
}

int server_open(struct proxy_server *serv) {
    serv->epoll = epoll_create1(0); // Using epoll_create1 for flags, 0 for default
    if (serv->epoll == -1) {
        perror("epoll_create1 failed");
        return -1;
    }

    serv->socket = socket(serv->config.domain, serv->config.service, serv->config.protocol);
    if (serv->socket == -1) {
        perror("socket creation failed");
        close(serv->epoll);
        serv->epoll = -1;
        return -1;
    }

    int option = 1;
    // Set SO_REUSEADDR to allow immediate reuse of port
    if (setsockopt(serv->socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1) {
        perror("setsockopt SO_REUSEADDR failed");
        server_close(serv);
        return -1;
    }

    struct epoll_event ev = {EPOLLIN | EPOLLET, {.fd = serv->socket}}; // Use EPOLLET for edge-triggered
    struct sockaddr_in server_address = {0}; // Initialize to zero
    server_address.sin_family = serv->config.domain;
    server_address.sin_port = htons(serv->config.port);
    server_address.sin_addr.s_addr = htonl(serv->config.interface); // INADDR_ANY is 0.0.0.0, use htonl for network byte order

    if (bind(serv->socket, (struct sockaddr *) &server_address, sizeof(server_address)) != 0) {
        perror("bind failed");
        server_close(serv);
        return -1;
    }
    if ((listen(serv->socket, 128)) < 0) {
        perror("listen failed");
        server_close(serv);
        return -1;
    }
    if (epoll_ctl(serv->epoll, EPOLL_CTL_ADD, serv->socket, &ev) == -1) {
        perror("epoll_ctl add server socket failed");
        server_close(serv);
        return -1;
    }
    return 0;
}


socket_t destination_socket(struct proxy_server *serv) {
    socket_t sock = socket(serv->config.domain, serv->config.service, serv->config.protocol);
    if (sock == -1) {
        perror("destination socket creation failed");
        return -1;
    }

    struct sockaddr_in server_address = {0}; // Initialize to zero
    server_address.sin_family = serv->config.domain;
    server_address.sin_port = htons(serv->config.dest_port);
    // Use inet_pton to convert string IP to network address
    if (inet_pton(serv->config.domain, serv->config.dest_server, &server_address.sin_addr) <= 0) {
        perror("inet_pton failed for destination address");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *) &server_address, sizeof(server_address)) != 0) {
        perror("connect to destination failed");
        close(sock);
        return -1;
    }
    return sock;
}

// Returns 0 on success (bytes transferred), -1 on error or connection closed
ssize_t do_client(struct proxy_client *cli, socket_t fd, socket_t epoll_fd, struct clients_list *clients) {
    socket_t to_fd = (cli->cli_socket == fd) ? cli->des_socket : cli->cli_socket;
    ssize_t bytes_received;
    ssize_t bytes_sent_total = 0; // Track total bytes sent in this session

    while (1) {
        bytes_received = recv(fd, buffer, packet_size, 0);

        if (bytes_received == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No more data to read for now, but not an error
                return 0; // Indicate no fatal error, just stop reading for this event
            }
            perror("recv failed");
            return -1; // Indicate a fatal error
        }
        if (bytes_received == 0) {
            // Connection closed by peer
            return -1; // Indicate connection closed
        }

        ssize_t current_send_pos = 0;
        while (current_send_pos < bytes_received) {
            ssize_t bytes_sent = send(to_fd, buffer + current_send_pos, bytes_received - current_send_pos, 0);
            if (bytes_sent == -1) {
                perror("send failed");
                return -1; // Indicate a fatal error
            }
            if (bytes_sent == 0) {
                // Should not happen for blocking sockets unless connection is truly gone
                fprintf(stderr, "send returned 0 bytes, connection likely closed.\n");
                return -1;
            }
            current_send_pos += bytes_sent;
            bytes_sent_total += bytes_sent;
        }

        // If less than packet_size was received, there's likely no more data immediately available
        if (bytes_received < packet_size) {
            break;
        }
    }
    return bytes_sent_total; // Return total bytes forwarded
}

void *do_server(void *arg) {
    struct proxy_server *server = arg;
    struct epoll_event ev_list[2]; // Max 2 events per wait (client and destination)
    struct proxy_client *cli;
    int nfds;

    if (server_open(server) == -1) {
        fprintf(stderr, "Failed to open server on port %d. Exiting thread.\n", server->config.port);
        // It's crucial for the main thread to clean up `serv` struct after join.
        // For now, server_close was called internally by server_open on failure.
        return NULL;
    }

    fprintf(stderr, "Proxy server listening on port %d, forwarding to %s:%d\n",
            server->config.port, server->config.dest_server, server->config.dest_port);

    while (running && server->socket != -1) { // Check global running flag and server socket status
        nfds = epoll_wait(server->epoll, ev_list, sizeof(ev_list) / sizeof(ev_list[0]), -1);

        if (nfds == -1) {
            if (errno == EINTR) { // Interrupted by a signal (e.g., SIGTERM)
                continue; // Loop again, will check 'running' flag
            }
            perror("epoll_wait failed");
            break; // Fatal error, exit loop
        }

        for (int i = 0; i < nfds; ++i) {
            if (ev_list[i].data.fd == server->socket) {
                // New incoming connection on the listening socket
                socket_t cli_socket = accept(server->socket, NULL, NULL);
                if (cli_socket == -1) {
                    perror("accept failed");
                    continue;
                }

                socket_t des_socket = destination_socket(server);
                if (des_socket == -1) {
                    fprintf(stderr, "Failed to connect to destination for new client. Closing client socket.\n");
                    close(cli_socket);
                    continue;
                }

                // Make sockets non-blocking for epoll ET mode (recommended)
                int flags = fcntl(cli_socket, F_GETFL, 0);
                fcntl(cli_socket, F_SETFL, flags | O_NONBLOCK);
                flags = fcntl(des_socket, F_GETFL, 0);
                fcntl(des_socket, F_SETFL, flags | O_NONBLOCK);


                struct proxy_client *new_pclient = new_client(cli_socket, des_socket);
                if (new_pclient == NULL) {
                    close(cli_socket);
                    close(des_socket);
                    continue;
                }
                proxy_clients_add(&server->clients, new_pclient);

                struct epoll_event ev_cli = {EPOLLIN | EPOLLET, {.fd = cli_socket}};
                if (epoll_ctl(server->epoll, EPOLL_CTL_ADD, cli_socket, &ev_cli) == -1) {
                    perror("epoll_ctl add cli_socket failed");
                    proxy_clients_rem(&server->clients, new_pclient); // Clean up
                    continue;
                }

                struct epoll_event ev_des = {EPOLLIN | EPOLLET, {.fd = des_socket}};
                if (epoll_ctl(server->epoll, EPOLL_CTL_ADD, des_socket, &ev_des) == -1) {
                    perror("epoll_ctl add des_socket failed");
                    // Need to remove cli_socket from epoll first, then remove client
                    epoll_ctl(server->epoll, EPOLL_CTL_DEL, cli_socket, NULL);
                    proxy_clients_rem(&server->clients, new_pclient); // Clean up
                    continue;
                }
            } else {
                // Data on an existing client or destination socket
                cli = proxy_clients_find(&server->clients, ev_list[i].data.fd);
                if (cli == NULL) {
                    fprintf(stderr, "Error: Client for fd %d not found, possibly already closed or invalid.\n", ev_list[i].data.fd);
                    // Attempt to remove from epoll to clean up dangling FD
                    epoll_ctl(server->epoll, EPOLL_CTL_DEL, ev_list[i].data.fd, NULL);
                    close(ev_list[i].data.fd); // Close the dangling fd
                    continue;
                }

                if (do_client(cli, ev_list[i].data.fd, server->epoll, &server->clients) == -1) {
                    // Connection closed or error occurred, remove client
                    fprintf(stderr, "Connection on FD %d closed or error. Removing client.\n", ev_list[i].data.fd);
                    if (epoll_ctl(server->epoll, EPOLL_CTL_DEL, cli->cli_socket, NULL) == -1) {
                        perror("epoll_ctl DEL cli_socket failed");
                    }
                    if (epoll_ctl(server->epoll, EPOLL_CTL_DEL, cli->des_socket, NULL) == -1) {
                        perror("epoll_ctl DEL des_socket failed");
                    }
                    proxy_clients_rem(&server->clients, cli); // This frees cli
                }
            }
        }
    }
    // Loop exited, clean up server resources
    fprintf(stderr, "Proxy server on port %d shutting down.\n", server->config.port);
    server_close(server); // Close server socket and epoll fd
    return NULL;
}


struct proxy_server *parse_server(config_setting_t *proxy) {
    struct proxy_server *serv = calloc(1, sizeof(*serv));
    if (serv == NULL) {
        perror("Failed to allocate proxy_server");
        return NULL;
    }
    memset(serv, 0, sizeof(*serv)); // Initialize all members to 0
    serv->socket = -1;
    serv->epoll = -1;

    // Default values in case they are not found in config
    serv->config.domain = AF_INET;
    serv->config.service = SOCK_STREAM;
    serv->config.protocol = IPPROTO_TCP;
    serv->config.interface = INADDR_ANY; // 0.0.0.0

    if (!config_setting_lookup_int(proxy, "domain", &serv->config.domain)) {
        fprintf(stderr, "Warning: 'domain' not found in config, using default AF_INET.\n");
    }
    if (!config_setting_lookup_int(proxy, "service", &serv->config.service)) {
        fprintf(stderr, "Warning: 'service' not found in config, using default SOCK_STREAM.\n");
    }
    if (!config_setting_lookup_int(proxy, "protocol", &serv->config.protocol)) {
        fprintf(stderr, "Warning: 'protocol' not found in config, using default IPPROTO_TCP.\n");
    }
    if (!config_setting_lookup_int(proxy, "interface", &serv->config.interface)) {
        fprintf(stderr, "Warning: 'interface' not found in config, using default INADDR_ANY.\n");
    }
    if (!config_setting_lookup_int(proxy, "prot", &serv->config.port)) { // Note: 'prot' in config.cfg, 'port' in struct
        fprintf(stderr, "Error: 'prot' (port) not found in config.\n");
        free(serv);
        return NULL;
    }

    config_setting_t *destination = config_setting_lookup(proxy, "destination");
    if (destination == NULL) {
        fprintf(stderr, "Error: 'destination' section not found in config.\n");
        free(serv);
        return NULL;
    }

    if (!config_setting_lookup_string(destination, "address", &serv->config.dest_server)) {
        fprintf(stderr, "Error: 'destination.address' not found in config.\n");
        free(serv);
        return NULL;
    }
    if (!config_setting_lookup_int(destination, "port", &serv->config.dest_port)) {
        fprintf(stderr, "Error: 'destination.port' not found in config.\n");
        free(serv);
        return NULL;
    }
    return serv;
}

void start_new_server(struct list_threads *threads, struct proxy_server *serv) {
    if (serv == NULL) return;

    struct list_threads_elm *elm = malloc(sizeof(*elm));
    if (elm == NULL) {
        perror("Failed to allocate list_threads_elm");
        server_close(serv); // Clean up the server struct if element allocation fails
        free(serv);
        return;
    }
    *elm = (struct list_threads_elm){0, serv, NULL};
    int ret = pthread_create(&elm->thread, NULL, do_server, serv);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed: %s\n", strerror(ret));
        free(elm);
        server_close(serv); // Clean up the server struct if thread creation fails
        free(serv);
        return;
    }

    if (threads->first == NULL) {
        threads->first = elm;
    } else {
        threads->last->next = elm;
    }
    threads->last = elm;
}

void join_thread_list(struct list_threads *threads) {
    for (struct list_threads_elm *elm = threads->first, *next; elm != NULL; ) {
        pthread_join(elm->thread, NULL); // Wait for thread to finish
        next = elm->next;
        // The serv struct is freed by server_close() inside do_server() when the thread exits.
        // However, if the server_open() failed, it's freed in start_new_server().
        // So, we only free the elm here.
        free(elm);
        elm = next;
    }
    threads->first = NULL;
    threads->last = NULL;
}

int main(int argc, char **argv) {
    parse_args(argc - 1, argv + 1);

    // Register signal handler for graceful shutdown
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        perror("Failed to register SIGINT handler");
        return EXIT_FAILURE;
    }
    if (signal(SIGTERM, sig_handler) == SIG_ERR) {
        perror("Failed to register SIGTERM handler");
        return EXIT_FAILURE;
    }

    struct list_threads threads = {NULL, NULL}; // Initialize to NULL
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
    if (setting == NULL) {
        fprintf(stderr, "Error: 'proxy_servers' section not found in config.\n");
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    int count = config_setting_length(setting);
    if (count == 0) {
        fprintf(stderr, "No proxy servers defined in config.\n");
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }
    printf("Found %d proxy server(s) in config.\n", count);

    for (int i = 0; i < count; i++) {
        proxy = config_setting_get_elem(setting, i);
        if (proxy == NULL) {
            fprintf(stderr, "Error: Could not get proxy server element at index %d.\n", i);
            continue;
        }
        struct proxy_server *serv = parse_server(proxy);
        if (serv != NULL) {
            start_new_server(&threads, serv);
        } else {
            fprintf(stderr, "Failed to parse server configuration for element %d.\n", i);
        }
    }

    join_thread_list(&threads); // Wait for all proxy threads to finish

    config_destroy(&cfg); // Clean up libconfig resources
    fprintf(stderr, "All proxy threads terminated. Simple-proxy exiting.\n");
    return EXIT_SUCCESS;
}