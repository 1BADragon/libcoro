#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <coro.h>
#include <list.h>

struct server_arg {
    uint16_t port;
};

struct client {
    struct list_head node;
    int client_sock;
    struct coro_task *task;
    struct sockaddr_in addr;
    struct list_head *client_list;
};

static void fd_close(enum coro_exit_how how, void *arg)
{
    (void)how;
    close(*(int *)arg);
}

static void *accepting_task(void *args)
{
    int new_client;
    struct sockaddr_in new_addr = {0};
    struct server_arg *servargs = args;
    struct client *client;
    socklen_t addr_len;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sock) {
        return NULL;
    }

    coro_register_cleanup(NULL, &fd_close, &sock);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    new_addr.sin_family = AF_INET;
    new_addr.sin_addr.s_addr = INADDR_ANY;
    new_addr.sin_port = htons(servargs->port);

    if (bind(sock, (struct sockaddr *)&new_addr, sizeof(struct sockaddr_in))) {
        return NULL;
    }

    if (listen(sock, 10)) {
        return NULL;
    }

    for (;;) {
        addr_len = sizeof(new_addr);
        new_client = coro_accept(sock, (struct sockaddr *)&new_addr, &addr_len);

        if (-1 == new_client) {
            break;
        }

        client = malloc(sizeof(struct client));
        if (NULL == client) {
            close(new_client);
            break;
        }

        client->client_sock = new_client;
        client->addr = new_addr;
        client->task = NULL;

        coro_yeild_val(client);
    }

    return NULL;
}

static void clean_client(enum coro_exit_how how, void *raw_client)
{
    (void)how;
    struct client *c = raw_client;
    char ip_buf[24];

    inet_ntop(AF_INET, &c->addr.sin_addr, ip_buf, 24);

    coro_printf("Connection to client at %s:%hu closed\n", ip_buf, ntohs(c->addr.sin_port));

    close(c->client_sock);
    list_del(&c->node);
    free(c);
}

static void *client_task(void *raw_client)
{
    struct client *at;
    struct client *c = raw_client;
    uint8_t buf[64];
    char ip_buf[24];

    inet_ntop(AF_INET, &c->addr.sin_addr, ip_buf, 24);

    coro_printf("New connection from %s:%hu\n", ip_buf, ntohs(c->addr.sin_port));

    coro_register_cleanup(NULL, clean_client, c);
    for (;;) {
        ssize_t rc = coro_recv(c->client_sock, buf, 64, 0);

        if (rc <= 0) {
            break;
        }

        list_for_each_entry(at, c->client_list, node) {
            ssize_t total_sent = 0;

            while (total_sent < rc) {
                ssize_t send_rc = coro_send(at->client_sock, buf + total_sent, 64 - total_sent, 0);

                if (send_rc <= 0) {
                    return NULL;
                }

                total_sent += send_rc;
            }
        }
    }

    return NULL;
}

static void clean_client_list(enum coro_exit_how how, void *list_raw)
{
    (void)how;
    struct list_head *list = list_raw;
    struct client *at;
    struct client *_safe;

    list_for_each_entry_safe(at, _safe, list, node) {
        close(at->client_sock);
        list_del(&at->node);
        free(at);
    }
}

static void *server_start(void *args)
{
    void *raw_val;
    struct coro_task *new_conn_task = NULL;

    struct list_head *client_list = NULL;

    client_list = malloc(sizeof(struct list_head));
    INIT_LIST_HEAD(client_list);

    coro_register_cleanup(NULL, clean_client_list, client_list);
    new_conn_task = coro_create_task(NULL, &accepting_task, args);
    if (NULL == new_conn_task) {
        return NULL;
    }

    while (!coro_await_val(new_conn_task, &raw_val)) {
        struct client *client = raw_val;

        client->task = coro_create_task(NULL, &client_task, client);
        if (NULL == client->task) {
            close(client->client_sock);
            free(client);
            continue;
        }

        client->client_list = client_list;
        list_add_tail(&client->node, client_list);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    uint16_t port;

    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    port = atoi(argv[1]);

    struct server_arg arg;
    struct coro_loop *loop = coro_new_loop(0);

    arg.port = port;
    struct coro_task *server_task = coro_create_task(loop, server_start, &arg);

    coro_run(loop);
    coro_task_join(server_task);

    coro_free_loop(loop);

    return 0;
}
