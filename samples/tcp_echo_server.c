#include <stdlib.h>
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
};

static void *server_entry(void *arg);
static void *client_entry(void *arg);

static LIST_HEAD(clients);

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
    struct coro_task *server_task = coro_create_task(loop, server_entry, &arg);

    coro_run(loop);
    coro_task_join(server_task);

    coro_free_loop(loop);

    return 0;
}

static void *server_entry(void *_arg)
{
    struct sockaddr_in addr = {0};
    struct server_arg *arg = _arg;
    socklen_t len = sizeof(struct sockaddr_in);

    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(arg->port);
    addr.sin_family = AF_INET;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sock) {
        perror("Failed to create socket");
        goto exit;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
        perror("Bind failed");
        goto exit;
    }

    if (listen(sock, 10)) {
        perror("Listen failed");
        goto exit;
    }

    for (;;) {
        int client = coro_accept(sock, (struct sockaddr *)&addr, &len);

        if (client == -1) {
            goto exit;
        }

        printf("New client: %s:%hu\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        struct client *arg = malloc(sizeof(struct client));
        if (NULL == arg) {
            perror("Failed to allocate client argument");
            close(client);
            goto exit;
        }

        arg->client_sock = client;
        arg->task = coro_create_task(NULL, client_entry, arg);

        if (arg->task == NULL) {
            close(arg->client_sock);
            free(arg);
        }

        list_add_tail(&arg->node, &clients);
    }

exit:
    close(sock);
    return NULL;
}

static void *client_entry(void *_arg)
{
    uint8_t buf[128];
    struct client *self = _arg;
    struct client *curr;

    for(;;) {
        long rc = coro_recv(self->client_sock, buf, 128, 0);

        if (rc <= 0) {
            break;
        }

        list_for_each_entry(curr, &clients, node) {
            long sent = 0;
            while (sent < rc) {
                long this_send = coro_send(curr->client_sock, buf + sent, rc - sent, 0);

                if (this_send <= 0) {
                    goto exit;
                }

                sent += this_send;
            }
        }
    }


exit:
    close(self->client_sock);
    return NULL;
}
