#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ev.h"

#define CLIENT_QUEUE_LEN 10
#define SERVER_PORT 10000

struct ev *ev;

int init_server_socket(void)
{
	int ret, flag;
	int listen_fd = -1;
	struct sockaddr_in6 server_addr;

	puts("Create listening server in port 10000");

	listen_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0) {
		perror("socket()");
		return -1;
	}

	flag = 1;
	ret = setsockopt(listen_fd, SOL_SOCKET,
			 SO_REUSEADDR, &flag, sizeof(flag));
	if (ret == -1) {
		perror("setsockopt()");
		return -1;
	}

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(SERVER_PORT);

	/* Bind address and socket together */
	ret = bind(listen_fd, (struct sockaddr*)&server_addr,
		   sizeof(server_addr));
	if (ret == -1) {
		perror("bind()");
		close(listen_fd);
		return -1;
	}

	/* Create listening queue (client requests) */
	ret = listen(listen_fd, CLIENT_QUEUE_LEN);
	if (ret == -1) {
		perror("listen()");
		close(listen_fd);
		return -1;
	}

	return listen_fd;
}

void process_client_read(int fd, int what, void *priv_data)
{
	int client_sock_fd = fd;
	ssize_t read_data;
	char ch;

	(void)what;
	(void)priv_data;


	read_data = read(client_sock_fd, &ch, 1);
	if (read_data == -1) {
		perror("read()");
		close(client_sock_fd);
	}

	write(client_sock_fd, &ch, 1);
}

void process_new_client_request(int fd, int what, void *priv_data)
{
	int server_fd = fd;
	int ret;
	struct sockaddr_in6 client_addr;
	socklen_t client_addr_len;
	int client_sock_fd;
	char str_addr[INET6_ADDRSTRLEN];
	struct ev_entry *ev_entry;

	(void)what;
	(void)priv_data;

	puts("callback called");

	/* Do TCP handshake with client */
	client_sock_fd = accept(server_fd,
			(struct sockaddr*)&client_addr,
			&client_addr_len);
	if (client_sock_fd == -1) {
		perror("accept()");
		close(server_fd);
		return;
	}

	inet_ntop(AF_INET6, &(client_addr.sin6_addr),
			str_addr, sizeof(str_addr));
	printf("New connection from: %s:%d\n",
			str_addr,
			ntohs(client_addr.sin6_port));

	ev_entry = ev_entry_new(client_sock_fd, EV_READ, process_client_read, NULL);
	if (!ev_entry) {
		puts("ev_entry_new failed");
	}

	ret = ev_add(ev, ev_entry);
	if (ret < 0) {
		puts("ev_addfailed");
	}

}

int main(void)
{
	int server_fd, ret;
	struct ev_entry *ev_entry;

	ev = ev_new(0);
	if (!ev) {
		puts("Cannot create event handler\n");
		return EXIT_FAILURE;
	}

	server_fd = init_server_socket();
	if (server_fd < 0) {
		puts("init server failed");
		return EXIT_FAILURE;
	}

	ev_entry = ev_entry_new(server_fd, EV_READ, process_new_client_request, &server_fd);
	if (!ev_entry) {
		puts("ev_entry_new failed");
		return EXIT_FAILURE;
	}

	ret = ev_add(ev, ev_entry);
	if (ret < 0) {
		puts("ev_addfailed");
		return EXIT_FAILURE;
	}

	ret = ev_loop(ev, 0);
	if (ret < 0) {
		puts("ev_addfailed");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
