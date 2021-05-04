/*
 * Skeleton files for personal server assignment.
 *
 * @author Godmar Back
 * written for CS3214, Spring 2018.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include "buffer.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"
#include "buffer.h"
#include "http.h"

/* Implement HTML5 fallback.
 * If HTML5 fallback is implemented and activated, the server should
 * treat requests to non-API paths specially.
 * If the requested file is not found, the server will serve /index.html
 * instead; that is, it should treat the request as if it
 * had been for /index.html instead.
 */
bool html5_fallback = false;

// silent_mode. During benchmarking, this will be true
bool silent_mode = false;
bool end_gracefully = false;

// default token expiration time is 1 day
int token_expiration_time = 24 * 60 * 60;

// root from which static files are served
char * server_root;

void *thread(void *vargp);
void *thread(void *vargp)
{

    int client_socket = *((int *)vargp);
    pthread_detach(pthread_self());
    free(vargp);
    struct http_client client;
    struct bufio *bufiop = bufio_create(client_socket);
    if (bufiop == NULL) {
        // todo: advised client that we're out of memory
        goto done;
    }
    http_setup_client(&client, bufio_create(client_socket));
    client.closed = false;
    do {
    	http_handle_transaction(&client);
    } while (!client.closed);
    /* persistent connection is assumed,
     * no backward compat for HTTP/1.0 clients yet
    */
    bufio_close(client.bufio);
done:
    pthread_exit(&client_socket); /* don't need return value */
}
/*
 * A non-concurrent, iterative server that serves one client at a time.
 * For each client, it handles exactly 1 HTTP transaction.
 */

/* EDIT: It's concurrent now */
static void
server_loop(char *port_string)
{
    int accepting_socket = socket_open_bind_listen(port_string, 10000);
    while (accepting_socket != -1 && !end_gracefully) {
        if (!silent_mode) fprintf(stderr, "Waiting for client...\n");
        int client_socket = socket_accept_client(accepting_socket);
        if (client_socket == -1)
            return;

        pthread_t tid;
	int *connfdp = malloc(sizeof(int)); /* just to be safe */
	if (connfdp == NULL) {
		if (!silent_mode) perror("malloc");
//		exit(EXIT_FAILURE);
                continue;
	}
	*connfdp = client_socket;
	int er;
	if ((er = pthread_create(&tid, NULL, thread, connfdp)) != 0) {
	    if (er == EAGAIN) {
		if (!silent_mode) perror("Insufficient resources to create another thread");
		//struct http_transaction ta;
		//send_error(&ta, HTTP_INTERNAL_ERROR, "500 Internal Server Error");
		close(client_socket);
		/* todo: warn client then wait for some threads to die */
	    } else {
		if (!silent_mode) perror("No permission to set scheduling policy");
	        exit(EXIT_FAILURE); 
            }
	}
    }
}

static void
usage(char * av0)
{
    fprintf(stderr, "Usage: %s -p port [-R rootdir] [-h] [-e seconds]\n"
        "  -p port      port number to bind to\n"
        "  -R rootdir   root directory from which to serve files\n"
        "  -e seconds   expiration time for tokens in seconds\n"
        "  -h           display this help\n"
	"  -a           display fallback resource\n"
	"  -s           silent mode\n"
        , av0);
    exit(EXIT_FAILURE);
}

void end_prog(int ret);
void end_prog(int ret)
{
    end_gracefully = true;
}
int
main(int ac, char *av[])
{
    int opt;
    char *port_string = NULL;
    while ((opt = getopt(ac, av, "ahp:R:se:")) != -1) {
        switch (opt) {
            case 'a':
                html5_fallback = true;
                break;

            case 'p':
                port_string = optarg;
                break;

            case 'e':
                token_expiration_time = atoi(optarg);
                if (!silent_mode) fprintf(stderr, "token expiration time is %d\n", token_expiration_time);
                break;

            case 's':
                silent_mode = true;
                break;

            case 'R':
                server_root = optarg;
                break;

            case 'h':
            default:    /* '?' */
                usage(av[0]);
        }
    }

    if (port_string == NULL)
        usage(av[0]);

    /* We ignore SIGPIPE to prevent the process from terminating when it tries
     * to send data to a connection that the client already closed.
     * This may happen, in particular, in bufio_sendfile.
     */ 
    signal(SIGPIPE, SIG_IGN);
    signal(SIGQUIT, &end_prog);

    if (!silent_mode) fprintf(stderr, "Using port %s\n", port_string);
    server_loop(port_string);
//    exit(EXIT_SUCCESS);
    return 0;
}

