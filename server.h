/*
    This file is part of the GangTella project.
*/

#ifndef __SERVER__H
#define __SERVER__H

#include "prerequesites.h"
#include "client.h"

GBEGIN_DECL

typedef struct _server_ {
    SOCKET                 sock;
    std::vector<client_t>  clients;
    pthread_mutex_t        mutex;
    pthread_t              thread;
    bool                   started;

} server_t;

/** @brief Initialize the default parameters of the server_t structure.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
**/
gerror_t server_create(server_t* server);

/** @brief Initialize a new server structure.
 *  @note This function assumes server is not null, and mutex and started
 *  are already initialized.
 *
 *  @param server     : A pointer to the server structure.
 *  @param port       : A valid port to set the server. Range is [0 - 65534].
 *  @param maxclients : The maximum number of clients that can be accepted by
 *  this server. Range is [0 - 256] generally, but you may extend it to
 *  size_t maximum value.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null or if maxclients is 0.
 *  - GERROR_INVALID_SOCKET if socket can't be initialized.
 *  - GERROR_INVALID_BINDING if socket can't be binded.
 *  - GERROR_INVALID_LISTENING if socket can't listen to port.
 *  On Windows :
 *  - GERROR_WSASTARTUP if WSA can't be started.
**/
gerror_t server_initialize(server_t* server, size_t port, int maxclients);

/** @brief Launch the Server thread.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
 *  - GERROR_THREAD_CREATION if thread cannot be created.
**/
gerror_t server_launch(server_t* server);

void* server_destroy     (server_t* server);
void* server_thread_loop (void*);
client_t* server_find_client_by_name(server_t* server, const std::string& name);
client_t* server_init_client_connection(server_t* server, const std::string& cname, const char* adress, size_t port);
void server_end_client(server_t* server, const std::string& client_name);

GEND_DECL

#endif // __SERVER__H
