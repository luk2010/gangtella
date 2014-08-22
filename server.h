/*
    This file is part of the GangTella project.
*/

/*
    GangTella Project
    Copyright (C) 2014  Luk2010

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __SERVER__H
#define __SERVER__H

#include "prerequesites.h"
#include "client.h"
#include "encryption.h"
#include "packet.h"
#include "user.h"

GBEGIN_DECL

typedef std::map<uint32_t, client_t*> ClientsIdMap;
typedef gerror_t (*client_send_t) (client_t*, uint8_t, const void*, size_t);
typedef void (*bytesreceived_t) (const std::string& name, size_t received, size_t total);
typedef void (*bytessend_t) (const std::string& name, size_t received, size_t total);

typedef enum {
    SP_NORMAL  = 1,
    SP_CRYPTED = 2
} SendPolicy;

typedef struct _server_ {
    SOCKET                sock;

    std::string           name;         // Name displayed to other servers. This name is send to the client.
    std::vector<client_t> clients;      // List of activated clients.
    ClientsIdMap          client_by_id; // Every clients by ID. This list is updated for every clients connection or deconnection.

    pthread_mutex_t       mutex;
    pthread_t             thread;
    bool                  started;

    uint32_t              port;
    crypt_t*              crypt;        // RSA public/private key of this server.
    buffer_t*             pubkey;       // Public key ready to be send to new clients.

    client_send_t         client_send;  // Function to send packet. Can be crypted or not.
    bytesreceived_t       br_callback;  // Function called when bytes are received when transmitting a file.
    bytessend_t           bs_callback;  // Function called when bytes are send when transmitting a file.
    
    user_t				  logged_user;  // Current user logged in.
    bool 				  logged;       // True if logged in.
} server_t;

gerror_t server_create    					(server_t* server, const std::string& disp_name);
gerror_t server_initialize					(server_t* server, size_t port, int maxclients);
gerror_t server_launch    					(server_t* server);
gerror_t server_destroy   					(server_t* server);

gerror_t server_setsendpolicy				(server_t* server, int policy);
gerror_t server_setbytesreceivedcallback	(server_t* server, bytesreceived_t callback);
gerror_t server_setbytessendcallback		(server_t* server, bytessend_t callback);
Packet* server_receive_packet				(server_t* server, client_t* client);

client_t* server_find_client_by_name		(server_t* server, const std::string& name);

gerror_t server_abort_operation				(server_t* server, client_t* client);

gerror_t server_init_user_connection		(server_t* server, user_t& out, const char* adress, size_t port);
gerror_t server_init_client_connection		(server_t* server, client_t*& out, const char* adress, size_t port);
gerror_t server_wait_establisedclient	    (client_t* client, uint32_t timeout = 0);
void server_end_client						(server_t* server, const std::string& client_name);

GEND_DECL

#endif // __SERVER__H
