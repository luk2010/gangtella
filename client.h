/*
    File        : client.h
    Description : Client related function
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

#ifndef __CLIENT__H
#define __CLIENT__H

#include "prerequesites.h"
#include "user.h"

GBEGIN_DECL


/** @brief represents a one-way connection.
 *  There are always two ways to represent a connection on a server :
 *  - The server-to-client connection wich represents the first client.
 *  - The client-to-server connection wichh represents the mirror client.
 *
 *  client : server <------- client
 *  mirror : server -------> client
**/
typedef struct _client_ {
    SOCKET      sock;          // socket of the connection.
    std::string name;          // Name of the origin from the connection.
    uint32_nt   id;            // The connection ID, given by the server.

    pthread_t   server_thread; // [Server-side] store the client procesing thread
    SOCKADDR_IN address;       // [server-side] store the address information.
    _client_*   mirror;        // [server-side] Mirror client connection.
    void*       server;        // [Server-side] Server creating this client.
    buffer_t    pubkey;        // Public Key to decrypt data received.
    bool        established;   // [Server-side] True if connection is established, false otherwise.
    
    user_t      logged_user;   // [Server-side] Stores the user wich the client is logged with.
    bool        logged;        // [Server-side] True if client is logged with a user.
    
    bool        idling;        // [Server-side] True if the client thread loop is idling (waiting for a packet).

    _client_ () : sock(0) {}

    bool operator == (const _client_ other) {
        return sock == other.sock &&
                name == other.name;
    }
} client_t;

/** @defgroup client_function
 *  @brief Every client-side functions.
 *  @{
**/

gerror_t client_create				(client_t* client, const char* adress, size_t port);
gerror_t client_send_packet			(client_t* client, uint8_t packet_type, const void* data, size_t sz);
gerror_t client_send_cryptpacket	(client_t* client, uint8_t packet_type, const void* data, size_t sz);
gerror_t client_send_file			(client_t* client, const char* filename);
gerror_t client_close				(client_t* client, bool send_close_packet = true);

/**
 *  @}
**/

GEND_DECL

#endif // __CLIENT__H
