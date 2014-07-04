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

/** @brief Create a Client from given information.
 *
 *  @param client : Pointer to a complete client structure. @note Only fields client_t::name
 *  and client_t::sock are required.
 *  @param adress : A usual IP or domain name to connect.
 *  @param port : The port to use for the connection (server-ide).
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if one of the given args is null.
 *  - GERROR_INVALID_SOCKET if socket is invalid or can't be created.
 *  - GERROR_INVALID_HOST if host is invalid.
 *  - GERROR_INVALID_CONNECT if can't connect to host.
 *  - An error depending on client_send_packet().
**/
gerror_t client_create(client_t* client, const char* adress, size_t port);

/** @brief Send a packet to a given client.
 *  @see send_client_packet() for more details.
 *
 *  @param client : Pointer to the client structure.
 *  @param packet_type : Type of the packet to send.
 *  @param data : Raw data to send.
 *  @param sz : Size of the data to send.
 *
 *  @return
 *  The same as send_client_packet().
**/
gerror_t client_send_packet(client_t* client, uint8_t packet_type, const void* data, size_t sz);


gerror_t client_send_cryptpacket(client_t* client, uint8_t packet_type, const void* data, size_t sz);
gerror_t client_send_file(client_t* client, const char* filename);

/** @brief Close a client connection.
 *  @param send_close_packet : If true, send a PT_CLIENT_CLOSING_CONNECTION packet to
 *  the corresponding socket. This option is used by the server to end mirror connections,
 *  so don't use it or use it at your own risk.
 *
 *  @return
 *  - GERROR_NONE on success
 *  - GERROR_BADARGS if one of the given args is null.
 *  - GERROR_CANT_CLOSE_SOCKET if socket could not be closed.
 *  - @see errors from client_send_packet().
**/
gerror_t client_close(client_t* client, bool send_close_packet = true);

/**
 *  @}
**/

GEND_DECL

#endif // __CLIENT__H
