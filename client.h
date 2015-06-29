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

struct _client_;

// Defines some operation the clien is currently doing (like his state)
enum ClientOperation
{
    CO_IDLING,           // Client is waiting for a packet.
    CO_PROCESSINGPACKET, // Client is processing a packet.
    CO_ESTABLISHING,     // Client has not yet established complete connection.
    
    CO_NONE              // Client is doing nothing. (Probably stopped or not started yet.)
};

// A special thread structure to defines what we need
// in the client thread.
typedef struct __client_thread {
    struct _client_* owner;// This is the client owner.
    pthread_t        thethread;// This is the current thread object.
    pthread_mutex_t  mutexaccess;// This mutex has to be used when accessing data in this thread.
    
    ClientOperation  currope;// Defines the current operation.
    void*            opedata;// Datas going sometime with the packet processing.
    
    operator pthread_t& () { return thethread; }
    operator const pthread_t& () const { return thethread; }
    operator pthread_t* () { return &thethread; }
    operator const pthread_t* () const { return &thethread; }
    
    __client_thread& operator = (const __client_thread& rhs) {
        owner = rhs.owner;
        thethread = rhs.thethread;
        mutexaccess = rhs.mutexaccess;
        currope = rhs.currope;
        opedata = rhs.opedata;
        return *this;
    }
    
} client_thread_t;


/** @brief represents a one-way connection.
 *
 *  There are always two ways to represent a connection on a server :
 *  - The server-to-client connection wich represents the first client.
 *  - The client-to-server connection wichh represents the mirror client.
 *
 *  client : server <------- client
 *  mirror : server -------> client
 *
 *  ### Client construction and destruction
 *
 *  ```cpp
 *  clientptr_t myclient = nullptr;
 *  client_alloc(&myclient, 0, nullptr, nullptr); // Allocate the client structure.
 *  client_create(myclient, "69.69.69.69", 69);   // Create the connection.
 *  
 *  // [...]
 *
 *  client_close(myclient); // Stop the client threads.
 *  client_free(&myclient); // Free the client and save its data.
 *  ```
**/
typedef struct _client_ {
    SOCKET          sock;          // socket of the connection.
    std::string     name;          // Name of the origin from the connection.
    uint32_t       id;            // The connection ID, given by the server.

    client_thread_t server_thread; // [Server-side] store the client procesing thread
    SOCKADDR_IN     address;       // [server-side] store the address information.
    _client_*       mirror;        // [server-side] Mirror client connection.
    void*           server;        // [Server-side] Server creating this client.
    buffer_t        pubkey;        // Public Key to decrypt data received.
    bool            established;   // [Server-side] True if connection is established, false otherwise.


    userptr_t       logged_user;   // [Server-side] Stores the user wich the client is logged with.
    bool            logged;        // [Server-side] True if client is logged with a user.

    
    bool            idling;        // [Server-side] True if the client thread loop is idling (waiting for a packet).

    _client_ ()
    {
        sock                        = INVALID_SOCKET;
        name                        = "null";
        id                          = ID_CLIENT_INVALID;
        server_thread.owner         = this;
        server_thread.thethread     = 0;
        server_thread.mutexaccess   = PTHREAD_MUTEX_INITIALIZER;
        server_thread.currope       = CO_NONE;
        server_thread.opedata       = nullptr;
        address                     = {0};
        mirror                      = 0;
        server                      = nullptr;
        pubkey.size                 = 0;
        established                 = false;
        
        logged_user                 = nullptr;
        logged                      = false;
        
        idling                      = false;
    }

    bool operator == (const _client_ other) {
        return sock == other.sock &&
                name == other.name;
    }
} client_t;

typedef client_t* clientptr_t;

/** @defgroup client_function
 *  @brief Every client-side functions.
 *  @{
**/

gerror_t client_alloc               (clientptr_t* ret, uint32_t id, clientptr_t mirror = nullptr, void* cserver = nullptr);
gerror_t client_free                (clientptr_t* ret);

gerror_t client_create				(client_t* client, const char* adress, size_t port);
gerror_t client_send_packet			(client_t* client, uint8_t packet_type, const void* data, size_t sz);
gerror_t client_send_cryptpacket	(client_t* client, uint8_t packet_type, const void* data, size_t sz);
gerror_t client_send_file			(client_t* client, const char* filename);
gerror_t client_close				(client_t* client, bool send_close_packet = true);

gerror_t client_thread_setstatus    (clientptr_t client, ClientOperation ope);

/**
 *  @}
**/

GEND_DECL

#endif // __CLIENT__H
