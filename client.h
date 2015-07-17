////////////////////////////////////////////////////////////
//
// GangTella - A multithreaded crypted server.
// Copyright (c) 2014 - 2015 Luk2010 (alain.ratatouille@gmail.com)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
////////////////////////////////////////////////////////////

#ifndef __CLIENT__H
#define __CLIENT__H

#include "prerequesites.h"
#include "user.h"
#include "events.h"

GBEGIN_DECL

class Server;
class Client;

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
    Client*          owner;// This is the client owner.
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

/** @brief Represents a Client using up and down streams. 
**/
class Client2 : public Emitter
{
public:
    
    friend class Server;
    
public:
    
    /** @brief Constructs an empty client structure.
    **/
    Client2();
    
    /** @brief Constructs an empty client, initializing with some structures.
    **/
    Client2(uint32_t id, Server* cserver = nullptr);
    
    /** @brief Destructs the client structure.
    **/
    ~Client2();
    
public:
    
    /** @brief Returns the SOCKET corresponding to an upload stream.
    **/
    const SOCKET& getUpSocket() const;
    
    /** @brief Returns the SOCKET corresponding to a download stream.
    **/
    const SOCKET& getDownSocket() const;
    
    /** @brief Returns the name of the Class of this Emitter. This
     *  does not correspond to the name of the client. To get this,
     *  use Client::getServerName().
     **/
    const char* getName() const;
    
    /** @brief Returns the name of the server pointed to by this
     *  client.
     **/
    const std::string getServerName() const;
    
    /** @brief Returns a raw pointer to the address field of this
     *  client. Currently, it has no purpose except a use in function
     *  Client::getAddressString().
     **/
    const void* getAddressRawPointer() const;
    
    /** @brief Returns the IP adress in form of a string.
     **/
    const std::string getAddressString() const;
    
    /** @brief Returns the port used on the distant server to connect.
     **/
    const uint32_t getPort() const;
    
    /** @brief Returns the id of this client in the local server stack.
    **/
    const uint32_t& getLocalId() const;
    
    /** @brief Returns the public key used by this client to decrypt received
     * data.
    **/
    const buffer_t& getPublicKeyBuffer() const;
    
    /** @brief Returns a pointer to the local server used by this client.
    **/
    Server* getLocalServer();
    const Server* getLocalServer() const;
    
    /** @brief Returns true if Client is established.
    **/
    bool isEstablished() const;
    
    /** @brief Returns true if Client-thread is idling.
    **/
    bool isIdling() const;
    
    /** @brief Returns true if Client is logged in.
    **/
    bool isLogged() const;
    
    /** @brief Returns true if Client is connected.
    **/
    bool isConnected() const;
    
public:
    
    /** @brief Creates the client, and try to connect to given infos.
     *
     *  @param address : A pointer to a NULL-terminated ANSI string that 
     *  contains a host (node) name or a numeric host address string. For 
     *  the Internet protocol, the numeric host address string is a dotted-decimal 
     *  IPv4 address or an IPv6 hex address.
     *
     *  @param port : A pointer to a NULL-terminated ANSI string that contains 
     *  either a service name or port number represented as a string.
     *  A service name is a string alias for a port number. For example, “http” is 
     *  an alias for port 80 defined by the Internet Engineering Task Force (IETF) as 
     *  the default port used by web servers for the HTTP protocol.
    **/
    gerror_t create(const char* address, const char* port);
    
    /** @brief Send a packet using the down-stream.
    **/
    gerror_t sendPacket(uint8_t packet_type, const void* data = nullptr, size_t sz = 0);
    
    /** @brief Send a crypted packet using the down-stream.
     *  The packet is crypted using the internal local server private key,
     *  and can be decrypted using the public key.
    **/
    gerror_t sendCryptedPacket(uint8_t packet_type, const void* data, size_t sz);
    
    /** @brief Close the connection and, if true, send a closing connection packet to
     *  notifiate the distant server.
    **/
    gerror_t close(bool sendClosePacket = true);
    
private:
             
    Client2(const Client2& rhs) { }
    
private:
    
    SOCKET           _sockup;      ///< @brief Socket for uploading.
    SOCKET           _sockdown;    ///< @brief Socket for downloading.
    struct sockaddr* _sockaddr;    ///< @brief An internal structure to hold information about the address of the distant server.
    
    std::string      _servername;  ///< @brief Name of the distant server.
    uint32_t         _id;          ///< @brief ID of the client in the local server.
    buffer_t         _pubkey;      ///< @brief Public key to decrypt received data.
    client_thread_t  _thread;      ///< @brief Holds infos about the loop thread.
    userptr_t        _distantuser; ///< @brief Pointer to a structure filled with distant server logged user.
    
    void*            _localserver; ///< @brief Generic pointer to the local server structure.
    
    bool             _established; ///< @brief True if connection established.
    bool             _idling;      ///< @brief True if thread is idling.
    bool             _logged;      ///< @brief True if distant server is logged in.
    bool             _connected;   ///< @brief True if client is connected. (Client2::create() has been called.)
    
    DEFINE_MUTEX(_clientmutex); ///< @brief Defines a private mutex to access the client datas.
};

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
class Client : public Emitter {
public:
    SOCKET          sock;          // socket of the connection.
    std::string     name;          // Name of the origin from the connection.
    uint32_t        id;            // The connection ID, given by the server.

    client_thread_t server_thread; // [Server-side] store the client procesing thread
    SOCKADDR_IN     address;       // [server-side] store the address information.
    Client*         mirror;        // [server-side] Mirror client connection.
    void*           server;        // [Server-side] Server creating this client.
    buffer_t        pubkey;        // Public Key to decrypt data received.
    bool            established;   // [Server-side] True if connection is established, false otherwise.


    userptr_t       logged_user;   // [Server-side] Stores the user wich the client is logged with.
    bool            logged;        // [Server-side] True if client is logged with a user.

    
    bool            idling;        // [Server-side] True if the client thread loop is idling (waiting for a packet).

    Client ()
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

    bool operator == (const Client& other) {
        return sock == other.sock &&
                name == other.name;
    }
    
    /** @brief Returns the name of the Class of this Emitter. This
     *  does not correspond to the name of the client. To get this, 
     *  use Client::getServerName(). 
    **/
    const char* getName() const { return "Client"; }
    
    /** @brief Returns the name of the server pointed to by this
     *  client. 
    **/
    const std::string getServerName() const;
    
    /** @brief Returns a raw pointer to the address field of this
     *  client. Currently, it has no purpose except a use in function
     *  Client::getAddressString().
    **/
    const void* getAddressRawPointer() const;
    
    /** @brief Returns the IP adress in form of a string.
    **/
    const std::string getAddressString() const;
    
    /** @brief Returns the port used on the distant server to connect.
    **/
    const uint32_t getPort() const;
};

typedef Client    client_t;
typedef client_t* clientptr_t;

class ClientUserLoggedEvent : public Event {
public:
    userptr_t user;
};

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
