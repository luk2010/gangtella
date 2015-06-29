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
#ifndef __SERVER__H
#define __SERVER__H

#include "prerequesites.h"
#include "client.h"
#include "encryption.h"
#include "packet.h"
#include "user.h"
#include "events.h"

GBEGIN_DECL

////////////////////////////////////////////////////////////
/// @brief A Map organized "Clients by ID".
////////////////////////////////////////////////////////////
typedef std::map<uint32_t, client_t*> ClientsIdMap;

////////////////////////////////////////////////////////////
/// @brief A function to send bytes to given client.
////////////////////////////////////////////////////////////
typedef gerror_t (*client_send_t) (client_t*, uint8_t, const void*, size_t);

////////////////////////////////////////////////////////////
/// @brief A generic function to receive bytes from given
/// client by name.
////////////////////////////////////////////////////////////
typedef void (*bytesreceived_t) (const std::string& name, size_t received, size_t total);

////////////////////////////////////////////////////////////
/// @brief A generic function to send bytes to given client,
/// by name.
////////////////////////////////////////////////////////////
typedef void (*bytessend_t) (const std::string& name, size_t received, size_t total);


typedef enum {
    SP_NORMAL  = 1,
    SP_CRYPTED = 2
} SendPolicy;

typedef enum {
    SS_NOTCREATED = 0, // Default value, server has not been created yet.
    SS_CREATED    = 1, // Server has been created.
    SS_INITED     = 2, // Server has been created and inited.
    SS_STARTED    = 3, // Server has been launched.
    SS_STOPPED    = 4, // Server has been launched, then stopped.
    SS_ADDINGCLIENT = 5 // Server is adding a client.
    
} ServerStatus;

class server_t : public Emitter {
public:
    
    SOCKET                sock;

    std::string           name;            // Name displayed to other servers. This name is send to the client.
    std::vector<client_t> clients;         // List of activated clients.
    ClientsIdMap          client_by_id;    // Every clients by ID. This list is updated for every clients connection or deconnection.
    client_t*             localhost;       // A local client used to send packet to this server.

    pthread_mutex_t       mutex;
    pthread_t             thread;
    bool                  started;

    uint32_t              port;
    crypt_t*              crypt;           // RSA public/private key of this server.
    buffer_t*             pubkey;          // Public key ready to be send to new clients.

    client_send_t         client_send;     // Function to send packet. Can be crypted or not.
    bytesreceived_t       br_callback;     // Function called when bytes are received when transmitting a file.
    bytessend_t           bs_callback;     // Function called when bytes are send when transmitting a file.
    
//    userptr_t           logged_user;     // Current user logged in.
//    bool 			 	  logged;          // True if logged in.
    
    ServerStatus          status;          // Current status of the server. (By default it is SS_STOPPED then SS_STARTED).
    bool                  _must_stop;      // [Private] True when server must stop the threading loop.
    
//  networkptr_t          attachednetwork; // Current attached network. Null if none.
    
    struct {
        int maxbufsize;
        int maxclients;
        bool withssl;
        std::string name;
        int port;
    }                     args;
    
    const char* getName() const { return "Server"; }
};

extern server_t server;

/// @brief Event sent when server is started.
typedef Event ServerStartedEvent;

/// @brief Event sent when server is stopped.
typedef Event ServerStoppedEvent;

// Before using any of the functions below, be sure every field of the server's args structure
// has been correctly filled.

gerror_t server_create                      ();
gerror_t server_initialize					();

gerror_t server_launch    					(server_t* server);
gerror_t server_stop                        (server_t* server);
gerror_t server_destroy   					(server_t* server);

gerror_t server_setsendpolicy				(server_t* server, int policy);
gerror_t server_setbytesreceivedcallback	(server_t* server, bytesreceived_t callback);
gerror_t server_setbytessendcallback		(server_t* server, bytessend_t callback);
PacketPtr server_wait_packet                (server_t* server, client_t* client);
PacketPtr server_receive_packet				(server_t* server, client_t* client);
void server_preinterpret_packet             (server_t* server, client_t* client, PacketPtr& pclient);

client_t* server_find_client_by_name		(server_t* server, const std::string& name);

gerror_t server_abort_operation				(server_t* server, client_t* client, int error);
gerror_t server_notifiate                   (server_t* server, client_t* client, int error);

gerror_t server_init_user_connection		(server_t* server, /* user_t& out, */ const char* adress, size_t port);
gerror_t server_end_user_connection         (server_t* server, client_t* client);
gerror_t server_unlog                       (server_t* server);

gerror_t server_init_client_connection		(server_t* server, client_t*& out, const char* adress, size_t port);
gerror_t server_wait_establisedclient	    (client_t* client, uint32_t timeout = 0);
void server_end_client						(server_t* server, const std::string& client_name);
gerror_t server_check_client                (server_t* server, client_t* client);

int      server_get_status                  (server_t* server);
gerror_t server_wait_status                 (server_t* server, int status, long timeout = 0);
client_t* server_client_exist               (server_t* server, const std::string& cip, const size_t& cport);

GEND_DECL

#endif // __SERVER__H
