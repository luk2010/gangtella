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

#include "client.h"
#include "server.h"

GBEGIN_DECL

Client2::Client2 ()
{
    _sockup             = INVALID_SOCKET;
    _sockdown           = INVALID_SOCKET;
    _sockaddr           = nullptr;
    _servername         = "null";
    _id                 = ID_CLIENT_INVALID;
    _pubkey.size        = 0;
    _thread.owner       = nullptr;
    _thread.thethread   = 0;
    _thread.mutexaccess = PTHREAD_MUTEX_INITIALIZER;
    _thread.currope     = CO_NONE;
    _thread.opedata     = nullptr;
    _distantuser        = nullptr;
    _localserver        = nullptr;
    _established        = false;
    _idling             = false;
    _logged             = false;
    _connected          = false;
    INIT_MUTEX(_clientmutex);
}

Client2::Client2(uint32_t id, Server* cserver)
{
    _sockup             = INVALID_SOCKET;
    _sockdown           = INVALID_SOCKET;
    _sockaddr           = nullptr;
    _servername         = "null";
    _id                 = id;
    _pubkey.size        = 0;
    _thread.owner       = nullptr;
    _thread.thethread   = 0;
    _thread.mutexaccess = PTHREAD_MUTEX_INITIALIZER;
    _thread.currope     = CO_NONE;
    _thread.opedata     = nullptr;
    _distantuser        = nullptr;
    _localserver        = (void*) cserver;
    _established        = false;
    _idling             = false;
    _logged             = false;
    _connected          = false;
    INIT_MUTEX(_clientmutex);
}

Client2::~Client2()
{
    if(isConnected())
        close();
}

const SOCKET& Client2::getUpSocket() const
{
    return _sockup;
}

const SOCKET& Client2::getDownSocket() const
{
    return _sockdown;
}

const char* Client2::getName() const
{
    return "Client2";
}

const std::string Client2::getServerName() const
{
    return _servername;
}

const void* Client2::getAddressRawPointer() const
{
    if(_sockaddr->sa_family == AF_INET)
        return &(((struct sockaddr_in*)_sockaddr)->sin_addr);
    else if(_sockaddr->sa_family == AF_INET6)
        return &(((struct sockaddr_in6*)_sockaddr)->sin6_addr);
    else {
        gnotifiate_error("[Client2] Bad adress type (internal error).");
        return nullptr;
    }
}

const std::string Client2::getAddressString() const
{
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(_sockaddr->sa_family, getAddressRawPointer(), buf, INET6_ADDRSTRLEN);
    return std::string(buf);
}

const uint32_t Client2::getPort() const
{
    if(_sockaddr->sa_family == AF_INET)
        return ((struct sockaddr_in*)_sockaddr)->sin_port;
    else if(_sockaddr->sa_family == AF_INET6)
        return ((struct sockaddr_in6*)_sockaddr)->sin6_port;
    else
        return 0;
}

const uint32_t& Client2::getLocalId() const
{
    return _id;
}

const buffer_t& Client2::getPublicKeyBuffer() const
{
    return _pubkey;
}

Server* Client2::getLocalServer()
{
    return (Server*) _localserver;
}

const Server* Client2::getLocalServer() const
{
    return (const Server*) _localserver;
}

bool Client2::isEstablished() const
{
    return _established;
}

bool Client2::isIdling() const
{
    return _idling;
}

bool Client2::isLogged() const
{
    return _logged;
}

bool Client2::isConnected() const
{
    return _connected;
}

gerror_t Client2::create(const char *address, const char* port)
{
    // From http://manpagesfr.free.fr/man/man3/getaddrinfo.3.html
    
    if(isConnected())
        return GERROR_NONE;
    
    if(!address) {
        return GERROR_BADARGS;
    }
    
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    SOCKET sfd = 0;
    int s;
    
    // Fill the 'hints' structure.
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family    = AF_UNSPEC;
    hints.ai_socktype  = SOCK_STREAM;
    hints.ai_flags     = AI_PASSIVE;
    hints.ai_protocol  = 0;
    hints.ai_canonname = nullptr;
    hints.ai_addr      = nullptr;
    hints.ai_next      = nullptr;
    
    // Proceed to getaddrinfo func.
    s = getaddrinfo(address, port, &hints, &result);
    if(s != 0) {
        gnotifiate_error("[Client2] getaddrinfo returned error : %s", gai_strerror(s));
        return GERROR_INVALID_HOST;
    }
    
    for(rp = result; rp != nullptr; rp = rp->ai_next)
    {
        // We have a list of possible hosts. Just select the good one.
        if(rp->ai_protocol == IPPROTO_TCP)
        {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if(sfd == INVALID_SOCKET)
            {
                cout << "[Client2] Can't create socket !" << endl;
                return GERROR_INVALID_SOCKET;
            }
            
            if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                break; /* success */
            
            close(sfd);
        }
    }
    
    if(rp == nullptr)
    {
        gnotifiate_error("[Client2] Could not find any suitable host !");
        return GERROR_INVALID_CONNECT;
    }
    
    AutoMutex(&this->_clientmutex);
    
    _sockup   = sfd;
    _sockaddr = (struct sockaddr*) (rp->ai_addr->sa_family == AF_INET ? malloc(sizeof(struct sockaddr_in)) : malloc(sizeof(sockaddr_in6)));
    memcpy(_sockaddr, rp->ai_addr, rp->ai_addrlen);
    
    freeaddrinfo(result); /* no longer needed. */
    
    cout << "[Client] Connected to host '" << address << ":" << port << "'." << endl;
    _connected = true;
    return GERROR_NONE;
}

gerror_t Client2::sendPacket(uint8_t packet_type, const void *data, uint64_t sz)
{
    if(!isConnected()) {
        gnotifiate_warn("[Client2] Can't send packet with a non-connected client.");
        return GERROR_NOT_INITIALIZED;
    }
    
    return send_client_packet(_sockup, _sockdown, packet_type, data, sz);
}

gerror_t Client2::sendCryptedPacket(uint8_t packet_type, const void *data, uint64_t sz)
{
    // First we have to create the EncryptionInfoPacket
    
    server_t* server = (server_t*) _localserver;
    encrypted_info_t info;
    info.ptype = packet_type;
    
    if(sz > 0) {
        info.cryptedblock_number = (uint32_t) (sz / (RSA_SIZE - 11) ) + 1;
        info.cryptedblock_lastsz = (uint32_t) sz % (RSA_SIZE - 11);
    }
    else {
        info.cryptedblock_number = 0;
        info.cryptedblock_lastsz = 0;
    }
    
#ifdef GULTRA_DEBUG
    cout << "[Client2] Sending CryptPacket Info (Block Num = " << info.cryptedblock_number << ", LBS = " << info.cryptedblock_lastsz << ")." << endl;
#endif // GULTRA_DEBUG
    
    // We send the info to client
    info = serialize<encrypted_info_t>(info);
    gerror_t err = sendPacket(PT_ENCRYPTED_INFO, &info, sizeof(encrypted_info_t));
    info = deserialize<encrypted_info_t>(info);
    
    if(err != GERROR_NONE)
        return err;
    
    if(info.cryptedblock_number > 1)
    {
        // We have to send many crypted chunk
        unsigned char* chunk   = reinterpret_cast<unsigned char*>(const_cast<void*>(data));
        unsigned char* current = nullptr;
        unsigned char* to      = (unsigned char*) malloc(RSA_SIZE);
        memset(to, 0, RSA_SIZE);
        
        unsigned int i = 0;
        for (; i < info.cryptedblock_number - 1; ++i)
        {
            current = chunk + ( i * ( RSA_SIZE - 11 ) );
            int len = Encryption::crypt(server->crypt, to, current, RSA_SIZE - 11);
            
#ifdef GULTRA_DEBUG
            cout << "[Client2] Sending len = " << len << "bytes." << endl;
#endif // GULTRA_DEBUG
            
            sendPacket(PT_ENCRYPTED_CHUNK, to, len);
        }
        
        current = chunk + ( i * ( RSA_SIZE - 11 ) );
        int len = Encryption::crypt(server->crypt, to, current, info.cryptedblock_lastsz);
        
#ifdef GULTRA_DEBUG
        cout << "[Client2] Sending len = " << len << "bytes." << endl;
#endif // GULTRA_DEBUG
        
        sendPacket(PT_ENCRYPTED_CHUNK, to, len);
        
        // Terminated !
        free(to);
        
#ifdef GULTRA_DEBUG
        cout << "[Client2] Crypt Terminated." << endl;
#endif // GULTRA_DEBUG
        
        return GERROR_NONE;
    }
    else if(info.cryptedblock_number == 1)
    {
        // We have to send one crypted chunk
        unsigned char* chunk = reinterpret_cast<unsigned char*>(const_cast<void*>(data));
        unsigned char* to    = (unsigned char*) malloc(RSA_SIZE);
        
        int len = Encryption::crypt(server->crypt, to, chunk, RSA_SIZE - 11);
        sendPacket(PT_ENCRYPTED_CHUNK, to, len);
        
        // Terminated !
        free(to);
        return GERROR_NONE;
    }
    
    return GERROR_NONE;
}

gerror_t Client2::close(bool sendClosePacket)
{
    if(!isConnected())
        return GERROR_NONE;
    
    if(sendClosePacket) {
        sendPacket(PT_CLIENT_CLOSING_CONNECTION);
    }
    
    AutoMutex(&this->_clientmutex);
    
    if(_thread.thethread)
        pthread_cancel(_thread);
    _thread.owner       = nullptr;
    _thread.thethread   = 0;
    _thread.mutexaccess = PTHREAD_MUTEX_INITIALIZER;
    _thread.currope     = CO_NONE;
    _thread.opedata     = nullptr;
    
    closesocket(_sockup);
    closesocket(_sockdown);
    
    // Reinitializing datas.
    _sockup             = INVALID_SOCKET;
    _sockdown           = INVALID_SOCKET;
    _sockaddr           = nullptr;
    _servername         = "null";
    _id                 = ID_CLIENT_INVALID;
    
    if(_pubkey.size)
        free(_pubkey.buf);
    _pubkey.size        = 0;
    
    if(_distantuser)
        user_destroy(_distantuser);
    _distantuser        = nullptr;
    
    _established        = false;
    _idling             = false;
    _logged             = false;
    _connected          = false;
    
    gnotifiate_info("[Client2] Closed client '%s'.", _servername.c_str());
    return GERROR_NONE;
}

GEND_DECL