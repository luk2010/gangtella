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

#ifndef GangTellaX_serverlistener_h
#define GangTellaX_serverlistener_h

#include "prerequesites.h"
#include "server.h"

GBEGIN_DECL

/** @brief An interface to easily handle server events. 
**/
class ServerListener : public Listener
{
public:
    
    virtual ~ServerListener() { }
    
    void handle(const Event* e);
    
public:
    
    /** @brief Called when the Server is started.
    **/
    virtual void onServerStarted(const ServerStartedEvent* e) = 0;
    
    /** @brief Called when the Server is stopped.
    **/
    virtual void onServerStopped(const ServerStoppedEvent* e) = 0;
    
};

GEND_DECL

#endif