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

#include "serverlistener.h"

GBEGIN_DECL

void ServerListener::handle(const Event *e)
{
    if(!e) {
        gnotifiate_warn("Not handled 'null' event.");
    }
    
    if(e->type == "ServerStartedEvent")
        onServerStarted(dynamic_cast<const ServerStartedEvent*>(e));
    else if(e->type == "ServerStoppedEvent")
        onServerStopped(dynamic_cast<const ServerStoppedEvent*>(e));
    else if(e->type == "ServerWillStopEvent")
        onServerWillStop(dynamic_cast<const ServerWillStopEvent*>(e));
    else if(e->type == "ServerNewClientCreatedEvent")
        onClientCreated(reinterpret_cast<const ServerNewClientCreatedEvent*>(e));
    else if(e->type == "ServerClientCompletedEvent")
        onClientCompleted(reinterpret_cast<const ServerClientCompletedEvent*>(e));
    else if(e->type == "ServerHttpRequestEvent")
        onHttpRequest(reinterpret_cast<const ServerHttpRequestEvent*>(e));
    else if(e->type == "ServerClientClosingEvent")
        onClientClosing(reinterpret_cast<const ServerClientClosingEvent*>(e));
    else if(e->type == "ServerClientClosedEvent")
        onClientClosed(reinterpret_cast<const ServerClientClosedEvent*>(e));
    
    else {
        gnotifiate_warn("Not handled event type '%s'.", e->type.c_str());
    }
}

GEND_DECL
