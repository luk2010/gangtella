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

#include "events.h"

GBEGIN_DECL

void Emitter::addListener(Gangtella::Listener *l)
{
    if(l)
        _listeners.push_back(l);
    else {
        gnotifiate_warn("Attempt to add 'null' listener to emitter '%s'.", getName() );
    }
}

void Emitter::removeListener(Listener* l)
{
    if(!l) {
        gnotifiate_warn("Attempt to remove 'null' listener from emitter '%s'.", getName());
        return;
    }
    
    std::vector<Listener*>::iterator it = std::find(_listeners.begin(), _listeners.end(), l);
    if(it == _listeners.end()) {
        gnotifiate_warn("Not found given listener '%ui'.", (uintptr_t) (*it));
        return;
    }
    
    _listeners.erase(it);
}

void Emitter::sendEvent(const Event *e)
{
    if(!e) {
        gnotifiate_warn("Attempt to send 'null' event from emitter '%s'", getName() );
    }
    
    for (std::vector<Listener*>::iterator it = _listeners.begin(); it != _listeners.end(); it++) {
        (*it)->handle(e);
    }
}



GEND_DECL
