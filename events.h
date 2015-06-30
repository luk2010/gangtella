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

#ifndef GangTellaX_events_h
#define GangTellaX_events_h

#include "prerequesites.h"

GBEGIN_DECL

class Emitter;
class Listener;

/** @brief Describes a general event structure.
 *  This can be dynamicly casted to another event structure
 *  according to its type.
 **/
class Event
{
public:
    Emitter* parent;  ///< @brief Parent of this event. Should not be null.
    std::string type; ///< @brief Type of the event.
};

/** @brief An emitter is an object that send event to every listeners
 *  registered.
 **/
class Emitter
{
public:
    
    virtual ~Emitter() { }
    
    /** @brief Adds a listener to the Emitter object. It will receive every
     *  events sended by the function Emitter::sendEvent() .
    **/
    void addListener(Listener* l);
    
    /** @brief Removes gien Listener from the list.
    **/
    void removeListener(Listener* l);
    
    /** @brief Sends an event to every Listeners object. This function DO NOT
     *  free the event object, nor modify it. 
    **/
    void sendEvent(const Event* e);
    
    /** @brief Should return a correct printable name of this Emitter.
    **/
    virtual const char* getName() const = 0;
    
protected:
    
    std::vector<Listener*> _listeners;
};

/** @brief A listener is an object that can handle signals produced by the
 *  server, or other emitting objects.
 **/
class Listener
{
public:
    
    virtual ~Listener() {}
    
    /** @brief Handle given event.
     *  The behaviour of this function depends only on the
     *  user's implementation.
     *  @warning This function may NEVER destroy, free or modify the Event
     *  object.
    **/
    virtual void handle(const Event* e) { }
};

// Some generals Events can be defined directly here, as they do not rely on
// any dependancy.

/// @brief A simple event, usually send in a context where an object receives some bytes.
struct BytesReceivedEvent : Event {
    uint32_t numbytes; ///< @brief Number of bytes received during the transaction.
};

/// @brief A simple event, usually send in a context where an object send some bytes.
struct BytesSendEvent : Event {
    uint32_t numbytes; ///< @brief Number of bytes send during the transaction.
};

GEND_DECL

#endif
