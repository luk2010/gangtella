/*
 This file is part of the GangTella project.
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

#ifndef __SERVER__INTERN_H
#define __SERVER__INTERN_H

#include "server.h"

GBEGIN_DECL

extern void*        server_client_thread_loop           (void* data);
extern void         server_launch_accepting_thread      (server_t* server, int csock, SOCKADDR_IN csin);
extern std::string  server_http_get_page                (server_t* server, HttpRequestPacket* packet);
extern uint32_t     server_generate_new_id              (server_t* cserver);
extern client_t*    server_create_client_thread_loop    (server_t* server, client_t* client);
extern int          server_find_client_index_private_   (server_t* cserver, const std::string& name);
extern void         server_launch_minimal               (server_t* server, void* (*command)(void*));

GEND_DECL

#endif
