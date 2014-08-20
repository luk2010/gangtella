/*
    File        : user.h
    Description : Defines common user operations.
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

#ifndef __USER_H__
#define __USER_H__

#include "prerequesites.h"

GBEGIN_DECL

/** @brief This struct represents a user in user-space of GangTella
 *  network.
**/
typedef struct {
	std::string name; // User name
	std::string key;  // User key
	std::string iv;   // User iv
	
} user_t;

typedef struct {
	std::string ip;
	std::string port;
} dbclient_t;

typedef struct {
	std::string                   dbname;   // Database name.
	std::string                   dbfile;   // Database file.
	bool                          autosave; // True if database is saved when destroyed or reloaded.
	std::map<std::string, user_t> users;    // Users in the database, with their user_t struct.
	std::vector<dbclient_t>       clients;  // Clients successfully connected to this server.
	
} user_db_t;

extern user_db_t* udatabase;

gerror_t user_create			(user_t& user, const std::string& uname, const std::string& upass);
gerror_t user_destroy			(user_t& user);
gerror_t user_database_load		(const std::string& dbname);
gerror_t user_database_export	(const std::string& dbname);
gerror_t user_database_destroy	();
bool     user_database_isloaded	();

GEND_DECL

#endif // __USER_H__
