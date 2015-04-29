/*
 File        : database.h
 Description : Handles every database related functions.
 */

/*
 GangTella Project
 Copyright (C) 2014 - 2015  Luk2010
 
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

#ifndef __DATABASE__H
#define __DATABASE__H

#include "prerequesites.h"

// The database / user pair is a double protection.
// The database contains every users on this computer.
// Each user can only reach its own known clients.
// So the database is a map <user,client_info>

// Easier structures are used here to manipulate those data quicker.

GBEGIN_DECL

gerror_t database_load(database_t*& to, const std::string& dbname, const std::string& dbpass, bool autocreateIfInexistante = true);
database_user_t* database_find_user(database_t* db, const std::string& username);
database_user_t* database_create_user(database_t* db, const std::string& username, const std::string& userpass);
gerror_t database_save(database_t* database);

GEND_DECL

#endif
