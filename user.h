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
#include "database.h"

GBEGIN_DECL

gerror_t user_create				 (userptr_t* user, const std::string& uname, const std::string& upass);
gerror_t user_destroy				 (user_t* user);

// new API
gerror_t user_register_client       (user_t* usr, const database_clientinfo_t& client);
bool     user_has_accepted          (user_t* usr, const char* username);
database_accepted_user_t* user_find_accepted (user_t* usr, const char* username);

GEND_DECL

#endif // __USER_H__
