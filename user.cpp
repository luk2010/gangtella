/*
    File        : user.cpp
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

#include "user.h"
#include "encryption.h"
#include "client.h"
#include "server.h"

GBEGIN_DECL

/** @brief Serialize to text the given client list.
 *
 *  The output will be of the form :
 *  $dbclientlist$size$ip$port$ip$port$ip$port...
**/
template <> std::string to_text(const dbclientlist_t& clist)
{
    std::string ret;
    ret += "$dbclientlist";
    ret += "$"; ret += std::to_string(clist.size());
    if(clist.size() > 0)
    {
        for (unsigned int i = 0; i < clist.size(); ++i)
        {
            ret += "$"; ret += clist[i]->ip;
            ret += "$"; ret += clist[i]->port;
        }
    }
    return ret;
}

template <> dbclientlist_t from_text(const std::string& clist)
{
    dbclientlist_t ret;
    stringlist_t tokens;
    
    // We separate everything in the string list.
    Tokenize(clist, tokens, "$");
    
    if(tokens.size())
    {
        size_t i = 0;
        int res = 0;
        if(tokens[i] == "dbclientlist")
        {
            ++i;
            res = atoi(tokens[i].c_str());
            ret.reserve(res);
            if(res)
            {
                for(unsigned int j = 0; j < res; ++j)
                {
                    i = 2 * j + 2;
                    dbclientptr_t more = new dbclient_t;
                    more->port = atoi(tokens[i].c_str());
                    more->ip   = tokens[i+1];
                    ret.push_back(more);
                }
            }
        }
    }
    
    return ret;
}

/** @brief Add clients from list2 in list1 if they are not already in.
**/
gerror_t clientlist_complete(dbclientlist_t& list1, const dbclientlist_t& list2)
{
    for (unsigned int i = 0; i < list2.size(); ++i)
    {
        dbclientptr_t c = list2[i];
        bool isok = false;
        for(unsigned int j = 0; j < list1.size(); ++j)
        {
            dbclientptr_t c2 = list1[j];
            if(c2->ip == c->ip && c2->port == c->port)
                isok = true;
        }
        
        if(!isok)
        {
            dbclientptr_t newc = new dbclient_t;
            newc->ip   = c->ip;
            newc->port = c->port;
            list1.push_back(newc);
        }
    }
    
    return GERROR_NONE;
}

/** @brief Login a user using password and name.
 *
 *  You must have entered a network first to login. The user database will be the one
 *  from the attached network. You can't use a user from a network to connect to another
 *  one.
 *  
 *  @param net   : Network to look for in.
 *  @param user  : [out] A pointer to a pointer to returns the user. If null, no user is returned.
 *  @param uname : Name of the user to read into network. If no user is found, it creates a new
 *  entry in the network database.
 *  @param upass : Password of the user to read into the network database.
 *
 *  @return 
 *  - GERROR_NONE        : No errors occured.
 *  - GERROR_BADARGS     : uname or upass are empty.
 *  - GERROR_USR_NODB    : No database loaded.
 *  - GERROR_USR_NOKEY   : Can't create keypass.
 *  - GERROR_USR_BADPSWD : Incorrect password.
 *  - GERROR_NET_INVALID : Network given invalid or null.
**/
gerror_t user_create(userptr_t* user, const std::string& uname, const std::string& upass)
{
    userptr_t ret = database_find_user(globalsession.database, uname);
    
    // If user is not in the network database, add it.
    if(!ret)
    {
		// Create new user
        database_create_user(globalsession.database, uname, upass);
            
        // Return the user if possible
        if(*user)
            *user = ret;
            
        cout << "[User] Correctly created user '" << uname << "'." << endl;
        return GERROR_NONE;
	}
	
	// We found user in database, so check password.
	if(Encryption::user_check_password(ret->m_key->buf, ret->m_iv->buf, upass.c_str(), upass.size()))
	{
        // Return the user if possible
        if(*user)
            *user = ret;

		cout << "[User] Correctly loaded user '" << uname << "'." << endl;
		return GERROR_NONE;
	}
	
	// Password wrong, return.
	return GERROR_USR_BADPSWD;
}

/** @brief Destroy a given user.
 *  
 *  @param user : User to destroy.
 *
 *  @note
 *  The user structure is invalid after this function. Every members is set to 0.
 *
 *  @return 
 *  - GERROR_NONE    : No errors occured.
 *  - GERROR_BADARGS : User is invalid.
**/
gerror_t user_destroy(user_t* user)
{
    /*
    free(user->name);
    free(user->key);
    free(user->iv);
     */
    netbuf_free(user->m_name);
    netbuf_free(user->m_key);
    netbuf_free(user->m_iv);
	
	// Everything went okay
	return GERROR_NONE;
}


// ================================================================================================

gerror_t user_register_client(user_t* usr, const database_clientinfo_t& client)
{
    usr->clients.push_back(client);
    return GERROR_NONE;
}

bool user_has_accepted(user_t* usr, const char* username)
{
    for(unsigned int i = 0; i < usr->acceptedusers.size(); ++i)
        if(usr->acceptedusers[i].name == std::string(username))
            return true;
    return false;
}

database_accepted_user_t* user_find_accepted (user_t* usr, const char* username)
{
    for(unsigned int i = 0; i < usr->acceptedusers.size(); ++i)
        if(usr->acceptedusers[i].name == std::string(username))
            return &usr->acceptedusers[i];
    return nullptr;
}


GEND_DECL
