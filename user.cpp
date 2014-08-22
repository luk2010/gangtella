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

GBEGIN_DECL

user_db_t* udatabase = nullptr;

/** @brief Create a user using password and name.
 * 
 *  If the current directory contains users.gtl file, it will read the user data from this 
 *  file and verify that the password is correct.
 *  If users.gtl does not exist, a new user is created using given pass and initializing with
 *  a new initialization vector.
 *
 *  @note
 *  You can also load a different database using user_database_load().
 *  
 *  @param user  : A reference to an allocated user structure.
 *  @param uname : Name of the user to read into database. If no user is found, it creates a new
 *  entry in the database.
 *  @param upass : Password of the user to read into the database.
 *
 *  @return 
 *  - GERROR_NONE        : No errors occured.
 *  - GERROR_BADARGS     : uname or upass are empty.
 *  - GERROR_USR_NODB    : No database loaded.
 *  - GERROR_USR_NOKEY   : Can't create keypass.
 *  - GERROR_USR_BADPSWD : Incorrect password.
**/
gerror_t user_create(user_t& user, const std::string& uname, const std::string& upass)
{
	if(uname.empty() || upass.empty())
		return GERROR_BADARGS;
	
	if(!user_database_isloaded())
		return GERROR_USR_NODB;
		
	if(udatabase->users.find(uname) == udatabase->users.end())
	{
		// Create new user in database
		user.name = uname;
		if(Encryption::user_create_keypass(user.key, user.iv, upass.c_str(), upass.size()) != GERROR_NONE)
		{
			// Can't create keypass, abort.
			return GERROR_USR_NOKEY;
		}
		
		// Everything turned right, new user is on !
#ifdef GULTRA_DEBUG
		cout << "[User] Correctly created user '" << uname << "'." << endl;
#endif // GULTRA_DEBUG
		
		return GERROR_NONE;
	}
	
	// We found user in database, so check password.
		
	if(Encryption::user_check_password(udatabase->users[uname].key, udatabase->users[uname].iv, upass.c_str(), upass.size()))
	{
		// Load user from database
		user.name = uname;
		user.key  = udatabase->users[uname].key;
		user.iv   = udatabase->users[uname].iv;

#ifdef GULTRA_DEBUG
		cout << "[User] Correctly loaded user '" << uname << "'." << endl;
#endif // GULTRA_DEBUG

		return GERROR_NONE;
	}
	
	// Password wrong, return.
	return GERROR_USR_BADPSWD;
}

/** @brief Destroy a given user, and saves its data into the database.
 *  
 *  @param user : User to destroy. If an entry corresponding to this user
 *  is already used, the fields name and signed_pass can't be changed (this
 *  is for security purpose). If the entry doesn't exist, the user is saved directly
 *  in the database.
 *
 *  @note
 *  The user structure is invalid after this function. Every members is set to 0.
 *
 *  @return 
 *  - GERROR_NONE    : No errors occured.
 *  - GERROR_BADARGS : User is invalid.
**/
gerror_t user_destroy(user_t& user)
{
	if(user.name.empty() || user.key.empty())
		return GERROR_BADARGS;
	
	// Find the user in the database
	if(udatabase->users.find(user.name) == udatabase->users.end())
	{
		// We did not find the user : save it.
		udatabase->users[user.name].name = user.name;
		udatabase->users[user.name].key  = user.key;
		udatabase->users[user.name].iv   = user.iv;
	}
	
	user.name.clear();
	user.key.clear();
	user.iv.clear();
	
	// Everything went okay
	return GERROR_NONE;
}

/** @brief Load a database with given name.
 *  
 *  The database must follow an exact pattern. You can export your database
 *  using user_database_export(), and so import another database using this
 *  function.
 *
 *  @note
 *  Only one database can be used by server, and at server creation, database 
 *  "users.gtl" is loaded by default.
 *
 *  @param dbname : Path to the database to load. It can be an absolute path or
 *  a relative from the executable.
 *
 *  @return 
 *  - GERROR_NONE         : No errors occured.
 *  - GERROR_BADARGS      : Path is invalid.
 *  - GERROR_CANTOPENFILE : Stream can't be opened.
 *  - GERROR_IO_CANTREAD  : Stream can't read database data.
**/
gerror_t user_database_load(const std::string& dbname)
{
	if(dbname.empty())
		return GERROR_BADARGS;
		
	if(udatabase)
		user_database_destroy();
	
	std::ifstream indb(dbname.c_str());
	if(!indb)
		return GERROR_CANTOPENFILE;
		
	udatabase = new user_db_t;
	std::string curr_word;

	cout << "[User] Processing database '" << dbname << "'." << endl;
	udatabase->dbfile = dbname;
	while(indb >> curr_word)
	{
		if(curr_word == "[dbname]")
		{
			// Database name processing
			indb >> udatabase->dbname;
#ifdef GULTRA_DEBUG
			cout << "[User] Name = '" << udatabase->dbname << "'." << endl;
#endif // GULTRA_DEBUG
		}
		else if(curr_word == "[autosave]")
		{
			std::string boolean; indb >> boolean;
			if(boolean == "true")
				udatabase->autosave = true;
			else
				udatabase->autosave = false;
#ifdef GULTRA_DEBUG
			cout << "[User] Autosave = '" << boolean << "'." << endl;
#endif // GULTRA_DEBUG
		}
		else if(curr_word == "[user]")
		{
			std::string uname, ukey, uiv;
			indb >> uname >> ukey >> uiv;
#ifdef GULTRA_DEBUG
			cout << "[User] New user processed ('" << uname << "')." << endl;
#endif // GULTRA_DEBUG

			udatabase->users[uname].name = uname;
			udatabase->users[uname].key  = ukey;
			udatabase->users[uname].iv   = uiv;
		}
		else if(curr_word == "[client]")
		{
			std::string cip, cport;
			indb >> cip >> cport;
#ifdef GULTRA_DEBUG
			cout << "[User] New client processed ('" << cip << ":" << cport << "')." << endl;
#endif // GULTRA_DEBUG
		
			dbclient_t dbc;
			dbc.ip   = cip;
			dbc.port = cport;
			udatabase->clients.push_back(dbc);
		}
		else
		{
			cout << "[User] Bad keyword given in database '" << dbname << "' (" << curr_word << ")." << endl;
		}
	}

	cout << "[User] Database '" << dbname << "' loaded." << endl;
	return GERROR_NONE;
}

/** @brief Export a database to given filename.
 *
 *  Use this function to export your database giving you the
 *  possibility to load it from any GangTella application.
 *
 *  @param dbname : File to save the database.
 *
 *  @return 
 *  - GERROR_NONE         : No errors occured.
 *  - GERROR_BADARGS      : Path is invalid or no database is
 *  loaded.
 *  - GERROR_CANTOPENFILE : File given can't be opened.
**/
gerror_t user_database_export(const std::string& dbname)
{
	if(dbname.empty() || !user_database_isloaded())
		return GERROR_BADARGS;
	
	std::ofstream os(dbname.c_str());
	if(!os)
	{
#ifdef GULTRA_DEBUG
		cout << "[User] Can't open file '" << dbname << "' to export database !" << endl;
#endif // GULTRA_DEBUG

		return GERROR_CANTOPENFILE;
	}
	
	// File is opened and database is ready to be exported. 
#ifdef GULTRA_DEBUG
	cout << "[User] Exporting database '" << udatabase->dbname << "' to file '" << dbname << "'." << endl;
#endif // GULTRA_DEBUG

	// Name
	os << "[dbname] " << udatabase->dbname << "\n";
	
	// Autosave option
	if(udatabase->autosave)
		os << "[autosave] true\n";
	else
		os << "[autosave] false\n";
	
	// Users
	std::map<std::string, user_t>::const_iterator e  = udatabase->users.end();
	std::map<std::string, user_t>::iterator       it = udatabase->users.begin();
	
	for(; it != e; ++it)
		os << "[user] " << it->first << " " << it->second.key << " " << it->second.iv << "\n";
	for(size_t i = 0; i < udatabase->clients.size(); ++i)
		os << "[client] " << udatabase->clients[i].ip << " " << udatabase->clients[i].port << "\n";
	
	return GERROR_NONE;
}

/** @brief Returns true if database is loaded.
**/
bool user_database_isloaded()
{
	return !(udatabase == nullptr);
}

/** @brief Destroy the currently loaded database.
 *  @note Database with 'autosave' option set to true will 
 *  be re-exported to their appropriate file.
 *
 *  @return
 *  - GERROR_NONE : No errors occured.
**/
gerror_t user_database_destroy()
{
	if(!user_database_isloaded())
		return GERROR_NONE;
	
	if(udatabase->autosave)
		user_database_export(udatabase->dbfile);
	
	delete udatabase;
	return GERROR_NONE;
}

/** @brief Returns true if user is loaded.
**/
bool user_is_loaded(const std::string& name)
{
	return udatabase ? udatabase->users.find(name) != udatabase->users.end() : false;
}

GEND_DECL
