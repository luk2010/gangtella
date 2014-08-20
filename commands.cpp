/*
    File        : commands.cpp
    Description : Implements every console related functions.
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

#include "commands.h"

GBEGIN_DECL

std::streambuf* coutbuf = nullptr;
std::string console_last_command = "";

#undef cout
#undef endl

gerror_t console_set_output(std::ostream& os)
{
    coutbuf = cout.rdbuf();
    cout.rdbuf(os.rdbuf());

    return GERROR_NONE;
}

gerror_t console_restore_output()
{
    if(coutbuf)
        cout.rdbuf(coutbuf);

    coutbuf = nullptr;
    return GERROR_NONE;
}

void console_reset_lastcommand()
{
	console_last_command.clear();
}

std::string console_get_lastcommand()
{
	return console_last_command;
}

void console_waitfor_command()
{
	std::string cpy = console_last_command;
	while(console_last_command == cpy);
}

GEND_DECL
