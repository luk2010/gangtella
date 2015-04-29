/*
 File        : gcrypt.h
 Description : Definition of the GangCrypt algorythm.
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

#ifndef GangTellaX_gcrypt_h
#define GangTellaX_gcrypt_h

#include "prerequesites.h"

GBEGIN_DECL

gerror_t gcrypt(std::string in, std::string& out, const std::string& password);
gerror_t guncrypt(std::string in, std::string& out, const std::string& password);

GEND_DECL

#endif
