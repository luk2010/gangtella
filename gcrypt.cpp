/*
 File        : gcrypt.h
 Description : Implementation of the GangCrypt algorythm.
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

#include "gcrypt.h"

#include <algorithm> // std::find

GBEGIN_DECL

gerror_t gcrypt(std::string in, std::string& out, const std::string& password)
{
    srand((unsigned) time(NULL));
    
    uint32_t curin = 0;
    uint32_t curpass = 0;
    
    // Writing total lenght
    uint32_t len = serialize<uint32_t>((uint32_t) in.length());
    uint8_t* tmplen = (uint8_t*) &len;
    out.push_back(tmplen[0]);
    out.push_back(tmplen[1]);
    out.push_back(tmplen[2]);
    out.push_back(tmplen[3]);
    
#ifdef GULTRA_DEBUG
    gnotifiate_info("[gcrypt] Total lenght = %i.", in.length());
#endif
    
    std::vector<uint32_t> passthrought;
    passthrought.reserve(in.length());
    for(unsigned int i = 0; i < in.length(); ++i)
        passthrought.push_back(i);
    
    // Writing every bytes
    
    while(passthrought.size() > 0)
    {
        // Selecting random character in string
        uint32_t curintmp = rand() % passthrought.size();
        curin = passthrought[curintmp];
        passthrought.erase(passthrought.begin()+curintmp);
        
        char cin = in[curin];
        
        // Selecting current password string
        char cpass = password[curpass];
        
        if(in.length() >= UINT16_MAX)
        {
            // Coding character position with password
            uint32_t pos = (uint32_t) curin + (uint32_t) cpass;
            pos = serialize<uint32_t>(pos);
            // Coding character using password
            char cret = cin + cpass;
            
#ifdef GULTRA_DEBUG
            gnotifiate_info("[gcrypt] Coding position '%i'. (%i)", (uint32_t) curin, (uint32_t) cret);
#endif
            
            // Adding all this shit in the out string
            out.push_back(((uint8_t*)&pos)[0]);
            out.push_back(((uint8_t*)&pos)[1]);
            out.push_back(((uint8_t*)&pos)[2]);
            out.push_back(((uint8_t*)&pos)[3]);
            out.push_back(cret);
        }
        
        else if(in.length() >= UINT8_MAX)
        {
            // Coding character position with password
            uint16_t pos = (uint16_t) curin + (uint16_t) cpass;
            pos = serialize<uint16_t>(pos);
            // Coding character using password
            char cret = cin + cpass;
            
#ifdef GULTRA_DEBUG
            gnotifiate_info("[gcrypt] Coding position '%i'. (%i)", (uint32_t) curin, (uint32_t) cret);
#endif
            
            // Adding all this shit in the out string
            out.push_back(((uint8_t*)&pos)[0]);
            out.push_back(((uint8_t*)&pos)[1]);
            out.push_back(cret);
        }
        
        else if(in.length() < UINT8_MAX)
        {
            // Coding character position with password
            uint8_t pos = (uint8_t) curin + (uint8_t) cpass;
            pos = serialize<uint8_t>(pos);
            // Coding character using password
            char cret = cin + cpass;
            
#ifdef GULTRA_DEBUG
            gnotifiate_info("[gcrypt] Coding position '%i'. (%i)[opcode=0x%08.8X]", (uint32_t) curin, (uint32_t) cret, (uint32_t) pos);
#endif
            
            // Adding all this shit in the out string
            out.push_back(((uint8_t*)&pos)[0]);
            out.push_back(cret);
        }
        
        // Setting up variables
        curpass++;
        if(curpass >= password.length())
            curpass = 0;
    }
    
    return GERROR_NONE;
}

gerror_t guncrypt(std::string in, std::string& out, const std::string& password)
{
    uint32_t totlen = 0;
    uint64_t cursor = 0;
    uint32_t curpass = 0;
    
    // Read total lenght from in
    uint8_t* tmplen = (uint8_t*) &totlen;
    tmplen[0] = in[cursor+0];
    tmplen[1] = in[cursor+1];
    tmplen[2] = in[cursor+2];
    tmplen[3] = in[cursor+3];
    totlen = deserialize<uint32_t>(totlen);
    
#ifdef GULTRA_DEBUG
    gnotifiate_info("[guncrypt] Total lenght = '%i'.", totlen);
#endif
    
    cursor += sizeof(uint32_t);
    
    if(totlen == 0) {
        return GERROR_BADARGS;
    }
    
    // Prefill out buffer
    out.resize(totlen, 0);
    
    while(cursor < in.length())
    {
        // Read the next code position (uint32_t, depending on total lenght)
        uint32_t nextpos = 0;
        
        if(totlen >= UINT16_MAX)
        {
            uint8_t* tmppos = (uint8_t*) &nextpos;
            tmppos[0] = in[cursor+0];
            tmppos[1] = in[cursor+1];
            tmppos[2] = in[cursor+2];
            tmppos[3] = in[cursor+3];
            cursor += 4;
            
            nextpos = deserialize<uint32_t>(nextpos);
            nextpos = nextpos - (uint32_t) password[curpass];
        }
        
        else if(totlen >= UINT8_MAX)
        {
            uint16_t tmpconv;
            uint8_t* tmppos = (uint8_t*) &tmpconv;
            tmppos[0] = in[cursor+0];
            tmppos[1] = in[cursor+1];
            cursor += 2;
            
            tmpconv = deserialize<uint16_t>(tmpconv);
            tmpconv = tmpconv - (uint16_t) password[curpass];
            nextpos = (uint32_t) tmpconv;
        }
        
        else if(totlen < UINT8_MAX)
        {
            uint8_t tmpconv;
            uint8_t* tmppos = (uint8_t*) &tmpconv;
            tmppos[0] = in[cursor+0];
            cursor += 1;
            
            tmpconv = deserialize<uint8_t>(tmpconv);
            tmpconv = tmpconv - (uint8_t) password[curpass];
            nextpos = (uint32_t) tmpconv;
        }
        
        // Validate position
        if(nextpos >= totlen) {
            return GERROR_GCRYPT_BADPOS;
        }
        
        // Get code byte using password
        char ccode = in[cursor];
        cursor++;
        ccode = ccode - password[curpass];
        
#ifdef GULTRA_DEBUG
        gnotifiate_info("[guncrypt] Next position = %i. (%i)", nextpos, (uint32_t) ccode);
#endif
        
        out.replace(nextpos, 1, 1, ccode);
        
        // Update variables
        curpass++;
        if(curpass >= password.length())
            curpass = 0;
    }
    
    return GERROR_NONE;
}

GEND_DECL