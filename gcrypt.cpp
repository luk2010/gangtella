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
    cout << "[gcrypt] Total lenght = " << in.length() << "." << endl;
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
        
        // Coding character position with password
        uint32_t pos = (uint32_t) curin * (uint32_t) cpass;
        pos = serialize<uint32_t>(pos);
        // Coding character using password
        char cret = cin + cpass;
        
#ifdef GULTRA_DEBUG
        cout << "[gcrypt] Coding position " << (uint32_t) curin << ". (" << (uint32_t) cret << ")" << endl;
#endif
        
        // Adding all this shit in the out string
        out.push_back(((uint8_t*)&pos)[0]);
        out.push_back(((uint8_t*)&pos)[1]);
        out.push_back(((uint8_t*)&pos)[2]);
        out.push_back(((uint8_t*)&pos)[3]);
        out.push_back(cret);
        
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
    cout << "[guncrypt] Total size = " << totlen << "." << endl;
#endif
    
    cursor += sizeof(uint32_t);
    
    if(totlen == 0) {
        return GERROR_BADARGS;
    }
    
    // Prefill out buffer
    out.resize(totlen, 0);
    
    while(cursor < in.length())
    {
        // Read the next code position (uint32_t)
        uint32_t nextpos = 0;
        uint8_t* tmppos = (uint8_t*) &nextpos;
        tmppos[0] = in[cursor+0];
        tmppos[1] = in[cursor+1];
        tmppos[2] = in[cursor+2];
        tmppos[3] = in[cursor+3];
        nextpos = deserialize<uint32_t>(nextpos);
        nextpos = nextpos / (uint32_t) password[curpass];
        
        cursor += 4;
        
        // Validate position
        if(nextpos >= totlen) {
            return GERROR_GCRYPT_BADPOS;
        }
        
        // Get code byte using password
        char ccode = in[cursor];
        cursor++;
        ccode = ccode - password[curpass];
        
#ifdef GULTRA_DEBUG
        cout << "[guncrypt] Next position = " << nextpos << ". (" << (uint32_t) ccode << ")" << endl;
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