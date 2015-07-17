/*
 File        : server_clientloop.cpp
 Description : Defines the client loop server method.
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

#include "server.h"
#include "server_intern.h"
#include "commands.h"

GBEGIN_DECL

void* server_client_thread_loop(void* data)
{
    client_t* client = (client_t*) data;
    server_t* org    = (server_t*) client->server;
    
    while(1)
    {
        // We wait for a packet to come.
        // Idling means we also supervise the connection,
        // by sending PT_CONNECTIONSTATUS to the client.
        
        client_thread_setstatus(client, CO_IDLING);
        
        client->idling  = true;
        Packet* pclient = server_wait_packet(org, client);
        client->idling  = false;
        
        client_thread_setstatus(client, CO_PROCESSINGPACKET);
        
        if(!pclient || pclient->m_type == PT_CLIENT_CLOSING_CONNECTION)
        {
            // Client send PT_CLOSING_CONNECTION if it wants this server to destroy the client object.
            // We close the socket, destroy the client but don't send any packet.
            cout << "[Server]{client} Destroying client." << endl;
            cout << "[Server]{client} Destroying client." << endl;
            cout << "[Server]{client} Destroying client." << endl;
            uint32_t cid = ID_CLIENT_INVALID;
            if(client->mirror != NULL)
            {
                cid   = client->mirror->id;
                client_close(client->mirror, false);
                
                delete client->mirror;
                client->mirror = 0;
            }
            
            closesocket(client->sock);
            client->sock = 0;
            /*
             if(client->logged)
             {
             // We destroy the user and log off.
             user_destroy(client->logged_user);
             client->logged = false;
             }
             */
            
            cout << "[Server]{" << client->name << "} Closed client." << endl;
            
            // Erasing client from vectors
            int cindex = server_find_client_index_private_(org, client->name);
            
            gthread_mutex_lock(&org->mutex);
            org->clients.erase(org->clients.begin() + cindex);
            if(cid != ID_CLIENT_INVALID)
                org->client_by_id[cid] = nullptr;
            gthread_mutex_unlock(&org->mutex);
            
            if(pclient)
                delete pclient;
            
            return NULL;
        }
        else if(pclient->m_type == PT_CLIENT_MESSAGE)
        {
            ClientMessagePacket* cmp = reinterpret_cast<ClientMessagePacket*>(pclient);
            std::string message = cmp->buffer;
            cout << "[Server]{" << client->name << "} " << message << endl;
            delete cmp;
        }
        else if(pclient->m_type == PT_CLIENT_ESTABLISHED)
        {
            cout << "[Server]{" << client->name << "} Established connection." << endl;
            client->established = true;
            delete pclient;
            
            // We directly register the client to the user in the session. The user will be saved
            // when terminating the session.
            
            database_clientinfo_t dbclient;
            dbclient.ip   = std::string(inet_ntoa(client->address.sin_addr));
            dbclient.port = (uint16_t) ntohs(client->mirror->address.sin_port);
            
            user_register_client(globalsession.user, dbclient);
        }
        
        /*  ------ PT_USER_INIT ----------------------------------------------------------------------
         *  Description : A user send to this server a demand to be accepted.
         *
         *  Behaviour   : - If user has already been accepted by this server, accept it again
         *  automatically.
         *                - If user has not already been accepted by this server, ask for this server
         *  permission to do it.
         *
         *  Result      : Send a PT_USER_INIT_RESPONSE to the asking user in case of success, errors
         *  otherwise.
         *  ------------------------------------------------------------------------------------------
         */
        else if(pclient->m_type == PT_USER_INIT)
        {
            // Get the traditional packet structure.
            cout << "[Server]{" << client->name << "} Initializing user." << endl;
            UserInitPacket* uip = reinterpret_cast<UserInitPacket*>(pclient);
            
#ifdef GULTRA_DEBUG
            cout << "[Server]{" << client->name << "} Connected user '" << uip->data.name << "'." << endl;
#endif
            
            // We must be logged in to accept this client.
            if(globalsession.user)
            {
                //              networkptr_t net = server.attachednetwork;
                
                // Verify that user isn't already accepted.
                if(user_has_accepted(globalsession.user, uip->data.name))
                {
                    const char* uname = uip->data.name;
                    database_accepted_user_t* user = user_find_accepted(globalsession.user, uname);
                    if(user->keys.key != std::string(uip->data.key) ||
                       user->keys.iv != std::string(uip->data.iv) )
                    {
                        cout << "[Server]{" << client->name << "} User '" << user->name << "' is already in your"
                        << " database, but with another key. Please tell user not to change his key, or he is"
                        << " an usurpator." << endl;
                        org->client_send(client, PT_USER_INIT_AEXIST, NULL, 0);
                    }
                    
                    else
                    {
#ifndef GULTRA_DEBUG
                        cout << "[Server]{" << client->name << "} Sending user info." << endl;
#endif // GULTRA_DEBUG
                        
                        // User is already accepted, so register it normally.
                        user_init_t uinit;
                        strcpy(uinit.name, globalsession.user->m_name->buf);
                        strcpy(uinit.key,  globalsession.user->m_key->buf);
                        strcpy(uinit.iv,   globalsession.user->m_iv->buf);
                        org->client_send(client, PT_USER_INIT_RESPONSE, &uinit, sizeof(uinit));
                        
                        /*strcpy(client->logged_user->m_name->buf, uip->data.name);
                        strcpy(client->logged_user->m_key->buf, uip->data.key);
                        strcpy(client->logged_user->m_iv->buf, uip->data.iv);*/
                        netbuf_copyraw(client->logged_user->m_name, uip->data.name, strlen(uip->data.name));
                        netbuf_copyraw(client->logged_user->m_key, uip->data.key, strlen(uip->data.key));
                        netbuf_copyraw(client->logged_user->m_iv, uip->data.iv, strlen(uip->data.iv));
                        
                        
                        client->logged            = true;
                        
                        cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' accepted." << endl;
                        
                        ClientUserLoggedEvent* e = new ClientUserLoggedEvent;
                        e->type   = "ClientUserLoggedEvent";
                        e->parent = client;
                        e->user   = client->logged_user;
                        client->sendEvent(e);
                        delete e;
                    }
                    
                }
                
                else
                {
                    cout << "[Server]{" << client->name << "} Do you accept user '" << uip->data.name << "' ? [Y/n]" << endl;
                    
                    // If this server is logged in, we will ask for the user if we should accept this userinit command.
                    std::string lastcmd;
                    console_reset_lastcommand();
                    console_waitfor_command();
                    lastcmd = console_get_lastcommand();
                    
                    if(lastcmd != "n" || lastcmd != "N")
                    {
                        // If we accept the user, we save it to database.
#ifndef GULTRA_DEBUG
                        cout << "[Server]{" << client->name << "} Sending user info." << endl;
#endif // GULTRA_DEBUG
                        
                        user_init_t uinit;
                        strcpy(uinit.name, globalsession.user->m_name->buf);
                        strcpy(uinit.key,  globalsession.user->m_key->buf);
                        strcpy(uinit.iv,   globalsession.user->m_iv->buf);
                        org->client_send(client, PT_USER_INIT_RESPONSE, &uinit, sizeof(uinit));
                        
                        /* strbufcreateandcopy(client->logged_user->name, client->logged_user->lname,
                                            uip->data.name, strlen(uip->data.name));
                        strbufcreateandcopy(client->logged_user->key, client->logged_user->lkey,
                                            uip->data.key, strlen(uip->data.key));
                        strbufcreateandcopy(client->logged_user->iv, client->logged_user->liv,
                                            uip->data.iv, strlen(uip->data.iv)); */
                        
                        netbuf_copyraw(client->logged_user->m_name, uip->data.name, strlen(uip->data.name));
                        netbuf_copyraw(client->logged_user->m_key, uip->data.key, strlen(uip->data.key));
                        netbuf_copyraw(client->logged_user->m_iv, uip->data.name, strlen(uip->data.iv));
                        
                        client->logged = true;
                        
                        cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' accepted." << endl;
                    }
                    else
                    {
                        // User didn't accept the connection, just discard it.
                        org->client_send(client, PT_USER_INIT_NOTACCEPTED, nullptr, 0);
                        cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' not accepted." << endl;
                    }
                }
            }
            
            else
            {
                // If this server is not logged in, we should send the client a packet to
                // end the user initialization.
                org->client_send(client, PT_USER_INIT_NOTLOGGED, nullptr, 0);
                
                cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' tried to logged in to you but"
                << " you are not logged in. Please log in." << endl;
            }
            
            delete pclient;
        }
        
        // PT_USER_INIT_RESPONSE behaviour :
        // The client is okay to register ourselves, so we register
        // himm in our database.
        // Abort : GERROR_BADUSRREG
        else if(pclient->m_type == PT_USER_INIT_RESPONSE)
        {
            cout << "[Server]{" << client->name << "} Initializing user." << endl;
            UserInitPacket* uip = reinterpret_cast<UserInitPacket*>(pclient);
            
            // Register the user.
            /*
             database_register_user(server.attachednetwork,
             std::string(uip->data.name),
             std::string(uip->data.key),
             std::string(uip->data.iv),
             deserialize<stat_t>(uip->data.status),
             from_text<dbclientlist_t>(uip->data.clist),
             &(client->logged_user));
             */
            
            if(client->logged_user) {
                client->logged = true;
                cout << "[Server]{" << client->name << "} Connected user '" << uip->data.name << "'." << endl;
            }
            else {
                cout << "[Server]{" << client->name << "} Can't register new user '" << uip->data.name << "'." << endl;
                
                // Error during the operation, we abort current operation from the client side.
                // Telling him the error.
                server_notifiate(&server, client, GERROR_BADUSR/*REG*/);
            }
            
            delete pclient;
        }
        
        else if(pclient->m_type == PT_USER_INIT_NOTLOGGED)
        {
            cout << "[Server]{" << client->name << "} Can't initialize to server : It is not logged "
            << "in." << endl;
            delete pclient;
        }
        
        else if(pclient->m_type == PT_USER_INIT_NOTACCEPTED)
        {
            cout << "[Server]{" << client->name << "} Client didn't accept you ! I can't do anythig for you..." << endl;
            delete pclient;
        }
        
        else if(pclient->m_type == PT_USER_INIT_AEXIST)
        {
            cout << "[Server]{" << client->name << "} User '" << globalsession.user->m_name->buf << "' already exists in client database." << endl;
            delete pclient;
        }
        
        else if(pclient->m_type == PT_USER_END)
        {
            cout << "[Server]{" << client->name << "} Unlogging request from user '" << client->logged_user->m_name->buf << "'." << endl;
            
            user_destroy(client->logged_user);
            client->logged = false;
            
            // Now we send the PT_USER_END_RESPONSE packet to notifiate the server to unlog from us too.
            org->client_send(client, PT_USER_END_RESPONSE, NULL, 0);
            delete pclient;
        }
        
        else if(pclient->m_type == PT_USER_END_RESPONSE)
        {
            cout << "[Server]{" << client->name << "} Unlogging from user '" << client->logged_user->m_name->buf << "'." << endl;
            
            user_destroy(client->logged_user);
            client->logged = false;
            
            delete pclient;
        }
        
        else if(pclient->m_type == PT_CLIENT_SENDFILE_INFO)
        {
            ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(pclient);
            if(!csfip)
            {
                cout << "[Server]{" << client->name << "} Error receiving File Info. " << endl;
                delete pclient;
                continue;
            }
            
            std::string fname(csfip->info.name);                   // File name
            uint32_t    flen   = (uint32_t) csfip->info.lenght;          // File Lenght
            uint32_t    clen   = csfip->info.chunk_lenght;    // Lenght of one chunk
            uint32_t    clsz   = csfip->info.chunk_lastsize;  // Lenght of the last chunk
            uint32_t    cnum   = csfip->info.chunk_count;     // Number of chunks
            bool        chunks = csfip->info.has_chunk;            // True if we have more than one chunk.
            
            
            cout << "[Server]{" << client->name << "} Receiving file." << endl;
            cout << "[Server]{" << client->name << "} File Name -> '" << fname << "'." << endl;
            cout << "[Server]{" << client->name << "} File Size -> "  << flen  << "."  << endl;
#ifdef GULTRA_DEBUG
            if(chunks) {
                cout << "[Server]{" << client->name << "} Chunk Len  -> " << clen << "." << endl;
                cout << "[Server]{" << client->name << "} Chunk Last -> " << clsz << "." << endl;
                cout << "[Server]{" << client->name << "} Chunk num  -> " << cnum << "." << endl;
            }
#endif // GULTRA_DEBUG
            
            // We delete the info packet as we don't need it.
            delete pclient;
            pclient = nullptr;
            csfip   = nullptr;
            
            // We open a file for writing
            std::ofstream ofs(fname, std::ofstream::binary);
            if(!ofs)
            {
                // We can't open the file so abort the operation
                cout << "[Server]{" << client->name << "} Can't open file." << endl;
                
                // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                // because this server can't continue it.
                server_abort_operation(org, client, GERROR_CANTOPENFILE);
                
                goto clientloop_continue;
            }
            
            if(chunks)
            {
                // We have cnum chunks to receive.
                
#ifdef GULTRA_DEBUG
                cout << "[Server]{" << client->name << "} Receiving File chunks." << endl;
#endif // GULTRA_DEBUG
                
                uint32_t sz          = 0;        // Current bytes received (for bytes received callback)
                uint32_t chunk_num   = 0;        // Current chunk number.
                uint32_t last_chunk  = cnum - 1; // Last chunk number.
                bool     mstop       = false;    // Do we have to break the loop ?
                while(!mstop)
                {
                    // We receive the chunk packet
                    Packet* vchunk = server_receive_packet(org, client);
                    if(!vchunk)
                    {
                        // We can't receive the chunk, so close the stream and abort the operation.
                        cout << "[Server]{" << client->name << "} Can't receive correct chunk." << endl;
                        ofs.close();
                        
                        // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                        // because this server can't continue it.
                        server_abort_operation(org, client, GERROR_NORECEIVE);
                        
                        goto clientloop_continue;
                    }
                    
                    // Reinterpret the chunk
                    ClientSendFileChunkPacket* chunk = reinterpret_cast<ClientSendFileChunkPacket*>(vchunk);
                    if(!chunk)
                    {
                        // We can't reinterpret the vchunk.
                        cout << "[Server]{" << client->name << "} Can't reinterpret correct chunk." << endl;
                        delete vchunk;
                        ofs.close();
                        
                        // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                        // because this server can't continue it.
                        server_abort_operation(org, client, GERROR_NORECEIVE);
                        
                        goto clientloop_continue;
                    }
                    
                    // Write last chunk
                    if(chunk_num == last_chunk)
                    {
                        ofs.write(chunk->chunk, clsz);
                        sz   += clsz;
                        mstop = true;
                        
#ifdef GULTRA_DEBUG
                        cout << "[Server]{" << client->name << "} Written chunk n°" << chunk_num << " -> " << clsz << " bytes." << endl;
#endif // GULTRA_DEBUG
                        
                    }
                    
                    // Write normal chunk
                    else
                    {
                        ofs.write(chunk->chunk, clen);
                        sz += clen;
                        
#ifdef GULTRA_DEBUG
                        cout << "[Server]{" << client->name << "} Written chunk n°" << chunk_num << " -> " << clen << " bytes." << endl;
#endif // GULTRA_DEBUG
                        
                    }
                    
                    // Call callback
                    if(org->br_callback)
                        org->br_callback(fname, sz, flen);
                    
                    // Destroy the chunk and iterate to next one.
                    delete chunk;
                    chunk_num++;
                }
                
                // Client may send PT_CLIENT_SENDFILE_TERMINATE packet but ignore it.
                // Close the stream.
                ofs.close();
                goto clientloop_continue;
            }
            
            // We only have one chunk to proceed.
            else
            {
                // Receive the chunk packet
                Packet* vchunk = server_receive_packet(org, client);
                if(!vchunk)
                {
                    // We can't receive the chunk, so close the stream and abort the operation.
                    cout << "[Server]{" << client->name << "} Can't receive correct chunk." << endl;
                    ofs.close();
                    
                    // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                    // because this server can't continue it.
                    server_abort_operation(org, client, GERROR_NORECEIVE);
                    
                    goto clientloop_continue;
                }
                
                // Reinterpret the chunk
                ClientSendFileChunkPacket* chunk = reinterpret_cast<ClientSendFileChunkPacket*>(vchunk);
                if(!chunk)
                {
                    // We can't reinterpret the vchunk.
                    cout << "[Server]{" << client->name << "} Can't reinterpret correct chunk." << endl;
                    delete vchunk;
                    ofs.close();
                    
                    // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                    // because this server can't continue it.
                    server_abort_operation(org, client, GERROR_NORECEIVE);
                    
                    goto clientloop_continue;
                }
                
                // Here we write the entire file lenght.
                ofs.write(chunk->chunk, flen);
                
#ifdef GULTRA_DEBUG
                cout << "[Server] Written chunk -> " << flen << " bytes." << endl;
#endif // GULTRA_DEBUG
                
                if(org->br_callback)
                    org->br_callback(fname, flen, flen);
                
                // Delete chunk and close the stream.
                delete chunk;
                ofs.close();
                
                goto clientloop_continue;
            }
        }
        
        // This section is made to make the continue goto must useful.
    clientloop_continue:
        ;
        
    }
    
    return NULL;
}

GEND_DECL