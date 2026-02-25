/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

Notes:
    See SessionManager.h for an overview of this class.

****************************************************************************/


#include "stdafx.h"
#include <crtdbg.h>
#include "Util.h"
#include "SessionManager.h"

CSessManager* CSessManager::m_pSessManager = NULL;

// Create a session structure and add it to session list if the user is 
// successfully authenticated - Note that access to session list is synchronized
//
SessionId CSessManager::OpenSession(const SqlCpCredential* pAuth)
{
	UserId idUser = x_UserIdBad;
	if ((idUser = AuthenticateUser(pAuth)) == x_UserIdBad)
	{
		return x_SessionIdBad;
	}

	CAutoCriticalSection acs(&m_cs);
	acs.Enter();

	SessionId idSess = m_currSessId++;
	CAutoP<SessionNode> a_pNode = new SessionNode(idSess, idUser);

	m_sess.Add(a_pNode.PvReturn());
	return (idSess);
}

// Find the session to be closed and remove it from the list
//
void CSessManager::CloseSession(SessionId idSess)
{
	CAutoCriticalSection acs(&m_cs);
	acs.Enter();

	for (UINT i = 0; i < m_sess.GetCount(); i++)
	{
		if (m_sess[i]->_sessId == idSess)
		{
			delete m_sess[i];
			m_sess.RemoveAt(i);
			break;
		}
	}		
}

// Get the user object and authenticate against the supplied credential
//
UserId CSessManager::AuthenticateUser(const SqlCpCredential* pAuth) 
{
	// Supports basic auth
    if (!pAuth || !pAuth->name.cb || !pAuth->name.ws)
        return x_UserIdBad;

	CUser* pUser = CKeyManager::Get()->GetUserByName(CWStr(pAuth->name.ws, pAuth->name.cb));
	if (pUser)
	{
		if(pUser->FAuthenticate(CWStr(pAuth->password.ws, pAuth->password.cb)))
		{
			return pUser->GetUserId();
		}
	}

	return x_UserIdBad;
}

// Thie method is used to locate a user based on its SessionId. Once a session is established
// then Session information is used for all crypto operations
//
CUser* CSessManager::GetUserFromSessionId(SessionId idSess)
{
	CAutoCriticalSection acs(&m_cs);
	acs.Enter();

	for (UINT i = 0; i < m_sess.GetCount(); i++)
	{
		if (m_sess[i]->_sessId == idSess)
		{
			_ASSERT(m_sess[i]->_idUser != x_UserIdBad);
			return CKeyManager::Get()->GetUserById(m_sess[i]->_idUser );	
		}
	}
	return NULL;
}
