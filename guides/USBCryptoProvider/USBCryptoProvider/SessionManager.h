/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.


Notes:
    This class abstracts an authenticated user Session on the EKM provider. It 
    contains a list of nodes, which is synchronized; where each node represents 
    an authenticated session.
    SqlCpSession is a void pointer and EKM providers can chose to maintains complex
    data structures to represent a session. This provider only uses a integer sessionID.

****************************************************************************/


#ifdef __SESSIONMANAGER_H
#else
#define __SESSIONMANAGER_H

#include <atlcoll.h>
//#include "sqlcrypt.h"
#include "USBCryptoProvider.h"
#include "KeyManager.h"

typedef ULONG SessionId;
static const SessionId x_SessionIdBad = (SessionId)-1;

// Class maintaining authenticated sessions in EKM provider
//
class CSessManager
{
    // Session node identified by a sessionid/userid pair
    //
	struct SessionNode
	{
		SessionId _sessId;
		UserId	_idUser;

		SessionNode(SessionId sessId, UserId idUser) : 
					_sessId(sessId), _idUser(idUser)
		{
		}
	};

    // Session Id generated so far.
	SessionId m_currSessId;

    // List of authenticated sessions
	CAtlArray<SessionNode*> m_sess; 

    // Singleton pointer to session manager
	static CSessManager* m_pSessManager;

    // Critical section to synchronize session information
    // 
	CRITICAL_SECTION m_cs;

	CSessManager() : m_currSessId(0)
	{
		InitializeCriticalSection(&m_cs);
	}

	~CSessManager()
	{
		for (ULONG i = 0; i < m_sess.GetCount(); i++)
		{
			delete m_sess[i];
			m_sess[i] = NULL;
		}
		m_sess.RemoveAll();

		DeleteCriticalSection(&m_cs);
	}

    // Authenticate a user and return user ID on success
	UserId AuthenticateUser(const SqlCpCredential* pAuth);
public:

	// Method is not thread safe
	static void Initialize()
	{
		_ASSERT(!m_pSessManager);
		m_pSessManager = new CSessManager();
	}

	// Method is not thread safe
	static void Cleanup()
	{
		_ASSERT(m_pSessManager);
		delete m_pSessManager;
		m_pSessManager = NULL;
	}

    // Access singleton pointer
	static CSessManager* Get() 
	{
		_ASSERT(m_pSessManager);
		return m_pSessManager;
	}

    // Opens a session if the user is authenticated
	SessionId OpenSession(const SqlCpCredential* pAuth);

    // Closes a user session
	void CloseSession(SessionId idSess);

    // Lookup user object from a session id
	CUser* GetUserFromSessionId(SessionId);
};

#endif // __SESSIONMANAGER_H
