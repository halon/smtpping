/*
	SMTP PING
	Copyright (C) 2011 Halon Security <support@halon.se>

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#ifndef _RESOLVER_HPP_
#define _RESOLVER_HPP_

#include <string>
#include <vector>
#include <stdexcept>

#if defined(__APPLE__) or defined(__FreeBSD__) or defined(__linux)
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif
#ifdef __WIN32__
#include <winsock2.h>
#include <windns.h>

typedef VOID (WINAPI DNSRECORDLISTFREE)(PDNS_RECORD, DNS_FREE_TYPE);
typedef DNSRECORDLISTFREE* LPDNSRECORDLISTFREE;
typedef DNS_STATUS (WINAPI DNSQUERY)(LPCTSTR, WORD, DWORD, PIP4_ARRAY, PDNS_RECORD*, PVOID*);
typedef DNSQUERY* LPDNSQUERY;
#else
#include <resolv.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

class Resolver
{
	public:
		typedef enum {
			RR_MX,
			RR_A,
			RR_AAAA,
		} RecordType;

		Resolver();
		~Resolver();

		bool Lookup(const std::string& domain, RecordType recordType, std::vector<std::string>& result);
		int GetLastError() const {
#ifndef __WIN32__
			return m_res.res_h_errno;
#endif
		}
	private:
#ifdef __WIN32__
		HINSTANCE m_hDnsInst;
		LPDNSRECORDLISTFREE m_lpfnDnsRecordListFree;
		LPDNSQUERY m_lpfnDnsQuery;
#else
		struct __res_state m_res;
#endif
};

#endif
