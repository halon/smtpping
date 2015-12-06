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

#include "resolver.hpp"

#include <map>
#include <algorithm>

#if defined(__WIN32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#else
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <memory.h>

/*
 * initialize thread-safe m_res structure
 */
Resolver::Resolver()
{
#ifdef __WIN32__
	m_hDnsInst = LoadLibrary("DNSAPI.DLL");
	if (m_hDnsInst)
	{
		m_lpfnDnsRecordListFree = reinterpret_cast<LPDNSRECORDLISTFREE>(GetProcAddress(m_hDnsInst, "DnsRecordListFree"));
		m_lpfnDnsQuery = reinterpret_cast<LPDNSQUERY>(GetProcAddress(m_hDnsInst, "DnsQuery_A"));
	}
#else
	memset((void*)&m_res, 0, sizeof m_res);
	res_ninit(&m_res);
#endif
}

/*
 * close thread-safe m_res structure
 */
Resolver::~Resolver()
{
#ifdef __WIN32__
	if (m_hDnsInst)
	{
		FreeLibrary(m_hDnsInst);
		m_hDnsInst = NULL;
	}
#else
	res_nclose(&m_res);
#endif
}

bool Resolver::Lookup(const std::string& domain, RecordType recordType, std::vector<std::string>& result)
{
	std::map<unsigned int, std::vector<std::string> > prioMap;

#ifdef __WIN32__
	if (!m_lpfnDnsRecordListFree || !m_lpfnDnsQuery)
		return false;

	int req_rec_type;
#ifndef DNS_TYPE_AAAA
# define DNS_TYPE_AAAA (28)
#endif
	switch(recordType)
	{
		case RR_A:
			req_rec_type = DNS_TYPE_A;
			break;
		case RR_AAAA:
			req_rec_type = DNS_TYPE_AAAA;
			break;
		case RR_MX:
			req_rec_type = DNS_TYPE_MX;
			break;
		default:
			return false;
	}

	PDNS_RECORD pRec = NULL;
	if (m_lpfnDnsQuery(domain.c_str(), req_rec_type, DNS_QUERY_STANDARD, NULL, &pRec, NULL) != ERROR_SUCCESS)
		return false;

	PDNS_RECORD pRecFirst = pRec;
	while (pRec)
	{
		if (req_rec_type == pRec->wType && pRec->Flags.S.Section == DNSREC_ANSWER)
		{
			if (pRec->wType == DNS_TYPE_MX)
			{
				prioMap[(int)pRec->Data.MX.wPreference].push_back(pRec->Data.MX.pNameExchange);
			}
			if (pRec->wType == DNS_TYPE_AAAA)
			{
				SOCKADDR_IN6 addr;
				memset(&addr, 0, sizeof addr);
				addr.sin6_family = AF_INET6;
				addr.sin6_addr = *((in_addr6*)&(pRec->Data.AAAA.Ip6Address));
				char buf[128];
				DWORD bufsize = sizeof buf;
				if (WSAAddressToStringA((sockaddr*)&addr, sizeof addr, NULL, buf, &bufsize) == 0)
				{
					prioMap[0].push_back(buf);
				}
			}
			if (pRec->wType == DNS_TYPE_A)
			{
				SOCKADDR_IN addr;
				memset(&addr, 0, sizeof addr);
				addr.sin_family = AF_INET;
				addr.sin_addr = *((in_addr*)&(pRec->Data.A.IpAddress));
				char buf[128];
				DWORD bufsize = sizeof buf;
				if (WSAAddressToStringA((sockaddr*)&addr, sizeof addr, NULL, buf, &bufsize) == 0)
				{
					prioMap[0].push_back(buf);
				}
			}
		}
		pRec = pRec->pNext;
	}
	m_lpfnDnsRecordListFree(pRecFirst, DnsFreeRecordList);
#else
	unsigned char response[64 * 1024];
	memset(response, 0, sizeof response);

	unsigned char *resData, *resEnd;
	unsigned short rec_len, rec_pref;
	unsigned short rec_type;
	HEADER* header;

	int req_rec_type;
	switch(recordType)
	{
		case RR_A:
			req_rec_type = T_A;
			break;
		case RR_AAAA:
			req_rec_type = T_AAAA;
			break;
		case RR_MX:
			req_rec_type = T_MX;
			break;
		default:
			return false;
	}

	int len = res_nquery(&m_res, domain.c_str(), C_IN, req_rec_type, (unsigned char*)&response, sizeof response);
	if (len < 0)
	{
		if (m_res.res_h_errno == NO_DATA)
			return true;

		return false;
	}
	if (len > (int)sizeof response) {
		return false;
	}

	header = (HEADER*)&response;
	resData = (unsigned char*)&response + HFIXEDSZ;
	resEnd  = (unsigned char*)&response + len;

	int answer_count = ntohs((unsigned short)header->ancount);
	int query_count = ntohs((unsigned short)header->qdcount);

	for (int i = 0; i < query_count; i++) {
		if ((len = dn_skipname(resData, resEnd)) < 0)
			return false;

		resData += len + QFIXEDSZ;
	}

	char buf[MAXDNAME + 1];
	for (int i = 0; i < answer_count; i++) {
		len = dn_expand((unsigned char*)&response, resEnd, resData, (char*)&buf, sizeof buf - 1);
		if (len < 0) 
			return false;

		resData += len;

		GETSHORT(rec_type, resData);
		resData += INT16SZ + INT32SZ;

		GETSHORT(rec_len, resData);

		switch(rec_type)
		{
			case T_MX:
				GETSHORT(rec_pref, resData);
				rec_len -= sizeof(short);
				break;
			default:
				rec_pref = 0;
				break;
		}

		if (rec_type == req_rec_type) {
			switch(rec_type)
			{
				case T_A:
					{
						char buf[INET_ADDRSTRLEN];
						if (inet_ntop(AF_INET,
									(const struct sockaddr_in*)resData, buf, INET_ADDRSTRLEN)) {
							prioMap[rec_pref].push_back(buf);
						}
					}
					break;
				case T_AAAA:
					{
						char buf[INET6_ADDRSTRLEN];
						if (inet_ntop(AF_INET6,
									(const struct sockaddr_in6*)resData, buf, INET6_ADDRSTRLEN)) {
							prioMap[rec_pref].push_back(buf);
						}
					}
					break;
				case T_MX:
					{
						char buf[MAXDNAME + 1];
						len = dn_expand((unsigned char*)&response, resEnd, resData, (char*)&buf, sizeof buf - 1);
						if (len < 0) 
							return false;

						prioMap[rec_pref].push_back(buf);
					}
					break;
			}
		}

		resData += rec_len;
	}
#endif

	// merge map
	std::map<unsigned int, std::vector<std::string> >::iterator i;
	for(i = prioMap.begin(); i != prioMap.end(); ++i)
	{
		std::sort(i->second.begin(), i->second.end());
		result.insert(result.end(), i->second.begin(), i->second.end());
	}
	return true;
}
