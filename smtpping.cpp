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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <stdexcept>

using std::string;
using std::vector;

#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winbase.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

/* DNS Resolver */
#include "resolver.hpp"

/*
 * Global Variables
 */
bool debug = false;

#define APP_VERSION "1.0"
#define APP_NAME "smtpping"

/*
 * Signal Handlers (abort ping and show statistics)
 */
bool abort_ping = false;
void abort(int)
{
	abort_ping = true;
}

/*
 * SMTPReadLine: read a smtp line and return status code
 *               return false on disconnect
 */
bool SMTPReadLine(int s, std::string& ret)
{
#ifdef __WIN32__
#define MSG_NOSIGNAL 0
#endif
	char buf[1];
	string cmd;
	int r;
	do {
		r = recv(s, buf, sizeof(buf), MSG_NOSIGNAL);
		if (r > 0) cmd += buf[0];
		if (buf[0] == '\n')
		{
			if (debug)
				fprintf(stderr, "response %s", cmd.c_str());
			/* support multi-line responses */
			if (cmd.size() > 4 && cmd[3] == ' ')
			{
				ret = cmd.substr(0, 3);
				return true;
			} else
				cmd.clear();
		}
	} while(r > 0);
	return false;
}

/*
 * high resolution timers (should return ms with 2 decimals)
 */
#ifdef WIN32
#include <windows.h>

double PCFreq = 0.0;
__int64 CounterStart = 0;

/* initialize counters */
void StartCounter()
{
	LARGE_INTEGER li;
	if(!QueryPerformanceFrequency(&li))
		return;

	PCFreq = double(li.QuadPart)/1000.0;

	QueryPerformanceCounter(&li);
	CounterStart = li.QuadPart;
}

/* GetHighResTime(): should be ported */
double GetHighResTime()
{
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return double(li.QuadPart-CounterStart)/PCFreq;
}

#else
#include <sys/time.h>

/* GetHighResTime(): should be ported */
double GetHighResTime()
{
	struct timeval tv;
	if(gettimeofday(&tv, NULL) != 0)
		return 0;
	return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}
#endif

/*
 * usage information, displays all arugments and a short help
 */
void usage(const char* name, FILE* fp, int status)
{
	fprintf(fp, 
		"Usage: " APP_NAME " [ARGS] x@y.z [@server]\n"
		"Where: x@y.z  is the address that will receive e-mail\n"
		"       server is the address to connect to (optional)\n"
		"       ARGS   is one or many of: (optional)\n"
		"       -h, --help\tShow this help message\n"
		"       -d, --debug\tShow more debugging\n"
		"       -p, --port\tWhich TCP port to use [default: 25]\n"
		"       -w, --wait\tTime to wait between PINGs [default: 1000]"
						" (ms)\n"
		"       -c, --count\tNumber on messages [default: unlimited]\n"
		"       -s, --size\tMessage size in kilobytes [default: 10]"
						" (kb)\n"
		"       -H, --helo\tHELO message [default: example.org]\n"
		"       -S, --sender\tSender address [default: empty]\n"
		"\n"
		"  If no @server is specified, " APP_NAME " will try to find "
		"the recipient domain's\n  MX record, falling back on A/AAAA "
		"records.\n"
		"\n"
		"  " APP_NAME " " APP_VERSION " built on " __DATE__ 
		" (c) Halon Security <support@halon.se>\n"
		);
	exit(status);
}

int main(int argc, char* argv[])
{
	/* register signal handlers */
	signal(SIGINT, abort);

#ifdef __WIN32__
	/* initialize winsock */
	WSAData wData;
	WSAStartup(MAKEWORD(2,2), &wData);
#endif

	/* default pareamters */
	const char *smtp_helo = "example.org";
	const char *smtp_from = "";
	const char *smtp_port = "25";
	const char *smtp_rcpt = NULL;
	unsigned int smtp_probes = 0;
	unsigned int smtp_probe_wait = 1000;
	unsigned int smtp_data_size = 10;

	/* no arguments: show help */
	if (argc < 2)
		usage(argv[0], stderr, 2);

	/* getopts/longopts */
	static struct option longopts[] = { 
		{ "help",	no_argument,		0x0,	'h'	},
		{ "helo",	required_argument,	0x0,	'H'	},
		{ "sender",	required_argument,	0x0,	'S'	},
		{ "count",	required_argument,	0x0,	'c'	},
		{ "wait",	required_argument,	0x0,	'w'	},
		{ "size",	required_argument,	0x0,	's'	},
		{ "port",	required_argument,	0x0,	'p'	},
		{ 0x0,		0,			0x0,	0	}
	}; 
	opterr = 0;
	optind = 0;
	int ch;
	while ( (ch = getopt_long(argc, argv, "H:S:s:hw:c:p:d", longopts, 0x0)
			) != -1)
	{
		switch(ch)
		{
			case 'H':
				smtp_helo = optarg;
				break;
			case 'S':
				smtp_from = optarg;
				break;
			case 's':
				smtp_data_size = strtoul(optarg, NULL, 10);
				break;
			case 'h':
				usage(argv[0], stdout, 0);
				break;
			case 'w':
				smtp_probe_wait = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				smtp_probes = strtoul(optarg, NULL, 10);
				break;
			case 'p':
				smtp_port = optarg;
				break;
			case 'd':
				debug = true;
				break;
			default:
				usage(argv[0], stderr, 2);
				break;
		}
	}
	argc -= optind;
	argv += optind;

	/* no e-mail or mx specified */
	if (argc < 1)
		usage(argv[0], stderr, 2);

	/* mail address */
	smtp_rcpt = argv[0];

	/* generate message with approximatly size */
	string data;
	data += "Subject: SMTP Ping\r\n";
	data += string("From: <") + smtp_from + ">\r\n";
	data += string("To: <") + smtp_rcpt + ">\r\n";
	data += "\r\n";
	while (data.size() / 1024 < smtp_data_size)
	{
		data += "012345678901234567890012345674392584328574392857"
			"0123123123138912378913789\r\n";
	}
	data += "\r\n.\r\n";

	Resolver resolv;
	vector<string> address;

	/* erik@example.org @mailserver */
	if (argc > 1)
	{
		if (argv[1][0] != '@')
			usage(argv[0], stderr, 2);

		/* jmp past '@' */
		const char* domain = argv[1] + 1;

		/* resolve as A/AAAA */
		if (!resolv.Lookup(domain, Resolver::RR_A, address))
			if (debug) fprintf(stderr, "warning: failed to resolve "
				"A for %s\n", domain);
		if (!resolv.Lookup(domain, Resolver::RR_AAAA, address))
			if (debug) fprintf(stderr, "warning: failed to resolve "
				"AAAA for %s\n", domain);

		/* could not resolve, try to use address */
		if (address.empty())
			address.push_back(domain);
	} else
	{
		/* use mailaddress as mx */
		const char* domain = strrchr(smtp_rcpt, '@');

		/* no domain, abort! */
		if (!domain)
			usage(argv[0], stderr, 2);

		/* jmp past '@' */
		domain += 1;

		/* resolve as MX, with A/AAAA fallback */
		vector<string> mx;
		if (!resolv.Lookup(domain, Resolver::RR_MX, mx))
		{
			/* if dns failed, we should not try A/AAAA,
			   only if no data is returned */
			fprintf(stderr, "failed to resolve %s\n", domain);
		} else
		{
			/* no data, try A/AAAAA */
			if (mx.empty())
			{
				if (debug) fprintf(stderr, " no mx, failling "
					"back on A/AAAA record for %s\n",
					domain);

				if (!resolv.Lookup(domain, Resolver::RR_A,
					address))
					if (debug) fprintf(stderr, "failed to "
						"resolve A for %s\n", domain);
				if (!resolv.Lookup(domain, Resolver::RR_AAAA,
					address))
					if (debug) fprintf(stderr, "failed to "
						"resolve AAAA for %s\n",
						domain);
			} else
			{
				/* resolve all mx */
				bool ok;
				for(vector<string>::const_iterator i = mx.begin(); 
						i != mx.end(); 
						i++
					)
				{
					ok = false;
					if (!resolv.Lookup(*i, Resolver::RR_A, address))
						if (debug) fprintf(stderr, "warning: failed "
							"to resolve A for %s\n", i->c_str());
						else
							ok = true;
					if (!resolv.Lookup(*i, Resolver::RR_AAAA, address))
						if (debug) fprintf(stderr, "warning: failed to "
							"resolve AAAA for %s\n", i->c_str());
						else
							ok = true;
					/* could not reslove as either A or AAAA: 
					   maybe it's an IP */
					if (!ok)
						address.push_back(*i);
				}
			}
		}
	}

	/* register statistics */
#define STATS_GLOB(name) \
	double smtp_##name##_min = -1, smtp_##name##_max = -1,\
	smtp_##name##_sum = 0 , smtp_##name##_num = 0;

	STATS_GLOB(connect);
	STATS_GLOB(banner);
	STATS_GLOB(helo);
	STATS_GLOB(mailfrom);
	STATS_GLOB(rcptto);
	STATS_GLOB(data);
	STATS_GLOB(datasent);
	STATS_GLOB(quit);

#define STATS(name, min) \
	double smtp_##name = GetHighResTime();\
	if (smtp_##name - smtp_##min < smtp_##name##_min ||\
	smtp_##name##_min == -1)\
	smtp_##name##_min = smtp_##name - smtp_##min;\
	if (smtp_##name - smtp_##min > smtp_##name##_max ||\
	smtp_##name##_max == -1)\
	smtp_##name##_max = smtp_##name - smtp_##min;\
	smtp_##name##_sum += smtp_##name - smtp_##min; smtp_##name##_num++;

#define STATS_TIME(name) \
	(smtp_##name - smtp_init)
#define STATS_SESSION_TIME(name) \
	(smtp_##name - smtp_connect)

	/* connect to the first working address */
	unsigned int smtp_seq = 0;
	vector<string>::const_iterator i;
	for(i = address.begin(); i != address.end(); i++)
	{
		struct addrinfo *res = NULL, resTmp;

		memset(&resTmp, 0, sizeof(struct addrinfo));
		resTmp.ai_family = AF_UNSPEC;
		resTmp.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(i->c_str(), smtp_port, &resTmp, &res) != 0)
		{
			fprintf(stderr, "getaddrinfo() failed %s\n",
				i->c_str());
			continue;
		}

		/* print header */
		printf("PING %s ([%s]:%s): %d bytes (SMTP DATA)\n", 
			smtp_rcpt, i->c_str(), smtp_port, 
			(unsigned int)data.size());
reconnect:

		/* abort by ctrl+c or if smtp_seq is done */
		if (abort_ping || (smtp_probes && smtp_seq >= smtp_probes)) {
			freeaddrinfo(res);
			break;
		}

		/* sleep between smtp_req */
		if (smtp_seq > 0)
		{
#ifdef __WIN32__
			Sleep(smtp_probe_wait);
#else
			usleep(smtp_probe_wait * 1000);
#endif
		}

		/* only increase if smtp_req > 0 */
		if (smtp_seq > 0)
			smtp_seq++;

		int s = socket(res->ai_family, res->ai_socktype,
			res->ai_protocol);
		if (!s)
		{
			fprintf(stderr, "seq=%u: socket() failed\n", 
				smtp_seq);
			if (smtp_seq == 0) {
				freeaddrinfo(res);
				continue;
			} else {
				goto reconnect;
			}
		}

		/* initiate counters on windows */
#ifdef __WIN32__
		StartCounter();
#endif

		/* start up time */
		double smtp_init = GetHighResTime();

		/* connect */
		if (connect(s, res->ai_addr, res->ai_addrlen) != 0) {
			fprintf(stderr, "seq=%u: connect() failed "
				"%s\n", smtp_seq, i->c_str());
			if (smtp_seq == 0) {
				freeaddrinfo(res);
				continue;
			} else {
				close(s);
				goto reconnect; 
			}
		}
		STATS(connect, init);

		/* if it's working, start smtp_req */
		if (smtp_seq == 0)
			smtp_seq = 1;

		/*
		 * < SMTP Banner
		 */
		string ret, cmd;
		if (!SMTPReadLine(s, ret) || ret != "220")
		{
			fprintf(stderr, "seq=%u: recv: BANNER failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(banner, connect);

		/*
		 * > HELO helo
		 * < 250 OK
		 */
		cmd = string("HELO ") + smtp_helo + "\r\n";
		if (send(s, cmd.c_str(), cmd.size(), 0) != (int)cmd.size())
		{
			fprintf(stderr, "seq=%u: send: failed\n", smtp_seq);
			close(s);
			goto reconnect; 
		}
		if (!SMTPReadLine(s, ret) || ret != "250")
		{
			fprintf(stderr, "seq=%u: recv: HELO failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(helo, connect);

		/*
		 * > MAIL FROM: <address>
		 * < 250 OK
		 */
		cmd = string("MAIL FROM: <") + smtp_from + ">\r\n";
		if (send(s, cmd.c_str(), cmd.size(), 0) != (int)cmd.size())
		{
			fprintf(stderr, "seq=%u: send: failed\n", smtp_seq);
			close(s);
			goto reconnect; 
		}
		if (!SMTPReadLine(s, ret) || ret != "250")
		{
			fprintf(stderr, "seq=%u: recv: MAIL FROM failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(mailfrom, connect);

		/*
		 * > RCPT TO: <address>
		 * < 250 OK
		 */
		cmd = string("RCPT TO: <") + smtp_rcpt + ">\r\n";
		if (send(s, cmd.c_str(), cmd.size(), 0) != (int)cmd.size())
		{
			fprintf(stderr, "seq=%u: send: failed\n", smtp_seq);
			close(s);
			goto reconnect; 
		}
		if (!SMTPReadLine(s, ret) || ret != "250")
		{
			fprintf(stderr, "seq=%u: recv: RCPT TO failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(rcptto, connect);

		/*
		 * > DATA
		 * < 354 Feed me
		 */
		cmd = string("DATA\r\n");
		if (send(s, cmd.c_str(), cmd.size(), 0) != (int)cmd.size())
		{
			fprintf(stderr, "seq=%u: send: failed\n", smtp_seq);
			close(s);
			goto reconnect; 
		}
		if (!SMTPReadLine(s, ret) || ret != "354")
		{
			fprintf(stderr, "seq=%u: recv: DATA failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(data, connect);

		/*
		 * > data...
		 * < ??? Mkay
		 */
		if (send(s, data.c_str(), data.size(), 0) != (int)data.size())
		{
			fprintf(stderr, "seq=%u: send: failed\n", smtp_seq);
			close(s);
			goto reconnect; 
		}
		if (!SMTPReadLine(s, ret))
		{
			fprintf(stderr, "seq=%u: recv: EOM failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(datasent, connect);

		/*
		 * > QUIT
		 * < ??? Mkay
		 */
		cmd = string("QUIT\r\n");
		if (send(s, cmd.c_str(), cmd.size(), 0) != (int)cmd.size())
		{
			fprintf(stderr, "seq=%u: send: QUIT failed\n",
				smtp_seq);
			close(s);
			goto reconnect; 
		}
		if (!SMTPReadLine(s, ret))
		{
			fprintf(stderr, "seq=%u: recv: QUIT failed (%s)\n",
				smtp_seq, ret.c_str());
			close(s);
			goto reconnect; 
		}
		STATS(quit, connect);

		shutdown(s, 2);
		close(s);

		/* print statistics */
		printf("seq=%u, connect=%.2lf ms, helo=%.2lf ms,"
			"mailfrom=%.2lf ms, rcptto=%.2lf ms, datasent=%.2lf ms,"
			"quit=%.2lf ms\n",
				smtp_seq,
				STATS_TIME(connect),
				STATS_SESSION_TIME(helo),
				STATS_SESSION_TIME(mailfrom),
				STATS_SESSION_TIME(rcptto),
				STATS_SESSION_TIME(datasent),
				STATS_SESSION_TIME(quit)
			  );

		/* next loop */
		goto reconnect;
	}

	/* if we successfully connected somewhere */
	if (i != address.end() && smtp_seq > 0)
	{

		printf("\n--- %s SMTP ping statistics ---\n", i->c_str());
		printf("%d e-mail messages transmitted\n", smtp_seq);

#define SHOWSTAT(x) \
	printf(#x " min/avg/max = %.2lf/%.2lf/%.2lf ms\n", \
	smtp_##x##_min, smtp_##x##_num>0?smtp_##x##_sum / smtp_##x##_num:0, \
	smtp_##x##_max);

		SHOWSTAT(connect);
		SHOWSTAT(banner);
		SHOWSTAT(helo);
		SHOWSTAT(mailfrom);
		SHOWSTAT(rcptto);
		SHOWSTAT(data);
		SHOWSTAT(datasent);
		SHOWSTAT(quit);
	} else
	{
		printf("\n--- no pings were sent ---\n");    
	}

#ifdef __WIN32__
	if (abort_ping)
	{
		printf("Aborted by Control-C\n");
	}
	WSACleanup();
#endif
	return 0;
}
