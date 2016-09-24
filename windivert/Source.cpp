/*
* netfilter.c
* (C) 2013, all rights reserved,
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
* DESCRIPTION:
* This is a simple traffic filter/firewall using WinDivert.
*
* usage: netfilter.exe windivert-filter [priority]
*
* Any traffic that matches the windivert-filter will be blocked using one of
* the following methods:
* - TCP: send a TCP RST to the packet's source.
* - UDP: send a ICMP(v6) "destination unreachable" to the packet's source.
* - ICMP/ICMPv6: Drop the packet.
*
* This program is similar to Linux's iptables with the "-j REJECT" target.
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ws2tcpip.h>
#include "windivert.h"

#define MAXBUF  0xFFFF

/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_UDPHDR udp;
} UDPPACKET, *PUDPPACKET;

/*
* Prototypes.
*/

/*
* Entry.
*/
char *victim = "10.100.111.71";
char *attack = "10.100.111.169";


\



int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;
	// Check arguments.
	switch (argc)
	{
	case 2:
		break;
	case 3:
		priority = (INT16)atoi(argv[2]);
		break;
	default:
		fprintf(stderr, "usage: %s windivert-filter [priority]\n",
			argv[0]);
		fprintf(stderr, "examples:\n");
		fprintf(stderr, "\t%s true\n", argv[0]);
		fprintf(stderr, "\t%s \"outbound and tcp.DstPort == 80\" 1000\n",
			argv[0]);
		fprintf(stderr, "\t%s \"inbound and tcp.Syn\" -4000\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL, &payload_len);
		if (ip_header == NULL && ipv6_header == NULL)
		{
			continue;
		}
		// Dump packet info: 
		if (ip_header != NULL)
		{
			inet_pton(AF_INET,victim,&ip_header->DstAddr); //71번 IP로 보내라
			ip_header->Checksum = WinDivertHelperCalcChecksums(packet,packet_len,0);
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u \n",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			if (!WinDivertSend(handle, packet, packet_len, &send_addr, NULL))
				printf("error : don't send");
		}
		putchar('\n');
	}

}


