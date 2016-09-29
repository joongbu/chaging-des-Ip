#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ws2tcpip.h>
#include "windivert.h"
#define MAXBUF  0xFFFF
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_UDPHDR udp;
} UDPPACKET, *PUDPPACKET;

char *victim;
char *attack;
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
	victim = (char *)malloc(15);
	attack = (char *)malloc(15);
	printf("filltering ip : ");
	scanf_s("%s", victim);
	printf("by pass ip : ");
	scanf_s("%s", attack);
	printf("victim IP : %s\n", victim);
	printf("attack IP : %s\n", attack);

	// Main loop:
	UINT32 Ip;
	inet_pton(AF_INET, victim, &Ip);
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
			if (Ip == ip_header->DstAddr)
			{
				inet_pton(AF_INET, attack, &ip_header->DstAddr); //changing IP
				ip_header->Checksum = WinDivertHelperCalcChecksums(packet, packet_len, 0);
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
				printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u \n",
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				if (!WinDivertSend(handle, packet, packet_len, &send_addr, NULL))
					printf("error : don't send");
			}
		}
		putchar('\n');
	}

}



