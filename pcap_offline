#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
	int i;
	char filter[30];
	char errbuff[PCAP_ERRBUF_SIZE], tmbuf[64], buf[64];
	const char filename[] = "amqps.pcapng";
	int packet_num = 0;
	strcpy(filter, "");
	if(argc >= 2)
	{
		strcpy(filter, argv[1]);
		for(i=2; i<argc; i++)
		{
			strcat(filter, " ");
			strcat(filter, argv[i]);
		}
	}
	//open file offline
	pcap_t *handle = pcap_open_offline(filename, errbuff);
	if(!handle)
	{
		printf("pcap_open_offline() : %s\n",errbuff);
		exit(1);
	}
	printf("Open file : %s\n",filename);

	struct bpf_program filter_code;
	//compile filter
	if(pcap_compile(handle, &filter_code, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		printf("pcap_compile : %s\n", pcap_geterr(handle));
		pcap_close(handle);
		exit(1);
	}
	if(strlen(filter)!=0)
		printf("Filter : %s\n", filter);
	//packet reading
	while(1)
	{
		struct pcap_pkthdr *header = NULL;
		const u_char *content = NULL;
		int ret = pcap_next_ex(handle, &header, &content);
		if(ret == 1)
		{
			if(pcap_offline_filter(&filter_code, header, content) != 0)
			{
				//show packet number
				printf("----------------\n");
				printf("Packet # %d\n", ++packet_num);	
				
				//show the size in bytes of the packet
				printf("Packet size : %d bytes\n", header->len);

				//show Epoch time
				time_t nowtime = header->ts.tv_sec;
				struct tm *nowtm;
				nowtm = localtime(&nowtime);
				strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
				printf("Epoch Time : %s.%06ld\n", tmbuf, header->ts.tv_sec);

	//			printf("Epoch Time : %s", asctime(gmtime(((time_t)&header->ts.tv_sec))));		
				
				//show port and address
				struct ip *ip;
				struct tcphdr *tcp;
				ip = (struct ip*)(content+sizeof(struct ether_header));
				tcp = (struct tcphdr*)(content+sizeof(struct ether_header)+sizeof(struct ip));

				printf("Source port : %d\n", tcp->source);//source port
				printf("Destination port : %d\n", tcp->dest);//dest port

				printf("Source address : %s\n", inet_ntoa(ip->ip_src));//source addr
				printf("Destination address : %s\n",inet_ntoa(ip->ip_dst));//dest addr
			}
		}
		else if(ret == -2)
		{
			printf("No more packet from file.\n");
			break;
		}
	}
	pcap_close(handle);
	return 0;
}
