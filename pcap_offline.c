#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>
#include <time.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>


int main(int argc, char** argv)
{
	char errbuf[512] = {'\0'};
	struct pcap_pkthdr *header;
	const struct ip *ip;
	const struct tcphdr *tcp;
	const u_char *packet;
	u_int size_ip = sizeof(struct ip);
	u_int size_ether = sizeof(struct ether_header);
	int i;
	int pktcnt = 0;
	char filter[50];
	strcpy(filter, "");
	
	if(argc >= 3){
		i = 3;
		strcpy(filter, argv[2]);
		while(i<argc){
			strcat(filter, " ");
			strcat(filter, argv[i]);
			i++;
		}
		//printf("%s\n",filter);
	}

	// open pcap file
	pcap_t *handle = pcap_open_offline(argv[1],errbuf);
	if(!handle){
		printf("fail to open %s\n", argv[1]);
		exit(1);
	}
	printf("File name : %s\n\n", argv[1]);



	//compile filter
    struct bpf_program fcode;
    if(-1 == pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }//end if



	while(pcap_next_ex(handle, &header, &packet) >= 0)
	{
		if(pcap_offline_filter(&fcode, header, packet) != 0) {  
            
			char tmbuf[64];
			time_t nowtime = header->ts.tv_sec;
			struct tm *nowtm = localtime(&nowtime);
			strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

			ip = (struct ip*)(packet + size_ether);
			tcp = (struct tcphdr*)(packet + size_ether + size_ip);

			printf("Packet # %d\n", pktcnt++);
			printf("Packet size :\t%d bytes\n", header->len);
			printf("Epoch time :\t%s.%06ld\n", tmbuf, header->ts.tv_usec);
			printf("src port :\t%d\n", tcp->source);
			printf("dst port :\t%d\n", tcp->dest);
			printf("src addr :\t%s\n", inet_ntoa(ip->ip_src));
			printf("dst addr :\t%s\n", inet_ntoa(ip->ip_dst));
			printf("=====\n");

        }
	}
	pcap_close(handle);
	return 0;
}
