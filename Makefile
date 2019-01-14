all: pcap_offline.c
	gcc -o pcap_offline pcap_offline.c -lpcap
clean: pcap_offline
  	rm pcap_offline
