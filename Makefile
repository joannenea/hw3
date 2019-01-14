all: pcaprd.c
	gcc -o pcap_offline pcap_offline.c -lpcap
clean: pcaprd
  rm pcap_offline
