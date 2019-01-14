all: pcaprd.c
	gcc -o pcaprd pcaprd.c -lpcap
clean: pcaprd
  rm pcaprd
