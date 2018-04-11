all: arp_spoof

arp_spoof: main.o
	g++ -o arp_spoof main.o -lpcap

main.o:
	g++ -o main.o -c main.cpp

clean:
	rm -f arp_spoof
	rm -f *.o

