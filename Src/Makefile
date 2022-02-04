#Makefile
LDLIBS += -lpcap

deauth_attack: main.o deauth.o
	gcc -o deauth_attack main.o deauth.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

dot11.o: deauth.cpp
	g++ -c -o deauth.o deauth.cpp

clean:
	rm -f deauth_attack*.o