#
# seteuid build files

seteuid: main.o
	gcc main.o -o seteuid -lcrypt

main.o: main.c
	gcc main.c -Wall -Wextra -pedantic -O2 -c -o main.o

clean:
	rm -f main.o seteuid

install:
	cp seteuid /usr/bin/
	chown root:seteuid /usr/bin/seteuid
	chmod g+s /usr/bin/seteuid
	setcap 'CAP_SETUID+eip' /usr/bin/seteuid
