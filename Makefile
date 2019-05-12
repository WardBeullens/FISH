CC=gcc
CFLAGS=-I XKCP/bin/generic64/ 
LFLAGS=-L XKCP/bin/generic64/ -lkeccak -lcrypto

IMPLEMENTATION_SOURCE = sign.c merkletree.c test.c
IMPLEMENTATION_HEADERS= sign.h merkletree.h keccaklib

SUSHSY_SOURCE = sushsy/sushsy.c 
SUSHSY_HEADERS= sushsy/sushsy.h sushsy/parameters.h

MUD_SOURCE = mud/mud.c mud/F4.c
MUD_HEADERS= mud/mud.h mud/F4.h mud/parameters.h

sushsy: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) $(SUSHSY_HEADERS) $(SUSHSY_SOURCE)
	gcc -o benchsushsy $(IMPLEMENTATION_SOURCE) $(CFLAGS) $(LFLAGS) $(SUSHSY_SOURCE) -std=c11 -O3 -g -march=native -DSUSHSY

mud: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) $(MUD_HEADERS) $(MUD_SOURCE)
	gcc -o benchmud $(IMPLEMENTATION_SOURCE) $(CFLAGS) $(LFLAGS) $(MUD_SOURCE) -std=c11 -O3 -g -march=native -DMUD

keccaklib: 
	(cd XKCP; make generic64/libkeccak.a)

.PHONY: clean
clean:
	rm -f PQCgenKAT_sign test debug test_offline intermediateValues.txt *.req *.rsp >/dev/null