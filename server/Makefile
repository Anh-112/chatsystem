CC      = gcc
CFLAGS  = -Wall -O2 -pthread
SRCS_C  = crypto_lib.c

all: chat_server chat_client

chat_server: chat_server.c $(SRCS_C) chat_server.h crypto_lib.h
	$(CC) $(CFLAGS) -o $@ chat_server.c $(SRCS_C)

chat_client: chat_client.c $(SRCS_C) chat_server.h crypto_lib.h
	$(CC) $(CFLAGS) -o $@ chat_client.c $(SRCS_C)

clean:
	rm -f chat_server chat_client *.o

.PHONY: all clean
