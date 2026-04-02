CC ?= cc
SRC = tsa_client_openssl.c
OBJ = $(SRC:.c=.o)

UNAME_S := $(shell uname -s 2>/dev/null)

ifeq ($(OS),Windows_NT)
CC = gcc
TARGET = tsa_client_openssl.exe
CFLAGS = -Wall -Wextra -O2 -I"C:/OPENSSL/include"
LDFLAGS = -L"C:/OPENSSL/lib" -lssl -lcrypto -lws2_32
RM = cmd /C del /Q /F
else ifneq ($(findstring Darwin,$(UNAME_S)),)
TARGET = tsa_client_openssl
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS = -lssl -lcrypto
endif
LDFLAGS = $(OPENSSL_LIBS)
RM = rm -f
else
TARGET = tsa_client_openssl
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS = -lssl -lcrypto
endif
LDFLAGS = $(OPENSSL_LIBS)
RM = rm -f
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)
	-$(RM) *.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM) *.o $(TARGET)