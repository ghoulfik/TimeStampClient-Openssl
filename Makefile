CC       := gcc
SRC      := tsa_client_openssl.c
OBJ      := $(SRC:.c=.o)

ifeq ($(OS),Windows_NT)
	TARGET  := tsa_client_openssl.exe
	CFLAGS  := -Wall -Wextra -O2 -I"C:/OPENSSL/include"
	LDFLAGS := -L"C:/OPENSSL/lib" -lssl -lcrypto -lws2_32
	RM_CMD  := cmd /C del /Q /F
else
	UNAME_S := $(shell uname -s 2>/dev/null)
	TARGET := tsa_client_openssl
	CFLAGS := -Wall -Wextra -O2
	OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
	OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

	ifneq ($(strip $(OPENSSL_CFLAGS)),)
		CFLAGS := $(CFLAGS) $(OPENSSL_CFLAGS)
	endif

	ifneq ($(strip $(OPENSSL_LIBS)),)
		LDFLAGS := $(OPENSSL_LIBS)
	else
		ifeq ($(UNAME_S),Darwin)
			LDFLAGS := -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
		else
			LDFLAGS := -lssl -lcrypto
		endif
	endif

	RM_CMD := rm -f
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)
	-$(RM_CMD) *.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM_CMD) *.o $(TARGET)