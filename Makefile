CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -I"C:/OPENSSL/include"
LDFLAGS  = -L"C:/OPENSSL/lib" -lssl -lcrypto -lws2_32
RM       = cmd /C del /Q /F
TARGET   = tsa_client_openssl.exe
SRC      = tsa_client_openssl.c
OBJ      = $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)
	-$(RM) *.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-$(RM) *.o $(TARGET)