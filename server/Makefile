CC      ?= $(CROSS_COMPILE)gcc
CFLAGS  ?= -Wall -Wextra -g
TARGET  ?= aesdsocket
SRC     ?= aesdsocket.c
OBJ     ?= $(SRC:.c=.o)
LDFLAGS ?= -lpthread -lrt

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
