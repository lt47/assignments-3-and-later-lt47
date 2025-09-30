CC      := $(CROSS_COMPILE)gcc
CFLAGS  := -Wall -Wextra -g
TARGET  := aesdsocket
SRC     := aesdsocket.c
OBJ     := $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
