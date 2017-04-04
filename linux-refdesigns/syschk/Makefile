C_SRC := syschk.c
CFLAGS := -Werror -Wall
CROSS_COMPILE = arm-linux-gnueabihf-
CC = $(CROSS_COMPILE)gcc

RM := rm -rf

ELF := syschk
OBJ := $(patsubst %.c,%.o,$(C_SRC))

.PHONY: all
all: $(ELF) $(OBJ)

.PHONY:
clean:
	$(RM) $(ELF) *.o

$(OBJ): $(C_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(ELF): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ -l curses

