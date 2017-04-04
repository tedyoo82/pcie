C_SRC := dmaxfer_test.c
#CFLAGS := -Werror -Wall -I ../modules
CFLAGS := -Wall -I ../modules
CROSS_COMPILE = arm-linux-gnueabihf-
CC = $(CROSS_COMPILE)gcc
ARCH = arm 

RM := rm -rf

ELF := dmaxfer_test
OBJ := $(patsubst %.c,%.o,$(C_SRC))

.PHONY: all
all: $(ELF) $(OBJ)

.PHONY:
clean:
	$(RM) $(ELF) *.o

$(OBJ): $(C_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(ELF): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ -lpthread

