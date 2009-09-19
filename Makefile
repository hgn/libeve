EPOLL      :=1 
BUILD_TYPE := testing

OBJ := ev.o

LIBS   := -lrt  # for clock_gettime(2)
CC     := gcc
CFLAGS := -Wall -Wextra -pipe -Wwrite-strings -Wsign-compare \
				 -Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
				 -fno-strict-aliasing -fno-common -Wformat-security \
				 -Wformat-y2k -Winit-self -Wpacked -Wredundant-decls \
				 -Wstrict-aliasing=3 -Wswitch-default -Wswitch-enum \
				 -Wno-system-headers -Wundef -Wvolatile-register-var \
				 -Wcast-align -Wbad-function-cast -Wwrite-strings \
				 -Wold-style-definition  -Wdeclaration-after-statement

CFLAGS += -ggdb3 -Werror

ifdef EPOLL
				EXTRA_CFLAGS := -DHAVE_EPOLL
endif

all: test bench

%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS) $< -o $@

test: $(OBJ) test.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS) -o test $(OBJ) test.c

bench: $(OBJ) bench.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS) -o bench $(OBJ) bench.c

clean:
	-rm -f $(OBJ) test bench

