OBJ := ev.o
LIBRARY := ev.a

LIBS   := -lrt  # for clock_gettime(2)
CC     := gcc
CFLAGS := -Wall -Wextra -Wunused -pipe -Wwrite-strings -Wsign-compare \
				 -Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
				 -fno-strict-aliasing -fno-common -Wformat-security \
				 -Wformat-y2k -Winit-self -Wpacked -Wredundant-decls \
				 -Wstrict-aliasing=3 -Wswitch-default -Wswitch-enum \
				 -Wno-system-headers -Wundef -Wvolatile-register-var \
				 -Wcast-align -Wbad-function-cast -Wwrite-strings \
				 -Wold-style-definition  -Wdeclaration-after-statement

#CFLAGS += -ggdb3 -Werror

EXTRA_CFLAGS := -DHAVE_EPOLL -DLIBEVE_DEBUG

all: $(LIBRARY) test

%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS) $< -o $@

$(LIBRARY): $(OBJ)
	ar rcs $(LIBRARY) $(OBJ)

test: $(OBJ) test.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS) -o test $(OBJ) test.c

clean:
	-rm -f $(OBJ) test

