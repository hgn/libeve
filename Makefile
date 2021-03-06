# SPDX-License-Identifier: The Unlicense

OBJ := ev.o
LIBRARY := ev.a

CC     ?= gcc
LIBS   := -lrt  # for clock_gettime(2)
CFLAGS := -Wall -Wextra -Wunused -pipe -Wwrite-strings -Wsign-compare \
				 -Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
				 -fno-strict-aliasing -fno-common -Wformat-security \
				 -Wformat-y2k -Winit-self -Wpacked -Wredundant-decls \
				 -Wstrict-aliasing=3 -Wswitch-default -Wswitch-enum \
				 -Wno-system-headers -Wundef -Wvolatile-register-var \
				 -Wcast-align -Wbad-function-cast -Wwrite-strings \
				 -Wold-style-definition  -Wdeclaration-after-statement \
				 -Wfloat-equal -Wundef -Wshadow -Wpointer-arith \
				 -Wcast-align -Wstrict-prototypes -Wstrict-overflow=5 \
				 -Wwrite-strings  -Waggregate-return -Wcast-qual \
				 -Wswitch-default -Wconversion -Wunreachable-code \
				 -Wno-format-extra-args -Wno-format-zero-length \
				 -Wformat-nonliteral -Werror=implicit-function-declaration
#CFLAGS += -fsanitize=address  -fsanitize=undefined
CFLAGS += -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables
CFLAGS += -fstack-protector-strong -grecord-gcc-switches
CFLAGS += -Wl,-z,defs -Wl,-z,relro -fexceptions
CFLAGS += -ftrapv
CFLAGS += -std=gnu11
CFLAGS += -Wno-unused-function
CFLAGS += -I.

# we enable SDT markers by default, compile
# with "SDT=disable make" if you want no SDT
# markers
ifneq ($(SDT),disable)
CFLAGS += -DSDT_ENABLED
endif

CFLAGS += -ggdb3 -Werror

EXTRA_CFLAGS := -DLIBEVE_DEBUG

.PHONY: all clean cscope

all: $(LIBRARY) test
	make -C examples all

%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS) $< -o $@

$(LIBRARY): $(OBJ)
	ar rcs $(LIBRARY) $(OBJ)
	@rm -f libev.a
	ln ev.a libev.a

test: $(OBJ) test.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS) -o test $(OBJ) test.c

cscope:
	find ${CURDIR} -name "*.[chsS]" > cscope.files
	cscope -b -q

clean:
	rm -f $(OBJ) ev.a libev.a test perf.data perf.data.old
	make -C examples clean

distclean: clean
	rm -f ${CURDIR}/cscope.*

