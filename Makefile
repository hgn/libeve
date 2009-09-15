EPOLL      :=1 
BUILD_TYPE := testing

TARGET = ev_test

OBJ := ev.o main.o

LIBS   := -lrt  # for clock_gettime(2)
CC     := gcc
CFLAGS := -Wall -g -W -pipe -Wwrite-strings -Wsign-compare \
				 -Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
				 -fno-strict-aliasing -fno-common 

ifdef EPOLL
				EXTRA_CFLAGS := -DHAVE_EPOLL
endif

all: $(TARGET)

%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS) $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS) -o $(TARGET) $(OBJ)

clean:
	-rm -f $(OBJ) $(TARGET)

