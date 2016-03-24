CC?= $(CROSS_COMPILE)gcc

EXE = netman_watch_dns
EXE_OBJ = $(EXE).o

INSTALLED_EXE += $(EXE)

CFLAGS += -Wall -Wno-unused-result

INC_FLAG += $(shell pkg-config --cflags --libs libsystemd) -I. -O2
LIB_FLAG += $(shell pkg-config  --libs libsystemd)

DESTDIR ?= /
SBINDIR ?= /usr/sbin

all: $(EXE)

%.o: %.C
	$(CC) -c $< $(CFLAGS) $(INC_FLAG)-o $@

$(EXE): $(EXE_OBJ)
	$(CC) $^ $(LDFLAGS) $(LIB_FLAG) -o $@

clean:
	rm -f $(EXE) *.o

install:
		install -m 0755 -d $(DESTDIR)$(SBINDIR)
		install -m 0755 $(EXE) $(DESTDIR)$(SBINDIR)
