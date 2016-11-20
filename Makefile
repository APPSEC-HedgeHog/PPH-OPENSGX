DIR = $(shell pwd)
QEMU := $(DIR)/qemu/x86_64-linux-user/qemu-x86_64
OPENSGX := $(DIR)/opensgx
USER := $(DIR)/user/test/simple
NJOB := $(shell nproc)
pph := $(DIR)/PolyPasswordHasher-C

$(shell cp $(USER).c user/enclu.c)

all: $(USER) $(QEMU) $(pph)
	(cd user; $(OPENSGX) -t $(USER))

$(USER): FORCE
	(cd user; make)

$(QEMU): FORCE
	(cd qemu; make -j $(NJOB))

$(pph): FORCE
	cd $(pph); autoreconf --install; ./configure; make; make install

.PHONY: FORCE
