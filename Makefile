
LIBMNL_DIR = $(realpath ./)/libmnl_build
LIBNFTNL_DIR = $(realpath ./)/libnftnl_build

LIBS = -L$(LIBMNL_DIR)/install/lib -lmnl -lkeyutils
INCLUDES = -I$(LIBMNL_DIR)/libmnl-1.0.5/include
CFLAGS = -static -no-pie -fno-PIE -g

exploit: exp.c
	gcc -o exploit exploit.c $(LIBS) $(INCLUDES) $(CFLAGS)


prerequisites: libmnl-build libkeyutils-apt

libmnl-build : libmnl-download
	tar -C $(LIBMNL_DIR) -xvf $(LIBMNL_DIR)/libmnl-1.0.5.tar.bz2
	cd $(LIBMNL_DIR)/libmnl-1.0.5 && ./configure --enable-static --prefix=`realpath ../install`
	cd $(LIBMNL_DIR)/libmnl-1.0.5 && make -j`nproc`
	cd $(LIBMNL_DIR)/libmnl-1.0.5 && make install


libmnl-download :
	mkdir $(LIBMNL_DIR)
	wget -P $(LIBMNL_DIR) https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2

libkeyutils-apt :
	sudo apt-get install libkeyutils-dev

run:
	./exploit

clean:
	rm -f exploit
	rm -rf $(LIBMNL_DIR)


