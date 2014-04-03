obj-m += hook.o
KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(shell pwd) modules
	gcc -Wall -o nf_user nf_user.c
clean:
	make -C $(KDIR) M=$(shell pwd) clean
	rm -f *odule* nf_user
