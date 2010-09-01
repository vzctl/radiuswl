# Author: lex@realisticgroup.com (Alexey Lapitsky)

obj-m := radiuswl.o compat_xtables.o
radiuswl-objs := ipt_radiuswl.o radius.o whitelist.o

all: libxt_radiuswl
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) KBUILD_EXTMOD=$(PWD) modules

libxt_radiuswl: 
	$(CC) -shared libxt_radiuswl.c -fPIC -o libxt_radiuswl.so


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean; rm *.so
