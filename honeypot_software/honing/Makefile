obj-m += honing.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

sys_execve = $(shell grep 'sys_execve' /boot/System.map-$(shell uname -r) | head -c 16)

load:   honing.ko
	insmod honing.ko sys_execve_addr=0x$(sys_execve)

