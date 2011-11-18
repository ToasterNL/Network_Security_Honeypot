#!/bin/sh
mkdir suricata
cd suricata
git clone git://phalanx.openinfosecfoundation.org/oisf.git
svn co https://svn.ntop.org/svn/ntop/trunk/PF_RING/
cd PF_RING/kernel
make
insmod ./pf_ring.ko
cp kernel/linux/pf_ring.h /usr/include/linux/

cd ../userland
make
cd lib
make install

cd oisf
./configure --enable-pfring --with-libpfring-includes=`pwd`/../PF_RING/userland/lib/ --prefix=`pwd`/../build/
make
make install

