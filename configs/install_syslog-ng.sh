mkdir syslog-ng
cd syslog-ng
apt-get download syslog-ng
apt-get download libcap2
apt-get download libevtlog0
dpkg -X syslog-ng* .
dpkg -X libcap2* .
dpkg -X libevtlog0* .
rm syslog-ng*
rm libcap2*
rm libevtlog0*
