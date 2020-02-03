#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

echo "root:toor" | chpasswd

apt update
apt install tcpreplay tshark wget -y

#test w single pcap
wget https://download.netresec.com/pcap/ists-12/2015-03-07/snort.log.1425741002 -O 1.pcap

for pcap in *.pcap
do
  tcpprep -i $pcap -o $pcap.cache -a bridge
  tcprewrite --endpoints=1.2.3.4:4.3.2.1 --infile=$pcap --outfile=$pcap.addresses --cache=$pcap.cache
  editcap -t 154000000 $pcap.addresses $pcap.addresses.time
done
