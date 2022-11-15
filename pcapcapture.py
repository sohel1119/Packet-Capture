import scapy.all as scapy
t = scapy.AsyncSniffer(iface="PutInterfaceName",filter="udp port 2123")
t.start()  # before sending packets
Pkts=t.stop()  #after sending packets
scapy.wrpcap("/tmp/test1.pcap" ,Pkts)