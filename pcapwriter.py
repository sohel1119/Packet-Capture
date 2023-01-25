from scapy.all import IP, UDP, Raw
import binascii
from scapy.utils import PcapWriter

pcapfilename = "test.pcap"
pktdump = PcapWriter(pcapfilename, append=False, sync=True)
pktStorage = []


def pcap(src, dst, payload):

    try:
        packet = IP(src=str(src), dst=str(dst)) / UDP(sport=2123,
                                                      dport=2123)/Raw(binascii.unhexlify(payload))
        return packet

    except ValueError:
        print('Error ')


pkt = pcap('3.3.3.3', '1.1.1.1', '32010004000000000c3d0000')
pktdump.write(pkt)
pktStorage.append(pkt)

for pkt in pktStorage:
    pktdump.write(pkt)

pktdump.close()
