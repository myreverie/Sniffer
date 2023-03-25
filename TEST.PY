from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils 
def packet_callback(win_pcap, param, header, pkt_data):
    # Assuming IP (for real parsing use modules like dpkt)
    print(pkt_data)

WinPcapUtils.capture_on("*Ethernet*", packet_callback)