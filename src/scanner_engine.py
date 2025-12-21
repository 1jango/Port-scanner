import socket
from scapy.all import IP, TCP, ICMP, sr1

class ScannerEngine:
    def __init__(self, target_ip, timeout=1):
        self.target_ip = target_ip
        self.timeout = timeout

    def is_host_alive(self):
        """Sends an ICMP Echo Request to check if the target is reachable."""
        pkt = IP(dst=self.target_ip)/ICMP()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        return resp is not None

    def get_service_name(self, port, protocol='tcp'):
        """Translates a port number to its common service name (80 -> http)."""
        try:
            return socket.getservbyport(port, protocol)
        except (socket.error, OverflowError):
            return "unknown"

    def syn_scan(self, port):
        """Performs a Stealth SYN Scan (half-open scanning)."""
        # 'S' flag stands for SYN
        syn_pkt = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
        response = sr1(syn_pkt, timeout=self.timeout, verbose=0)

        if response is None:
            return "Filtered"
        elif response.haslayer(TCP):
            # 0x12 (SYN-ACK) means the port is OPEN
            if response.getlayer(TCP).flags == 0x12:
                # Send RST (Reset) to close the connection immediately (stealthy)
                rst_pkt = IP(dst=self.target_ip)/TCP(dport=port, flags="R")
                sr1(rst_pkt, timeout=self.timeout, verbose=0)
                return "OPEN"
            # 0x14 (RST-ACK) means the port is CLOSED
            elif response.getlayer(TCP).flags == 0x14:
                return "Closed"
        return "Unknown"