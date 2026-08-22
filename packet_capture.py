"""
PacketCapture: wraps scapy sniffing and converts each packet into the
lightweight event dict DetectionEngine expects. Requires root privileges
and a real network interface to run live (sudo python3 main.py).
"""

import time

import config


def packet_to_event(pkt):
    """Convert a scapy packet into the detection engine's event schema.
    Returns None for packets we don't care about (no IP layer)."""
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in pkt:
        return None

    event = {
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "timestamp": time.time(),
        "payload": b"",
    }

    if TCP in pkt:
        event["proto"] = "TCP"
        event["dst_port"] = int(pkt[TCP].dport)
        event["flags"] = str(pkt[TCP].flags)
        if pkt[TCP].payload:
            event["payload"] = bytes(pkt[TCP].payload)
    elif UDP in pkt:
        event["proto"] = "UDP"
        event["dst_port"] = int(pkt[UDP].dport)
        if pkt[UDP].payload:
            event["payload"] = bytes(pkt[UDP].payload)
    else:
        event["proto"] = pkt[IP].proto  # numeric protocol id (e.g. ICMP=1)

    return event


class PacketCapture:
    def __init__(self, detection_engine):
        self.detection_engine = detection_engine

    def _handle(self, pkt):
        event = packet_to_event(pkt)
        if event:
            self.detection_engine.process_packet(event)

    def start(self):
        """Blocking call - starts live sniffing. Requires root."""
        from scapy.all import sniff
        print(f"[*] Starting capture on interface={config.INTERFACE or 'default'} "
              f"filter='{config.BPF_FILTER}'")
        sniff(iface=config.INTERFACE, filter=config.BPF_FILTER,
              prn=self._handle, store=False)
