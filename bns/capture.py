# Packet capture module
# Author: meterpreter

import threading
import queue
import time
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR

class PacketCapture:
    def __init__(self, interface="eth0", packet_queue=None):
        self.interface = interface
        self.queue = packet_queue or queue.Queue(maxsize=10000)
        self.running = False

    def _handle_packet(self, pkt):
        try:
            self.queue.put_nowait(pkt)
        except queue.Full:
            pass  # drop under overload

    def start(self):
        self.running = True
        self.thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self.thread.start()

    def _sniff_loop(self):
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: not self.running,
        )

    def stop(self):
        self.running = False
