#!/usr/bin/env python3
"""
Bank Network Sentinel — entry point
Author: meterpreter
"""
import queue
import time
from bns.capture import PacketCapture
from bns.parser import TrafficParser
from bns.detector import DetectionEngine
from bns.response import ResponseHandler
from bns.config import INTERFACE

def main():
    print("""
    ╔══════════════════════════════════════════╗
    ║   Bank Network Sentinel v1.0            ║
    ║   Author: meterpreter                    ║
    ║   Real-time banking network IDS          ║
    ╚══════════════════════════════════════════╝
    """)

    q = queue.Queue(maxsize=10000)
    capture = PacketCapture(interface=INTERFACE, packet_queue=q)
    parser = TrafficParser()
    detector = DetectionEngine()
    responder = ResponseHandler()

    capture.start()
    print(f"[+] Capturing on {INTERFACE}... (Ctrl+C to stop)")

    try:
        while True:
            try:
                pkt = q.get(timeout=1.0)
            except queue.Empty:
                continue
            rec = parser.parse(pkt)
            alerts = detector.detect(rec)
            if alerts:
                responder.handle(alerts)
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
    finally:
        capture.stop()

if __name__ == "__main__":
    main()
