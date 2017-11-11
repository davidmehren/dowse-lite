import socket
from functools import lru_cache
import pyshark
from subprocess import Popen, PIPE
import sys


def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


@lru_cache(maxsize=1024)
def get_domain_str(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain.split(".")[-1] + "/" + domain
    except socket.herror:
        return "IPs/" + ip


def main_app():
    print("Initializing Gource...")
    gource = Popen(["gource", "-realtime", "-log-format", "custom" ,"-"], stdin=PIPE, universal_newlines=True)
    print("Initializing Capture...")
    capture = pyshark.LiveCapture(interface='wlp3s0', bpf_filter="tcp", display_filter="ip.dst != 192.168.178.73")
    for packet in capture.sniff_continuously():
        try:
            gource.stdin.write(packet.sniff_timestamp.split(".")[0] + "|" + packet.ip.src + "|M|" + get_domain_str(
                packet.ip.dst) + "\n")
            gource.stdin.flush()
        except AttributeError:
            pass
        except KeyboardInterrupt:
            capture.close()
            gource.terminate()
            sys.exit(0)


try:
    main_app()
except KeyboardInterrupt:
    print("EXIT!")