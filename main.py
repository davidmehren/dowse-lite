import socket
from functools import lru_cache
import pyshark
import os, tempfile


@lru_cache(maxsize=1024)
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


def get_domain_str(ip):
    domain = get_domain(ip)
    return domain.split(".")[-1]+"/"+domain


tmpdir = tempfile.mkdtemp()
pipefile = "/tmp/dowsefifo"
print("Using FIFO", pipefile)
try:
    os.mkfifo(pipefile)
except OSError as e:
    print("Failed to create FIFO: %s" % e)
with open(pipefile, 'w') as fifo:
    print("Initializing Capture...")
    capture = pyshark.LiveCapture(interface='bnep0', bpf_filter="tcp", display_filter="ip.dst != 192.168.44.129")
    capture.set_debug()
    for packet in capture.sniff_continuously():
        try:
            fifo.write(packet.sniff_timestamp.split(".")[0] + "|" + packet.ip.src + "|M|" + get_domain_str(packet.ip.dst)+"\n")
            fifo.flush()
        except AttributeError:
            pass #print(packet)