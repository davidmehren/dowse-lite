#!/bin/env python3
import re
import socket
from functools import lru_cache

import os
import pyshark
from subprocess import Popen, PIPE
import sys
import argparse


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


def guess_ip(interface):
    print("Trying to guess IP of interface " + interface + " ...")
    ipv4 = re.search(re.compile(r'(?<=inet )(.*)(?=\/)', re.M), os.popen('ip addr show ' + interface).read()).groups()[
        0]
    print("My IP seems to be:", ipv4)
    return ipv4


def create_capture(interface, myip, mode):
    if mode == "dns":
        return pyshark.LiveCapture(interface=interface, display_filter="dns and ip.dst != %s" % myip)
    elif mode == "tcp":
        return pyshark.LiveCapture(interface=interface, bpf_filter="tcp", display_filter="ip.dst != %s" % myip)


def generate_packet_str(packet, mode):
    if mode == "dns":
        return packet.sniff_timestamp.split(".")[0] + "|" + packet.ip.src + "|M|" + packet.dns.qry_name.split(".")[
            -1] + "/" + packet.dns.qry_name + "\n"
    elif mode == "tcp":
        return packet.sniff_timestamp.split(".")[0] + "|" + packet.ip.src + "|M|" + get_domain_str(
            packet.ip.dst) + "\n"


def main_app(args):
    print("Running in mode: " + args.mode)
    if args.myip is None:
        args.myip = guess_ip(args.interface)
    print("Initializing Gource...")
    gource = Popen(["gource", "-realtime", "-log-format", "custom", "-"], stdin=PIPE, universal_newlines=True)
    print("Initializing Capture...")
    capture = create_capture(args.interface, args.myip, args.mode)
    for packet in capture.sniff_continuously():
        try:
            gource.stdin.write(generate_packet_str(packet, args.mode))
            gource.stdin.flush()
        except AttributeError:
            pass
        except KeyboardInterrupt:
            capture.close()
            gource.terminate()
            sys.exit(0)


try:
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="Interface to detect traffic on", type=str)
    parser.add_argument("--mode", help="Use RDNS of all TCP traffic (tcp, default) or analyse DNS querys (dns)",
                        default="tcp", choices=["tcp", "dns"])
    parser.add_argument("--myip", help="Set IP of this device if the autodetection leads to wrong results", type=str)
    args = parser.parse_args()
    main_app(args)
except KeyboardInterrupt:
    print("EXIT!")
