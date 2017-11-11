# dowse-lite
This is a Dowse-style traffic visualizer using wireshark.
This needs `pyshark`.

## Usage
```
usage: main.py [-h] [--mode {tcp,dns}] [--myip MYIP] interface

positional arguments:
  interface         Interface to detect traffic on

optional arguments:
  -h, --help        show this help message and exit
  --mode {tcp,dns}  Use RDNS of all TCP traffic (tcp, default) or analyse DNS
                    querys (dns)
  --myip MYIP       Set IP of this device if the autodetection leads to wrong
                    results
```
