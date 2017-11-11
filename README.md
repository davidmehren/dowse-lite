# dowse-lite
This is a Dowse-style traffic visualizer using wireshark.
This needs `pyshark`.

## Usage
- Set your interface and your local IP in `main.py` (this should be confgurable).
- Start the script.
- Use something like `cat /tmp/dowsefifo |gource --realtime --log-format custom -` to start the visualization.
