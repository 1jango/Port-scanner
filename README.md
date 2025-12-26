# \# Port-scanner

# 

# A network security tool for efficient, non-intrusive port discovery. It utilizes raw socket manipulation to perform TCP SYN (half-open) scanning.

# 

# \## Technical Implementation

# The scanner operates at the Transport Layer (Layer 4) of the OSI model:

# 

# 1\. SYN Packet Crafting: Sends a TCP SYN packet to the target.

# 2\. Response Analysis: 

# &nbsp;  - SYN-ACK (0x12): Port is OPEN. The scanner immediately dispatches a RST packet.

# &nbsp;  - RST-ACK (0x14): Port is CLOSED.

# &nbsp;  - No Response: Port is FILTERED.

# 3\. Concurrency: Uses ThreadPoolExecutor for asynchronous port scanning.

# 4\. Service Mapping: Automated protocol identification.

# 

# \## Usage

# Requires administrative/root privileges for raw socket access.

# 

# ```bash

# python src/main.py -t <target> -p <ports>

# python src/main.py -t 127.0.0.1 -p 80,443,8080

# sudo python3 src/main.py -t 127.0.0.1 -p 80,443,8080 (macOS users)

