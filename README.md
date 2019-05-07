# PCAP Lab ― AED :satellite::loop::loop::loop::loop::computer:
Updated: Spring :two::zero::one::nine:

----
## What is PCAP? :mega:
from the :globe_with_meridians:[Wikipedia](https://en.wikipedia.org/wiki/Pcap) page:

> "In the field of computer network administration, pcap is an application programming interface (API) for **capturing network traffic**. While the name is an abbreviation of a technical term of art (jargon) packet capture, that is not the API's proper name. Unix-like systems implement pcap in the **libpcap library**.

>Monitoring software may use libpcap to capture network packets travelling over a computer network. The pcap API is written in C".

---
## Run the code :airplane:

install `libcap` through apt,
```bash
sudo apt install libcap
```

then compile each source `.cpp` file using the `-lpcap` flag
```bash
g++ source_file.cpp -lpcap
```

----
## What you find over here :pencil:
Some exercises (C/C++) related to the usage of the libpcap library.

* **exercise 1** print some metadata (*caplen*, *len*) about a packet sensed in the network.

`Output example`
```bash
caplen: 64
len: 149
```

* **exercise 2** implement a *remote procedure call* (RPC) that counts the number of packets sensed by the library. Note that this is a stateful computation.

`Output example`
```bash
pkt nr: 1
pkt nr: 2
pkt nr: 3
pkt nr: 4
pkt nr: 5
pkt nr: 6
pkt nr: 7
pkt nr: 8
pkt nr: 9
pkt nr: 10
```

* **exercise 3** recognize IP packets and display their source and destination addresses. Which of them carries TCP data?

`Output example`
```bash
not an IP packet...
not an IP packet...
ip source: 192.168.1.117, ip destination: 216.58.198.34 TCP
ip source: 192.168.1.117, ip destination: 216.58.198.34 TCP
```

----
## changelog
* 07-May-2019 first commit


