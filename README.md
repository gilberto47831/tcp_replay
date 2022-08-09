# tcp_replay
Replay captured tcp traffic (pcaps).

Dependences:
Pcap, dumbnet

Usage:

```bash
$ ./replay <cfg file>
```

cfg file format:
```
pcap file
victim ip
victim mac
victim port
attacker ip 
attacker mac
attacker port
replay victim ip
replay victim mac
replay victim port
replay attacker ip
replay attacker mac
replay attacker port
net interface
timing (continuous, delay, exact)
```
