# Netdumper

​Automated pentesting tool for capturing IEEE 802.11 frames - WPA2 4-way handshake packets.

# Requirements

- The Wireless Network Interface Card (WNIC) Chipset/Driver Must Support Monitor Mode.

- Being In SuperUser Mode:

```bash
~$ ./myuser su
```

# Run

## Linux: 

Clone The Repository:
```bash
~$ ./myuser git clone https://github.com/lucaselblanc/netdumper.git
```

Run:
```bash
~$ python3 netdumper/wpa2.py"
```

## Termux: 

Clone The Repository:
```bash
~$ ./myuser git clone https://github.com/lucaselblanc/netdumper.git
```

Install The Necessary Packages/Depencies Manually:
```bash
~$ ./myuser git clone https://github.com/*.git && cd *
~$ ./myuser make
~$ ./myuser chmod +x *
```

Run:
```bash
~$ ./myuser su -c "/data/data/com.termux/files/usr/bin/python3 /data/data/com.termux/files/home/netdumper/wpa2.py"
```
