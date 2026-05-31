# Netdumper

​Automated pentesting tool for capturing IEEE 802.11 frames - WPA2 4-way handshake packets.

# Requirements

- Wi-Fi plate must be support monitoring mode (check the firmware).

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
~$ ./myuser ln -s "$(pwd)/*" "$PREFIX/bin/*"
```

Run:
```bash
~$ ./myuser su -c "/data/data/com.termux/files/usr/bin/python3 /data/data/com.termux/files/home/netdumper/wpa2.py"
```
