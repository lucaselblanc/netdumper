## Netdumper

 ​Automated wireless pentesting/auditing tool for IEEE 802.11 monitoring and WPA/WPA2 4-Way Handshake capture.

## The tool automatically:

- Installs required packages automatically (GNU/Linux Only).
- Detects wireless interfaces: managed/monitor.
- Enables monitor mode.
- Scans nearby access points and clients.
- Identifies active AP ↔ Client pairs.
- Performs targeted deauthentication.
- Captures WPA/WPA2 handshakes.
- Verifies captured handshakes.
- Restores network services after execution.

## Requirements

- The Wireless Network Interface Card (WNIC) Chipset/Driver Must Support Monitor Mode With Packet Injection.

## Permissions

- Root/SuperUser privileges are required:

```bash
~$ ./myuser su
root@distro:/home/myuser#
```

## Linux

Clone The Repository:
```bash
~$ ./myuser git clone https://github.com/lucaselblanc/netdumper.git
```

 The following packages will be installed automatically if missing:

- iw
- aircrack-ng
- net-tools
- wireless-tools

 Run:
```bash
~$ su
root@distro:/home/myuser# python3 ./netdumper/wpa2.py
```

## Termux

 Note: Monitor Mode and Packet Injection support on Android devices depends on the external Wi-Fi adapter, kernel support, and driver availability.

Clone The Repository:
```bash
~$ git clone https://github.com/lucaselblanc/netdumper.git
```

 Unlike traditional GNU/Linux environments, NetDumper does not automatically install dependencies on Termux. Some required packages may not be available in the default Termux repositories and must be compiled or installed manually.

Example:

 Install The Necessary Packages / Depencies Manually:
```bash
~$ git clone https://github.com/<project>.git && cd <project>
~/project $ autoreconf -i
~/project $ ./configure
~/project $ make
~/project $ make install
```

## Required binaries:

- iw //binary
- aircrack-ng //binary
- airmon-ng //shell script
- airodump-ng //binary
- aireplay-ng //binary
- ifconfig //binary
- iwconfig //binary

## Verify Installation:

```bash
~$ which iw
~$ which aircrack-ng
~$ which airmon-ng
~$ which airodump-ng
~$ which aireplay-ng
~$ which ifconfig
~$ which iwconfig
```

 Expected Output:

```bash
~$ which <binary>
/data/data/com.termux/files/usr/bin/<binary>
~$
```

 Run:
```bash
~$ su -c "/data/data/com.termux/files/usr/bin/python3 /data/data/com.termux/files/home/netdumper/wpa2.py"
```

## Output Files

 During execution the following files may be generated:

```txt
netdumper.log
airodump.csv
802.11-01.cap
802.11-02.cap
802.11-03.cap
...
```

## Limitations

- WPA/WPA2 only.
- Requires clients associated with an access point.
- Depends on monitor mode support.
- Depends on packet injection support for deauthing.

## Legal Notice

 This project is intended exclusively for authorized wireless security assessments, research, and educational purposes. Users are solely responsible for ensuring compliance with applicable laws, regulations, and authorization requirements before using this software.
