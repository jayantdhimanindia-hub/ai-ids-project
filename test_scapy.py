from scapy.all import sniff, conf
print("Scapy working!")
print("\nNetwork interfaces:")
for iface in conf.ifaces:
    print(" -", iface)