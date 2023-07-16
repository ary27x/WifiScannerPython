from scapy.all import *
import sys
import os
import threading
import time
import random
from colorama import Fore , Back , Style

''' 
~RUN AS ROOT~
<USAGE>:    
python wifiscanner.py <interface> <noise_filter_flag>

-> <interface> : this should refer to the interface name which is ALREADY in monitor mode
-> <noise_filter_flag> : this should either be 0 or 1; 1 - would show all the noise tapped by the interface as <UNKNOWN>
                                                       0 - would not display that
                                                       
EXAMPLE: python wifijammer wlan0mon 1
'''

CURRENT_CHANNEL = 1 # channel which is being tapped
channels = [1,2,3,4,5,6,7,8,9,10]
lock = threading.Lock()

IFACE = sys.argv[1]
NOISE_FILTER_FLAG = int(sys.argv[2]) # 1 for true and 0 for false

devices_found = set()
counter = 0
pkt_counter = 0
daemonFlag = True

def channelHopper():	# switching channels using terminal
    while True: 
        channel = random.choice(channels)
        os.system("iw dev wlan0 set channel {}".format(channel))
        with lock:	# keeping track of current channel 
            global CURRENT_CHANNEL
            CURRENT_CHANNEL = channel
        if not(daemonFlag):
        	break 
        time.sleep(0.2)

def handler(packet):
    global pkt_counter
    pkt_counter = pkt_counter + 1  
    if packet.haslayer(Dot11Beacon):
                    beaconFrame = packet.getlayer(Dot11Beacon)
                    if (beaconFrame.payload and (beaconFrame.payload.ID == 0)):
                    	name = beaconFrame.payload.info.decode('ascii')
                    else:
                      if (NOISE_FILTER_FLAG == 1): 	# check for noise
                      	return
                      name = "<UNKNOWN>"
                    if (beaconFrame.haslayer(Dot11EltDSSSet)):
                            	channelFrame = beaconFrame.getlayer(Dot11EltDSSSet)
                            	channel = channelFrame.channel
        
    else:
    	if (NOISE_FILTER_FLAG == 1):
                      return
    	name = "<UNKNOWN>" 	#default display values for noise check turned to 0
    	channel = 0         
    if packet.haslayer(Dot11):
        packet_dot11 = packet.getlayer(Dot11)
        if packet_dot11.addr2 and (packet_dot11.addr2 not in devices_found):
                devices_found.add(packet_dot11.addr2)
                ssid = packet_dot11.addr2
                global counter
                counter = counter + 1
                print(Fore.RED + "#", counter , '\t' ,Fore.GREEN+ ssid ,"\t" , Fore.YELLOW + name , "\t\t" , Fore.MAGENTA + str(channel))
                print()     	

hopperThread = threading.Thread(target = channelHopper)
hopperThread.start()	# starting of hopper thread

print("\n","~ary27x" , "\n")
print(Style.BRIGHT + Fore.BLUE + "[*]Monitoring Interface {}".format(IFACE) ) 
if (NOISE_FILTER_FLAG == 1):
	print("[!]Noise Filter: " +  Fore.RED +"ON")
else:
	print("[!]Noise Filter: " +  Fore.RED + "OFF")
print(Fore.BLUE + "[!]Ctrl + C To Exit")

print("\n" ,Style.BRIGHT+ Fore.RED+ "No.",'\t',Fore.GREEN + "<SSID>",'\t\t',Fore.YELLOW + "<NAME>" ,Fore.MAGENTA+ "\t\t" , "<CHANNEL>" "\n")

sniff(iface = IFACE , prn = handler) 	# forwading eack packet to handler

daemonFlag = False 	# hopper thread kill flag

print(Fore.BLUE + "\nCaptured {} Packets".format(pkt_counter))
print("Number Of Devices Found: " , len(devices_found))
print("Exiting.....")

