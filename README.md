# WifiScannerPython

**(RUN AS ROOT)**

**USAGE:**   
python wifiscanner.py [interface] [noise_filter_flag]

-> interface : this should refer to the interface name which is ALREADY in monitor mode

-> noise_filter_flag : this should either be 0(false) or 1(true); 1 - would show all the noise tapped by the interface as UNKNOWN ; 0 - would not display that
                                                       
EXAMPLE: python wifijammer wlan0mon 1

# Putting Your Card In Monitor Mode:  

**IMPORTANT : FIRST RUN airmon-ng check kill**

*Assuming : monitor mode and promiscuous mode is supported by wifi card , iface name = wlan0*

<ins>**Step 1: using iwconfig**</ins>

sudo ifconfig wlan0 down

sudo iwconfig wlan0 mode monitor

sudo ifconfig wlan0 up

//toggle the 'monitor' to 'manage' to return to normal mode

<ins>**Step 2: using airmon-ng**</ins>

airmon-ng check kill

airmong-ng start wlan0

// this changes wlan0 name to wlan0 mon

// to return to normal mode, airmon-ng stop wlan0mon 


