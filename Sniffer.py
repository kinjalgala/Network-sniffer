#Importing the necessary modules
import logging
from datetime import datetime
import subprocess
import sys

#A technique to suppress all low level messages while running or loading Scapy that are not errors
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# To handle import error 
try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()
    

#Always use "sudo scapy" in Linux!
print("\n! Make sure to run this program as ROOT !\n")

#To take the interface input on which to run the sniffer
network_interface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")
try:
    subprocess.call(["ifconfig", network_interface, "promisc"], stdout = None, stderr = None, shell = False)

except:
    print("\nFailed to configure interface as promiscuous.\n")

else:
    #Succefull in setting the PROMISC mode
    print("\nInterface %s was set to PROMISC mode.\n" % network_interface)


#Total number of packets to sniff (the "count" parameter)
packet_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")

#Considering the case when the user enters 0 (infinity)
if int(packet_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(packet_to_sniff))
    
elif int(packet_to_sniff) == 0:
    print("\nThe program will capture packets until the timeout expires.\n")


#the time interval to sniff 
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

#To Handle the value entered by the user
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))
    
    
#To apply any protocol filter to the sniffing process
protocol_sniffer = input("* Enter the protocol to filter by (arp|bootp|tcp|udp|icmp|0 is all): ")

#Considering the case when the user enters 0 (meaning all protocols)
if (protocol_sniffer == "arp") or (protocol_sniffer == "udp") or (protocol_sniffer == "icmp") or (protocol_sniffer == "bootp") or (protocol_sniffer == "tcp"):
    print("\nThe program will capture only %s packets.\n" % protocol_sniffer.upper())
    
elif (protocol_sniffer) == "0":
    print("\nThe program will capture all protocols.\n")

#Asking the user to enter the name and path of the log file to be created
log_file_name = input("* Please give a name to the log file: ")

#Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending
sniff_lof = open(log_file_name, "a")

#The function will extract parameters from the each packet and then log each packet to the log file
def packet_log(packet):
    
    #Getting the current timestamp
    now = datetime.now()
    
    #Writing the packet information to the log file, also considering the protocol or 0 for all protocols
    if protocol_sniffer == "0":
        #Writing the data to the log file
        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniff_lof)
        
    elif (protocol_sniffer == "arp") or (protocol_sniffer == "udp") or (protocol_sniffer == "icmp") or (protocol_sniffer == "bootp") or (protocol_sniffer == "tcp"):
        #Writing the data to the log file
        print("Time: " + str(now) + " Protocol: " + protocol_sniffer.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniff_lof)

        
#Printing an informational message to the screen
print("\n* Starting the capture...")
#Running the sniffing process (with or without a filter)
if protocol_sniffer == "0":
    sniff(iface = network_interface, count = int(packet_to_sniff), timeout = int(time_to_sniff), prn = packet_log)

elif (protocol_sniffer == "arp") or (protocol_sniffer == "udp") or (protocol_sniffer == "icmp")or (protocol_sniffer == "bootp")or (protocol_sniffer == "tcp"):
    sniff(iface = network_interface, filter = protocol_sniffer, count = int(packet_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
else:
    print("\nCould not identify the protocol.\n")
    sys.exit()

#Printing the closing message
print("\n* Please check the %s file to see the captured packets.\n" % log_file_name)

#Closing the log file
sniff_lof.close()
