#!/usr/bin/env python
################################################################################
# Author: Aaron E.                                                             #
#To dos:                                                                       #
#      - avoid detection(done) oct9.2015                                       #
#      -deflect the network poisoning(solved)                                  #
#       attack(done)  oct9.2015                                                #
#      -attack the attackers                                                   #
#      -PinPoint the attaker(d0ne)                                             #
#      May 2015                                                                #
#     - avoid ping scan (it is is here just taking a backset the firewall rule #
#  
#BUG: time stamp error time stamp does not change. perhaps coding error(solved)
#                                                                              #
#                                                                              #
################################################################################

# COMMENT:I am planning to change its name from tuko to Sentinel
# I will just read about sentinel I just watched X-men movie
# tuko is misplaced because of it's behavior of making noise
# but I don't want to lose it Pinoy touch. How about kwago
# because it's being stealthy I cannot make up mind for now.
#
# October 09, 2015 --> time stamp Added
# In Unix or GNU/LINUX you can set firewall rules and 
# those tools are natively available in Linux system
#
# in this machine I did it manually but it could be 
# added here and activated when an attack is occured
#
# it ignores local arp which is the solution for arp poisoning, sniffing 
# and scanning
# echo "1"  > /proc/sys/net/ipv4/conf/wlan0/arp_ignore
# echo "8" > /proc/sys/net/ipv4/conf/wlan0/arp_announce
#  and to activate this feature simply uncomment the line 102 and 103 take out # hash or numbersign
#
#disallow pings just figure it out
#iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT
#iptables -A INPUT -p icmp --icmp-type echo-reply -j REJECT
#iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
#iptables -A OUTPUT -p icmp --icmp-type echo-reply -j REJECT
#iptables -A OUTPUT -p icmp --icmp-type echo-request -j REJECT
#ip6tables -A INPUT -p icmp --icmp-type echo-reply -j DROP

# if you want to disconnect in wifi network when a scanning occurs to avoid detection just simply
# uncomment the line 115 that says  os.system('rfkill block 1)
# it disables radio signal of wifi.

from scapy.all import ARP, sniff # import what you need
import os
import time
import sys
import itertools
import threading
d = dict() # don't need global
#done = 'false'
#here is the animation
#def animate():
    #while done == 'false':
        #sys.stdout.write('\rLurking |')
        #time.sleep(0.1)
        #sys.stdout.write('\rLurking/')
        #time.sleep(0.1)
        #sys.stdout.write('\rLurking -')
        #time.sleep(0.1)
        #sys.stdout.write('\rLurking \\')
        #time.sleep(0.1)
        #sys.stdout.write('\rDone!     ')
        #animate()
#long process here
#done = 'false'
#time_stamp = time.strftime("%Y-%m-%d %H:%M:%S")
#printtime = str(time_stamp)
print"\t###########   TUKO v2.6   ###############"
print"\t#########################################"   
print"\t# SENTINEL PROJECT a Network Sec. Tool  #"
print"\t#########################################"   
print"\t#  Intrusion Detection Sys by  telnet15 #"
print"\t#########################################"
print"Anti-MITM to enable retalation mode please"
print"read the documents for futher information"


done = False
#here is the animation
def animate():
    for c in itertools.cycle(['......|', '....../', '......-', '......\\']):
        if done:
            break
        sys.stdout.write('\rActive and Lurking' + c)
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\rReady!    ')

t = threading.Thread(target=animate)
t.start()

#long process here
time.sleep(3)
done = True
sys.stdout.write('\n')
    



while 1:		
    def replay(pkt):
        if ARP in pkt and pkt[ARP].op == 2: # make sure ARP is in the packet
            if pkt[ARP].psrc in d: # just use in d
                if d[pkt[ARP].psrc] != pkt[ARP].hwsrc:
                        os.system('play --no-show-progress --null --channels 1 synth 0.30 sine 1000')
			return time.strftime("%Y-%m-%d %H:%M:%S") + "-->ALERT!:YOU ARE UNDER ATTACK! with mac addr-> {}".format(pkt[ARP].psrc + '->' + pkt[ARP].hwsrc) #someone is hammering your connection. A direct assault to your machine
		else:
                    os.system('play --no-show-progress --null --channels 1 synth 0.03 sine 750')
		    #os.system('rfkill block 1')
		    #os.system('echo "1"  > /proc/sys/net/ipv4/conf/wlan0/arp_ignore')
		    #os.system('echo "8"  > /proc/sys/net/ipv4/conf/wlan0/arp_annouce')
		    #print "printtime=" + printtime
		    # print "str_time" + str(time_stamp)

                    return time.strftime("%Y-%m-%d %H:%M:%S") + "-->WARNING :Somebody ARP scanning the network.ALERT!-> {}".format(pkt[ARP].psrc + '->' + 
pkt[ARP].hwsrc)  #This is just to scanned host.not the attaker
                                                                                                                 # The attaker just scanning/attempting.
                                                                                                                 #This behavior is consider an attack.
            else:
                d[pkt[ARP].psrc] = pkt[ARP].hwsrc
                
                os.system('play --no-show-progress --null --channels 1 synth 0.07 sine 500')
		return time.strftime("%Y-%m-%d %H:%M:%S") + "-->NOTE: ANNOUNCING -> {}".format(pkt[ARP].psrc + '->' + pkt[ARP].hwsrc )

                
    sniff(prn=replay, filter="arp", timeout=10)
    
   
   
