#!/usr/btin/python

from __future__ import print_function
from datetime import datetime
import time
import sys
import getopt
import os
import logging
import iptc
import subprocess

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

##########################################
# Convert binary byte to Hex Text
##########################################
def BytetoHex(val):
    lst = ""
    hv = hex(val).replace('0x', '')
    if len(hv) == 1:
            hv = '0'+hv

    lst=lst+hv

    return lst

##########################################
# Convert int to Hex Text
##########################################
def InttoHex(val, endianness="BIG-ENDIAN"):

    FirstByte=BytetoHex(val//256)
    SecondByte=BytetoHex(val%256)

    if (endianness=="LITTLE-ENDIAN"):
        return (""+SecondByte+" "+FirstByte)
    else:
        return (""+FirstByte+" "+SecondByte)



##########################################
# VARIABLE INITIALIZATION 
##########################################
DPORT=502
IP_DST="10.1.0.101"
SYN=2
ACK=16
PSH_ACK=24
RST=4
t=""
rule=iptc.Rule()

########################################
#IPTABLES INITIALIZATION
########################################
def init_iptables():
	global rule;

	match = iptc.Match(rule, "tcp")
	match.dport="502"
	match.tcp_flags = ['RST']
	chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT") # -A OUTPUT
	rule.protocol = "tcp" # -p tcp
	rule.target = iptc.Target(rule, "DROP") # -j DROP
	rule.add_match(match)
	try:
        	chain.delete_rule(rule)
	except:
        	a=0
	chain.insert_rule(rule)


########################################
# TCP NEGOTIATION
########################################
def tcp_negotiation():
	global t;
	global port;

	port=RandNum(1024,65535)

####
#SYN
	time.sleep(0.1)
	r=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=SYN, options=[ ('MSS', 1460), ('NOP', 1), ('NOP', 1), ('SAckOK','')])
	t=sr1(r)
	time.sleep(0.5)

####
#ACK
	p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, seq=t.ack, ack=t.seq+1, flags=ACK)
	send(p,True)
	SPORT_TCP=t.dport

###########################################
# SEND_COMMAND
###########################################
def send_command(FC, comando):
	global t;

	trans_str="0000"
	protocol_id="0000"
	unit_id="00"

	longitud=hex((len(comando)+3)/2).replace('0x', '')
	if len(longitud) == 1:
    		longitud = '00 0'+longitud
	if len(longitud) == 2:
    		longitud = '00 '+longitud
	if len(longitud) == 3:
    		longitud = '0'+longitud

	longitud=InttoHex(2+len(comando.replace(" ",""))/2)

	data=""+trans_str+protocol_id+longitud+unit_id+FC+comando
	d=data.replace(" ","").decode('hex')

	if t:
        	p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
        	port=RandNum(1024,65535)
        	p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)

	t=sr1(p,verbose=True, timeout=3)

###########################################
# CLOSE_COMM
###########################################
def close_comm():
	global t

        if t:
                r=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, seq=t.ack, ack=t.seq+1, flags=RST)
        else:
                r=IP(dst=IP_DST)/TCP(sport=SPORT_TCP, dport=DPORT, flags=RST)
	send(r)

        remove_iptables_rule()

###########################################
# REMOVE IPTABLES RULE
###########################################
def remove_iptables_rule():
        global rule
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT") # -A OUTPUT
        chain.delete_rule(rule)

###########################################
# MAIN
###########################################
init_iptables()
tcp_negotiation()
send_command("2b", "0E0100");
close_comm()
