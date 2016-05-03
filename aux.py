#!/usr/bin/python

from __future__ import print_function
from datetime import datetime
import time
import sys
import getopt
import os
import logging
import iptc
import subprocess
import curses
from ftplib import FTP
from pymodbus.client.sync import ModbusTcpClient as ModbusClient

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Verbosity Variables
verb=True
verboso=False

#NCURSES Variables
NCURSES=False
#NCURSES=True
outputscreen=None

rule = iptc.Rule()

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    RED = '\033[0;31m'
    DEFAULT = '\033[39m'
    ORANGE = '\033[33m'
    WHITE = '\033[97m'

##########################################
# Print banner
##########################################
def banner():
    print (Colors.RED )
    print ("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNmmNNNNNNNNNNNN")
    print ("NNNNNNox//mNNNNNNNNNNh.+/NNNNNNNNNNNNm/mNNNNNNNNNN")
    print ("NNNNNNNo`----------+++ooo++++-----------sNNNNNNNNN")
    print ("NNNNNNNo`-------------++oo++-o.o.o------sNNNNNNNNN")
    print ("NNNNNNNo.---mNNNNdo-`:++o:+i--/hNNNN----:dNNNNNNNN")
    print ("NNNNNNNo-.-:NNNNNNNm---o/+++:/NNNNNN----:NNNNNNNNN")
    print ("NNNNNNN..-:.mNNNNNNd+-:::/--/mNNNNNN--o`-NNNNNNNNN")
    print ("NNNNNNNos-s+oNNNNNNNN/-:::-/mNNNNNms:..-.NNNNNNNNN")
    print ("NNNNNNN..---yNNdNNNNN`./s`/NNNNNNNss-.-o-NNNNNNNNN")
    print ("NNNNNNNh-::-/NNNNNNNNNNNNNNN......ss`--so......NNN")
    print ("NNNNNNNh-::-/NNNNNNNNNNNNNNN...N...s`--s...N...NNN")
    print ("NNNNNNNh-::-/NNNNNNNNNNNNNNN...NN...s-s...NN...NNN")
    print ("NNNNNNNh-::-/NNNNNNNNNNNNNNN...NNNs..s..ooNN...NNN")
    print ("NNNNNNNh-::-/NNNNNNNNNNNNNNN...NNNss---sooNN...NNN")
    print ("NNNNNNNh-::-/NNNNNNNNNNNNNNN...NNNssssssNooN...NNN")
    print (Colors.DEFAULT)

##########################################
# Create Iptables rule:
# iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST --dport 502 -j DROP
##########################################
def create_iptables_rule(port):
	global rule	
	match = iptc.Match(rule, "tcp")
	match.dport=port
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

##########################################
# Remove Iptables rule:
#iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST --dport 502 -j DROP
##########################################
def remove_iptables_rule():
	global rule	
	chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT") # -A OUTPUT
	chain.delete_rule(rule)

##########################################
# Screeening functions
##########################################
def dot():
	write_screen("..")

def write_screen(text):
	if NCURSES:
		if (text.find('\n')>=0):
			y=outputscreen.getyx()[0]
			outputscreen.addstr(y+1,2,text.replace('\n',''))
		else:
			outputscreen.addstr(text)

		outputscreen.border(0)
		outputscreen.refresh()
	elif verb:	
		#print (Colors.GREEN)
		sys.stdout.write(Colors.GREEN+text+Colors.DEFAULT)
		sys.stdout.flush() 
		#print (Colors.DEFAULT)
		


################################################################################
#################### AUXILIARY & CONVERSION FUNCTIONS ##########################
################################################################################

##########################################
# SYNTAX INFORMATION
##########################################
def syntax_information():
      print ('usage: malmod.py [-h] [-v|-w] -m <PLC IP> [-u <File to Upload>|-d <File to Download>|-i|-c|-y|-z|-x|-R|-D|-B]')
      print ("Type modicon -h for further information")


##########################################
# Convert Binary to String (Binary to "01 40 3F FF")
##########################################
def BintoString(bl, endianness="BIG-ENDIAN"):
	cad=""
	for ch in bl:
		c=hex(ord(ch)).replace('0x','')	
		if len(c)==1:
			c='0'+c
		cad=cad+" "+c

	return cad
	
##########################################
# Convert Hex (without spaces) to String
##########################################
def HextoString(val, endianness="BIG-ENDIAN"):
    #print (val)#424d58205033342032303230
    cad=""
    for i in xrange(0, len(val),2):
	hexval=val[i:i+2]
	#print (hexval)
	b=HextoByte(hexval)
	cad=cad+chr(b)
	
    return (cad)

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
# Hex string to int
##########################################
def HextoInt(hexStr, endianness="BIG-ENDIAN"):
	s=hexStr.replace(' ','')
        if (endianness=="BIG-ENDIAN"):
                val= ( 256* int (s[:2], 16 ) )  +  int (s[2:4], 16 )
        else:
                val=  256*(int (s[2:4], 16 ) ) +  int (s[:2], 16 )

        return val

##########################################
# Hex string to byte
##########################################
def HextoByte(hexStr):
	s=hexStr.replace(' ','')
        return ( int (s[0:2], 16 ) )

##########################################
# Convert a string to Hex Text
##########################################
def toHex(s):
    lst = ""
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst=lst+hv
    
    return lst
#reduce(lambda x,y:x+y, lst)

##########################################
# Convert binary to Hex Text
##########################################
def BintoHex(s):
    lst = ""
    for ch in s:
	
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst=lst+hv

    return lst
    
##########################################
# Auxiliary function to set verbosity
##########################################
def set_verbose(b):
	global verboso
	verboso=b

def set_verb(b):
	global verb
	verb=b

def set_curses(b):
	global NCURSES 
	NCURSES=b

##########################################
# Auxiliary function to set verbosity
##########################################
def is_verbose():
	return verboso

def is_verb():
	return verb

def is_curses():
	return NCURSES

def set_outputscreen(s):
	global outputscreen;
	outputscreen=s
