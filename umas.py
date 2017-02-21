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
from aux import *
from ftplib import FTP
from pymodbus.client.sync import ModbusTcpClient as ModbusClient

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

k=0
t="";
IP_DST=""

SPORT_TCP=1128
DPORT=502
SYN=2
ACK=16
PSH_ACK=24
RST=4
FC="5A"  #90 Hex

blocksize=0
blocksize_str=""
trans=0

rule = iptc.Rule()

Command_File="commands.cmd"

FW27Code=""
HwDesc=""
CRC32=""

bytes_to_read=[64,264, 64, 1014, 998, 1008, 1014]

memory_block_sizes=[0,23296,16128,16128,16128,16128,16128,16128,16128,16128,0,0,0,0,0,0,0,2047,22272,65535]
trans_creciente=True

#########################################################################################
####################      UMAS PROTOCOL FUNCTIONS     ###################################
#########################################################################################

##########################################
# GENERIC SEND COMMANDO (Modbus XX YY ZZ)
##########################################
def send_command(comando):
	global t
	global trans

	if trans_creciente:
		trans+=1
	else:
		trans=1

	trans_str=InttoHex(trans)

#	write_screen("Enviando comando:"+comando+"...")
	longitud=hex((len(comando)+7)/3).replace('0x', '')
        if len(longitud) == 1:
            longitud = '00 0'+longitud
        if len(longitud) == 2:
            longitud = '00 '+longitud
        if len(longitud) == 3:
            longitud = '0'+longitud

	longitud=InttoHex(2+len(comando.replace(" ",""))/2)

	data=""+trans_str+" 00 00 "+longitud+" 00 5a "+comando

	d=data.replace(" ","").decode('hex')
	if t:
		p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
		port=RandNum(1024,65535)
		p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
	t=sr1(p,verbose=is_verbose(), timeout=3)	

	return t

##########################################
# Auxiliary function to extract UMAS_packet
##########################################
def get_UMAS_packet(packet):
	#print(str(packet))
        try:
                rawLoad = packet.getlayer(Raw).load
                rawLoadHex=rawLoad.encode("HEX").replace('0x','')
                UMAS_packet=rawLoadHex[16:] # Deberia comenzar con 00fe o similar
                return UMAS_packet
        except:
                return None

##########################################
# Check error
##########################################
def check_error(text):
	cadn=str(t)[46:56].encode("HEX").replace('0x','')
	if (cadn.find("fd") > 0):
		print (text + "("+cadn+")")
		reset_connection()
		sys.exit(1)	
	
##########################################
#Negotiation
##########################################
def tcp_negotiation(IP_RCV):
	##################
	#SYN
	global t
	global SPORT_TCP
	global IP_DST

	port=RandNum(1024,65535)
	IP_DST=IP_RCV
	
	time.sleep(0.1)
	r=IP(dst=IP_RCV)/TCP(sport=port, dport=DPORT, flags=SYN, options=[ ('MSS', 1460), ('NOP', 1), ('NOP', 1), ('SAckOK','')])
	t=sr1(r,verbose=is_verbose())
	time.sleep(0.1)

	##################
	#ACK
	p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, seq=t.ack, ack=t.seq+1, flags=16)
	send(p,verbose=is_verbose())
	SPORT_TCP=t.dport


def get_HwId():
	return HwId

def get_FwId():
	return FwId

def get_FwLoc():
	return FwLoc

def get_HwDesc():
	return HwDesc

def get_CRC32():
	return CRC32

def get_Ir():
	return Ir

def get_IP():
	return IP_DST

def set_IP(IP_str):
	global IP_DST
	IP_DST=IP_str

def get_Port():
	return port;

##########################################
#Modbus 00 02
##########################################
def device_information():
	global FwId
	global HwId	
	global HwDesc
	global FwLoc
	global Ir

	packet_received=send_command("00 02 00")

	while (len(str(packet_received))<62):
		packet_received=send_command("00 02 00")

	response=str(packet_received).encode("HEX").replace('0x','')
	pos=response.find("00fe")

	if (pos<0):
		write_screen("Error: Could not get device information")
	else:
		FwId=str(HextoByte(response[pos+22: pos+24]))+"."+str(response[pos+20: pos+22])
#		print("FwId:"+FwId)

		Ir=HextoInt(response[pos+28: pos+32],"LITTLE-ENDIAN")
#		print("Ir:"+str(Ir))

		HwId=str(HextoByte(response[pos+32: pos+34]))+"."+str(HextoByte(response[pos+34: pos+36]))+"."+str(HextoByte(response[pos+36: pos+38]))+"."+str(HextoByte(response[pos+38: pos+40]))
#		print("HwId:"+HwId)

		FwLoc=str(HextoByte(response[pos+40: pos+42]))+"."+str(HextoByte(response[pos+42: pos+44]))+"."+str(HextoByte(response[pos+44: pos+46]))+"."+str(HextoByte(response[pos+46: pos+48]))
#		print("FwLoc:"+FwLoc)

		device_desc_length=HextoByte(response[pos+48: pos+50])
#		print("length:"+str(device_desc_length))

		HwDesc=HextoString(response[pos+50:pos+50+(device_desc_length*2)])
	#	print("HWDesc:"+str(HwDesc))

	return packet
		
##########################################
# READ COILS (Modbus 00 24)
##########################################
def read_coils(start, num_coil):
	global t
	if (start>=0 and start<512 and num_coil>0 and num_coil<512 and start+num_coil<512):
		while (num_coil > 0):
			if num_coil>248:
				nr=248
			else:
				nr=num_coil

			s=hex(start).replace('0x', '')
        		start_hex_str=""
        		if (len(s)==1):
                		start_hex_str='0'+s+" 00"
        		if (len(s)==2):
               			start_hex_str=s+" 00"
        		if (len(s)==3):
                		start_hex_str=s[1:]+" 0"+s[0]
        		if (len(s)==4):
                		start_hex_str=s[-2:]+" "+s[:2]

			e=hex(nr).replace('0x', '')
        		end_hex_str=""
        		if (len(e)==1):
                		end_hex_str='0'+e+" 00"
        		if (len(e)==2):
               			end_hex_str=e+" 00"
        		if (len(e)==3):
                		end_hex_str=e[1:]+" 0"+e[0]
        		if (len(e)==4):
                		end_hex_str=s[-2:]+" "+s[:2]

			data="00 24 01 00 02 "+start_hex_str+" 00 00 "+end_hex_str

			packet_received=send_command(data)
			time.sleep(0.6)
			
			print (str(packet_received)[92:].encode("HEX"))
			
			num_coil-=248
			start+=248
	else:
		write_screen("Error: direccion de inicio o longitud de coils invalidos")

##########################################
# WRITE COILS (Modbus 00 25)
##########################################
def write_coils(start, num_coil, arr_list):
	global t
	if (start>=0 and start <1024 and num_coil>0 and num_coil<1024 and start+num_coil<1024 and len(arr_list)>=num_coil):
		arr_pos=0
		while (num_coil > 0):
			if num_coil>248:
				nr=248
			else:
				nr=num_coil

			for i in arr_list[arr_pos:arr_pos+nr]:

				if i:
					data_stream=data_stream+"1"
				else:
					data_stream=data_stream+"0"

				data_stream=data_stream+" "+word_str

			s=hex(start).replace('0x', '')
        		start_hex_str=""
        		if (len(s)==1):
                		start_hex_str='0'+s+" 00"
        		if (len(s)==2):
               			start_hex_str=s+" 00"
        		if (len(s)==3):
                		start_hex_str=s[1:]+" 0"+s[0]
        		if (len(s)==4):
                		start_hex_str=s[-2:]+" "+s[:2]

			e=hex(nr).replace('0x', '')
        		end_hex_str=""
        		if (len(e)==1):
                		end_hex_str='0'+e+" 00"
        		if (len(e)==2):
               			end_hex_str=e+" 00"
        		if (len(e)==3):
                		end_hex_str=e[1:]+" 0"+e[0]
        		if (len(e)==4):
                		end_hex_str=s[-2:]+" "+s[:2]

			data="00 25 01 00 02 "+start_hex_str+" 00 00 "+end_hex_str+" "+data_stream

			packet_received=send_command(data)
			time.sleep(0.6)
			
			print (str(packet_received)[92:].encode("HEX"))
			
			num_reg-=248
	
#######################################################################
# REQUEST INSTANCES OF UNLOCATED VARIABLES (Modbus 00 20, block 01 2e)
#######################################################################
def request_instances_unlocated_variables():

	code="00 20"
	subcode="01 2e"
	starting="00 00"
	length="F7 03" #1013
	data=code+" "+subcode+" "+starting+" 00 00 00 "+length
	packet_received=send_command(data)
	print (str(packet_received)[92:].encode("HEX"))

	starting="F7 03"
	length="0b 00" #11 hasta 1024
	data=code+" "+subcode+" "+starting+" 00 00 00 "+length
	send_command(data)
	print (str(packet_received)[92:].encode("HEX"))

#######################################################################
# REQUEST FUNCTION BLOCK INSTANCES (Modbus 00 20, block 01 32)
#######################################################################
def request_function_block_instances():

	code="00 20"
	subcode="01 32"
	starting="00 00"
	length="F7 03" #1013
	data=code+" "+subcode+" "+starting+" 00 00 00 "+length
	packet_received=send_command(data)
	print (str(packet_received)[92:].encode("HEX"))

################ATENCION!!! FALTAN 3!!! ####################


##########################################
# READ HOLDING REGISTERS (Modbus 00 24)
##########################################
def read_holding_registers(start, num_reg):
	global t
	if (start>=0 and start <1024 and num_reg>0 and num_reg<1024 and start+num_reg<1024):
		while (num_reg > 0):
			if num_reg>508:
				nr=508
			else:
				nr=num_reg

			s=hex(start).replace('0x', '')
        		start_hex_str=""
        		if (len(s)==1):
                		start_hex_str='0'+s+" 00"
        		if (len(s)==2):
               			start_hex_str=s+" 00"
        		if (len(s)==3):
                		start_hex_str=s[1:]+" 0"+s[0]
        		if (len(s)==4):
                		start_hex_str=s[-2:]+" "+s[:2]

			e=hex(nr).replace('0x', '')
        		end_hex_str=""
        		if (len(e)==1):
                		end_hex_str='0'+e+" 00"
        		if (len(e)==2):
               			end_hex_str=e+" 00"
        		if (len(e)==3):
                		end_hex_str=e[1:]+" 0"+e[0]
        		if (len(e)==4):
                		end_hex_str=s[-2:]+" "+s[:2]

			data="00 24 01 00 03 "+start_hex_str+" 00 00 "+end_hex_str

			packet_received=send_command(data)
			time.sleep(0.6)
			
			print (str(packet_received)[92:].encode("HEX"))
			
			num_reg-=508
			start+=508	
	else:
		write_screen("Error: invalid starting address o register length")

		        
##########################################
# WRITE HOLDING REGISTERS (Modbus 00 25)
##########################################
def write_holding_registers(start, num_reg, arr_list):
	global t
	if (start>=0 and start <1024 and num_reg>0 and num_reg<1024 and start+num_reg<1024 and len(arr_list)>=num_reg):
		arr_pos=0
		while (num_reg > 0):
			if num_reg>508:
				nr=508
			else:
				nr=num_reg

			for i in arr_list[arr_pos:arr_pos+nr]:
				s=hex(i).replace('0x', '')
       		 		word_str=""
       		 		if (len(s)==1):
       		         		word_str='0'+s+" 00"
       		 		if (len(s)==2):
       	        			word_str=s+" 00"
       		 		if (len(s)==3):
       		         		word_str=s[1:]+" 0"+s[0]
       		 		if (len(s)==4):
       		         		word_str=s[-2:]+" "+s[:2]

				data_stream=data_stream+" "+word_str


			s=hex(start).replace('0x', '')
        		start_hex_str=""
        		if (len(s)==1):
                		start_hex_str='0'+s+" 00"
        		if (len(s)==2):
               			start_hex_str=s+" 00"
        		if (len(s)==3):
                		start_hex_str=s[1:]+" 0"+s[0]
        		if (len(s)==4):
                		start_hex_str=s[-2:]+" "+s[:2]

			e=hex(nr).replace('0x', '')
        		end_hex_str=""
        		if (len(e)==1):
                		end_hex_str='0'+e+" 00"
        		if (len(e)==2):
               			end_hex_str=e+" 00"
        		if (len(e)==3):
                		end_hex_str=e[1:]+" 0"+e[0]
        		if (len(e)==4):
                		end_hex_str=s[-2:]+" "+s[:2]
	
			data="00 25 01 00 03 "+start_hex_str+" 00 00 "+end_hex_str+" "+data_stream

			packet_received=send_command(data)
			time.sleep(0.6)
			
			print (str(packet_received)[92:].encode("HEX"))
			
			num_reg-=508
			start+=508	

##########################################
# KEEPALIVE2 (Modbus 01 12)
##########################################
def send_keep_alive2():
	if (FwId=="2.70"):
		pck=send_command(FW27Code+"12")
	else:
		pck=send_command("01 12")
		
##########################################
# KEEP ALIVE (Modbus 01 04)
##########################################
def send_keep_alive():
	global PLC_Running
	global CRC32

	if (FwId=="2.70"):
		c=FW27Code+"04"
	else:
		c="00 04"

	UMAS_packet=None
	while not UMAS_packet:
		packet_received=send_command(c)
		cadn=str(packet_received).encode("HEX").replace('0x','')
		UMAS_packet=get_UMAS_packet(packet_received)

	CRC32=UMAS_packet[20:28]
	#print ("El CRC es: "+CRC32)
	
	if (cadn[-12:-10] == "02"):
		PLC_Running=True
	else:
		PLC_Running=False

	return packet_received

##########################################
# RESET CONNECTION
##########################################
def reset_connection():
	write_screen("\nResetting connection...")
	global t
	send_command("00 58 01 00 00 00 00 FF FF 00 00")
	time.sleep(0.3)
	#send_keep_alive();
	#time.sleep(0.3)
	#send_command("00 58 01 80 00 00 00 00 00 FB 03")
	#send_keep_alive();
	#time.sleep(0.3)
	if t:
		r=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, seq=t.ack, ack=t.seq+1, flags=RST)
	else:
		r=IP(dst=IP_DST)/TCP(sport=SPORT_TCP, dport=DPORT, flags=RST)
	t=send(r,verbose=is_verbose())
	remove_iptables_rule()
	write_screen("\nModifying iptables..\n")

##########################################
# REPEAT (Modbus 00 0A 00)
##########################################
def repeat(text):
	global t
	global trans

	if trans_creciente:
		trans+=1
	else:
		trans=1

	longitud=hex(len(text)+5).replace('0x', '')
        if len(longitud) == 1:
		longitud = '00 0'+longitud
        if len(longitud) == 2:
		longitud = '00 '+longitud
	if len(longitud) == 3:
		longitud='0'+longitud

	data=InttoHex(trans)+" 00 00 "+longitud+" 00 5a 00 0A 00 "
	data=data.split(" ")
	d = ''.join(data)+toHex(text)
	d=d.decode('hex')

	if t:
		p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
		port=RandNum(1024,65535)
		p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
	t=sr1(p,verbose=is_verbose())	


##########################################
# INIT - First packet sent to PLC (Modbus 00 01 00)
##########################################
def init():
	global blocksize
	global blocksize_str
	global blocksize_orig

	packet_received=send_command("00 01 00")

	response=str(packet_received).encode("HEX").replace('0x','')
	pos=response.find("00fe")

	blocksize=HextoInt(response[pos+4:pos+8],"LITTLE-ENDIAN")-8
	blocksize_str=InttoHex(blocksize,"LITTLE-ENDIAN")
	blocksize_orig=response[pos+4:pos+8]
	#write_screen("Assigning block size to: "+ blocksize)	
	

##########################################
# Memory Dump 
##########################################
# Section: string that represents an 16 bit hex number in little-endian mode. For instance "13 00" means section 0x13h
# Filename: string with the name of the File that will be written

def memory_dump(section_str, Filename=None):
	global t
	global trans

	write_screen ("\nDumping memory block "+section_str+"h ...")

	code="00 20"
	starting_str="00 00"
	length_str=blocksize_str
	starting=HextoInt(starting_str,"LITTLE-ENDIAN")
	length=HextoInt(length_str,"LITTLE-ENDIAN")

	Continue=True

	f=None
	if Filename:
		f=open(Filename, "wb")
	else:
		set_verb(True)

	while (Continue):
		if trans_creciente:
			trans+=1
		else:
			trans=1

		#data=""+InttoHex(trans)+" 00 00 00 0D 00 5a "+code+" 00 "+section+" "+starting_str+" 00 00 "+length_str
		#data=data.split(" ")
		#d = ''.join(data).decode('hex')
		#if t:
			#p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
		#else:
			#port=RandNum(1024,65535)
			#p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
		#t=sr1(p,verbose=is_verbose())	
		#time.sleep(0.9)


		packet_received=send_command(code+" 00 "+ section_str+" "+starting_str+" 00 00 "+length_str)
		time.sleep(0.9)
		cadn=str(packet_received)[46:54].encode("HEX").replace('0x','')

		if (cadn.find("fd")>0):
			check_error("\nAn error ocurred while dumping block starting in "+starting_str)
		else:
			if f:
				f.write(str(t)[54:])
			else:
				write_screen (str(t)[54:])

			time.sleep(0.3)

		starting+=length

		#Depending of the block read, we can read more or less bytes, or we will brick the PLC
		ss=HextoInt(section_str.replace(" ",""),"LITTLE-ENDIAN")
		dot()
		if (ss>=19):
		#13h to 2eh
			if (starting > 65535):
				Continue=False
		else:
			if (starting > memory_block_sizes[ss]):
				Continue=False
		
		starting_str=InttoHex(starting, "LITTLE-ENDIAN")

		#On the other hand if the reply is too short is because there's no extra info
		if (len(str(t))<80):
			Continue=False

	if f:
		f.close()

	write_screen("\nSuccessfully dumped "+str(starting -length)+" bytes.\n")

##########################################
# GET INTERNAL CARD INFO (Modbus 00 06 00)
##########################################
def get_internal_card_info():
	pck=send_command("00 06 00")

##########################################
#Modbus Read Sections 13&14
##########################################
def read_sections13_14():
	global t
	global trans

	code="00 20"
	section="13 00" # little endian
	length_str="64 00" #little-endian
	starting_str="00 00"

	if trans_creciente:
		trans+=1
	else:
		trans=1

	data=""+InttoHex(trans)+" 00 00 00 0D 00 5a "+code+" 00 "+section+" "+starting_str+" 00 00 "+length_str
	data=data.split(" ")
	d = ''.join(data).decode('hex')
	if t:
		p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
		port=RandNum(1024,65535)
		p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
	t=sr1(p,verbose=is_verbose())	
	time.sleep(0.9)

	starting_str=length_str
	length_str="9C 00"

	if trans_creciente:
		trans+=1
	else:
		trans=1

	data=""+InttoHex(trans)+" 00 00 00 0D 00 5a "+code+" 00 "+section+" "+starting_str+" 00 00 "+length_str
	data=data.split(" ")
	d = ''.join(data).decode('hex')
	if t:
		p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
		port=RandNum(1024,65535)
		p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
	t=sr1(p,verbose=is_verbose())	
	time.sleep(0.9)

	######  Block 14 ###
	section="14 00" # little endian
	length_str="64 00" #little-endian
	starting_str="00 00"

	if trans_creciente:
		trans+=1
	else:
		trans=1

	data=""+InttoHex(trans)+" 00 00 00 0D 00 5a "+code+" 00 "+section+" "+starting_str+" 00 00 "+length_str
	data=data.split(" ")
	d = ''.join(data).decode('hex')
	if t:
		p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
		port=RandNum(1024,65535)
		p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
	t=sr1(p,verbose=is_verbose())	
	time.sleep(0.9)


	######
	starting_str=length_str
	length_str=blocksize_str
	starting=HextoInt(starting_str,"LITTLE-ENDIAN")
	length=HextoInt(length_str,"LITTLE-ENDIAN")

	while (starting+length < 1604):
		if trans_creciente:
			trans+=1
		else:
			trans=1

		data=""+InttoHex(trans)+" 00 00 00 0D 00 5a "+code+" 00 "+section+" "+starting_str+" 00 00 "+length_str
		data=data.split(" ")
		d = ''.join(data).decode('hex')
		if t:
			p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
		else:
			port=RandNum(1024,65535)
			p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
		t=sr1(p,verbose=is_verbose())	
		time.sleep(0.9)

		starting+=length
		starting_str=InttoHex(starting, "LITTLE-ENDIAN")

	length_left=1604-starting

	if trans_creciente:
		trans+=1
	else:
		trans=1

	data=""+InttoHex(trans)+" 00 00 00 0D 00 5a "+code+" 00 "+section+" "+starting_str+" 00 00 "+InttoHex(length_left, "LITTLE-ENDIAN")
	data=data.split(" ")
	d = ''.join(data).decode('hex')
	if t:
		p=IP(dst=IP_DST)/TCP(sport=t.dport, dport=DPORT, flags=PSH_ACK, seq=t.ack, ack=t.seq+1)/Raw(load=d)
	else:
		port=RandNum(1024,65535)
		p=IP(dst=IP_DST)/TCP(sport=port, dport=DPORT, flags=PSH_ACK)/Raw(load=d)
	t=sr1(p,verbose=is_verbose())	
	time.sleep(0.9)

	
##########################################
# GET INTERNAL CARD INFO (Modbus 00 06 00)
##########################################
def get_internal_card_info():
	pck=send_command("00 06 00")
	return pck

##########################################
# INICIALIZATION
##########################################
def initialize(IP_DST):
	write_screen("\nModifying iptables..")
	create_iptables_rule("502")
	write_screen("\nInitializong connection..")
	tcp_negotiation(IP_DST);

	#0x02
	pckt=device_information();
	dot()
	time.sleep(0.6)
	dot()

	#0x01
	init();

	#0x0A
	repeat("T"*(blocksize+4));

	#0x03
	#0x0304
	#0x0304
	#0x04
	send_command("00 03 00")
	time.sleep(0.3)
	send_command("00 03 04")
	time.sleep(0.3)
	send_command("00 03 04")
	time.sleep(0.3)
	send_command("00 04")
	time.sleep(0.3)

	#0x01
	init()

	a=""
	dot()
	for i in range (1,blocksize+4):
		b=hex(i).replace('0x', '')
       		if len(b) == 1:
       			b = '0'+b
		a=a+b[-2:]+" "

	dot()
	
	#0x0A
	send_command("00 0A 00 "+a)
	time.sleep(0.3)
	
#	send_command("00 04")
#	time.sleep(0.3)
#	send_command("00 04")
#	time.sleep(0.3)
#	dot()

##########################################
# Download Strategy
##########################################
def download_strategy(Filename):
	global t
	global blocksize

	write_screen ("\nInitializing strategy download..")
	send_keep_alive2();
	time.sleep(0.5)
	send_keep_alive();
	time.sleep(0.3)

	read_sections13_14()
	dot()

	if (FwId=="2.70"):
		first_code=FW27Code
	else:
		first_code="01"

	write_screen ("\nDownloading strategy..")
	pck=send_command(first_code+" 33 00 01 "+blocksize_orig)
	time.sleep(0.6)
	f=open(Filename, "wb")
	keep_reading=True
	i=1

	while keep_reading:
		b=BytetoHex(i)
		dot()

		#Lanzamos la peticion:
		time.sleep(0.6)
		packet_received=send_command(first_code+" 34 00 01 "+b+" 00")

		if (len(str(packet_received))!=54):
			cadn=str(packet_received)[46:54].encode("HEX").replace('0x','')
			if (cadn.find("fd")>0):
				packet_received=send_command(first_code+" 34 00 01 "+b+" 00")
				time.sleep(0.3)
				cadn=str(packet_received)[46:54].encode("HEX").replace('0x','')
				if (cadn.find("fd")>0):
					check_error("\nAn error ocurred while downloading block "+str(i)+" on strategy download")
				else:	
					f.write(str(t)[54:])
					time.sleep(0.3)
			else:
				f.write(str(t)[54:])
				time.sleep(0.3)
			i+=1
		else:
			keep_reading=False	

	#Closing read file both in PLC and locally
	block_num_str=BytetoHex(i)
	pck=send_command(first_code+" 35 00 01 "+block_num_str+" 00")
	dot()
	f.write(str(t)[54:-6])
	f.close()

	#Extra info for verbose mode
	time.sleep(0.3)
	write_screen ("\nSuccessful download!!")
	cad="\n"+str(i)+" memory blocks were downloaded"
	write_screen(cad)

##########################################
# Upload Strategy
##########################################
def upload_strategy(Filename):
	global t

	upload_initialization()
	
	write_screen("\nUploading_strategy")

	if (FwId=="2.70"):
		first_code=FW27Code
	else:
		first_code="01"


	#START STRATEGY UPLOAD
	dot()
	pck=send_command(first_code+" 30 00 01")
	time.sleep(0.6)

	pck=send_keep_alive();
	time.sleep(0.3)

	f=open(Filename, "rb")

	k=0
	block_num=0
	bytes_left=True
        #blocksize=1012

	while bytes_left:

		#blocks 0 and 1 are the same (both with block_num 1)
		if (block_num==0):
			b=hex(block_num+1).replace('0x', '')
		else:
			b=hex(block_num).replace('0x', '')

       		if len(b) == 1:
       			b = '0'+b

		dot()
		if (block_num!=1):
			block=f.read(blocksize-1);	
	 		cad=""	
			for ch in block:
				c=hex(ord(ch)).replace('0x','')	
				if len(c)==1:
					c='0'+c
				cad=cad+" "+c

		longitud=len(block)
		d=hex(longitud).replace('0x', '')
		e=""
		if (len(d)==1):
			e='0'+d+" 00"
		if (len(d)==2):
			e=d+" 00"
		if (len(d)==3):
			e=d[1:]+" 0"+d[0]
		if (len(d)==4):
			e=d[-2:]+" "+d[:2]

		#if (block_num==12):
			#bytes_left=False	

		block_num+=1
		#Send request only if there bytes left to send, otherwise break the loop
		if (longitud>0):
			k=k+1
			#write_screen (cad)
			pck=send_command(first_code+" 31 00 01 "+b+" 00 "+e+cad)
			time.sleep(0.6)
			check_error("\nError: An error ocurred while uploading block "+str(k)+" on strategy upload")
		else:
			bytes_left=False

	#CLOSE CONNECTION
	time.sleep(0.6)
	dot()

	b=hex(k-1).replace('0x', '')
       	if len(b) == 1:
       		b = '0'+b

	pck=send_command(first_code+" 32 00 01 "+b+" 00")
	cadn=str(t)[46:100].encode("HEX").replace('0x','')
	if ((cadn.find(first_code+"fd") > 0)):
		print("\nError. Strategy upload failed ("+cadn+")")
	else:
		write_screen ("\nSuccessful upload!!")
		write_screen("\nApprox. "+str(k)+" Kb were uploaded")

	f.close()
	time.sleep(0.6)


##########################################
#	 Upload initialization
##########################################
def upload_initialization():
	write_screen ("\nInitializing strategy upload..")
	pck=send_keep_alive2();
	time.sleep(0.5)
	pck=send_keep_alive();
	time.sleep(0.5)
	pck=send_keep_alive2();
	time.sleep(0.5)
	pck=send_keep_alive();
	time.sleep(0.3)

	read_sections13_14()
	dot()
	read_sections13_14()
	dot()
	read_sections13_14()
	dot()

	pck=send_keep_alive();
	time.sleep(0.3)
	pck=send_keep_alive();
	time.sleep(0.3)
	pck=send_command("00 03 01")
	time.sleep(0.6)

	pckt=device_information();
	time.sleep(0.6)

	pck=get_internal_card_info()
	time.sleep(0.6)

	pck=send_keep_alive();
	time.sleep(0.3)

	dot()

	if (FwId=="2.70"):
		pck=send_command("00 58 02 03 00 00 00 00 00 00 00")
		time.sleep(0.6)
	else:
		#Antes funcionaba con FB, no se por que
		#send_command("00 58 02 01 00 00 00 00 00 FB 00")
		pck=send_command("00 58 02 01 00 00 00 00 00 00 00")
		time.sleep(0.6)

		cadn=str(pck)[:100].encode("HEX").replace('0x','')
		if ((cadn.find("00fd") > 0)):
			pck=send_command("00 58 01 00 00 00 00 FF FF 00 00")
			time.sleep(0.6)

##########################################
#   INIT_DEFAULT VALUES (Modbus 01 42 00 00)
##########################################
def init_default_values():
	send_command("01 42 00 00 ")
	time.sleep(0.3)

##########################################
#   SEND ID (Modbus 00 10)
##########################################
def send_id():
	global FW27Code
	if (FwId=="2.70"): 
		packet_received=send_command("00 10 06 70 00 00 08 55 4E 49 54 59 50 52 4F") # AKA UNITYPRO
		cadn=str(packet_received)[46:].encode("HEX").replace('0x','')
		if ((cadn.find("00fd")>0) | (len(cadn)<9)):
			packet_received=send_command("00 10 06 70 00 00 08 55 4E 49 54 59 50 52 4F") # AKA UNITYPRO
			cadn=str(packet_received)[46:].encode("HEX").replace('0x','')
			if ((cadn.find("fd")>0) | (len(cadn)<9)):
				print("\nError. Could not assign ID to PLC. PLC is already assigned to other entity. Try again later")
				reset_connection()
				sys.exit(11)
			else:
				FW27Code=cadn[8:10]
		else:
			FW27Code=cadn[8:10]
	else:
		#FW anterior
		packet_received=send_command("00 10 25 10 00 00 0F 4d 59 53 43 52 49 50 54 2d 36 31 33 36 33 34") # AKA MYSCRIPT-613634
		
	time.sleep(0.5)

##########################################
#   CREATE BACKUP
##########################################
def create_backup():
	#Creates a backup of strategy in Internal Card
	write_screen("\nCreating backup of strategy in card")	
	if (FwId=="2.70"):
		send_command(FW27Code+" 36 01 00 00") 
	else:
		send_command("01 36 01 00 00") 
	check_error("\nError: An error ocurred while creating backup of strategy")
	time.sleep(0.5)
	send_keep_alive()
	time.sleep(0.5)

##########################################
#   REMOVE BACKUP
##########################################
def remove_backup():
	#Removes backup from Internal Card
	write_screen("\nRemoving backup strategy from card")	
	if (FwId=="2.70"):
		send_command(FW27Code+" 36 04 00 00") 
	else:
		send_command("01 36 04 00 00") 
	check_error("\nError: An error ocurred while removing backup from card")
	time.sleep(0.5)
	send_keep_alive()
	time.sleep(0.5)

##########################################
#   RESTORE BACKUP
##########################################
def restore_backup():
	write_screen("\nRestoring backup from card")	
	#Restore backup from Internal Card
	if (FwId=="2.70"):
		send_command(FW27Code+" 36 02 00 00") 
	else:
		send_command("01 36 02 00 00") 
	check_error("\nError: An error ocurred while restoring backup from card")
	time.sleep(0.5)
	send_keep_alive()
	time.sleep(0.5)

##########################################
#   CHECK BACKUP
##########################################
def check_backup():
	#Check if backup an running strategy are the same
	write_screen("\nChecking if backup and strategy are equal")	
	if (FwId=="2.70"):
		send_command(FW27Code+" 36 03 00 00") 
	else:
		send_command("01 36 03 00 00") 
	time.sleep(0.5)
	send_keep_alive()
	time.sleep(0.5)


##########################################
#  GET SYSTEM BIT VALUE
##########################################
def get_systembit(sbit):
	
	if (FwId=="2.70"):
		code=FW27Code+" 22" 
	else:
		code="00 22"

	#unknown="C4 48 C4 37" #THIS VALUE DEPENDS ON THE STRATEGY. ITS A value that doubles the general stratgey CRC
	#unknown="8A E2 8D 00"
	#unknown="04 E9 0D 02"

	CRC_Int1=HextoInt(CRC32[0:4],"LITTLE-ENDIAN")
	CRC_Int2=HextoInt(CRC32[4:8],"LITTLE_ENDIAN")
	Doble=2*((65536*CRC_Int2)+CRC_Int1)
	CRC_Int2=Doble//65536
	CRC_Int1=Doble%65536
	New_CRC=InttoHex(CRC_Int1,"LITTLE-ENDIAN")+" "+InttoHex(CRC_Int2,"LITTLE-ENDIAN")

	#print("El nuevo CRC es: "+New_CRC)	

	systembitcode="01 2A"

	time.sleep(0.2)
	packet_received=send_command(code+New_CRC+"01"+systembitcode+"00 01 00 00 "+BytetoHex(sbit+6))
	if (len(packet_received)<=48):
		##send_command(code+New_CRC+"01"+systembitcode+"00 01 00 00 "+BytetoHex(sbit+4))
		##print("Length: "+str(len(packet_received))+".Trying again...")
		packet_received=send_command(code+New_CRC+"01"+systembitcode+"00 01 00 00 "+BytetoHex(sbit+6))
		
	UMAS_packet=get_UMAS_packet(packet_received)
	check_error("\nError:Could not retrieve system bit "+str(sbit)+" information")

	response=HextoByte(UMAS_packet[4:6])
	if (response%2==0):
		write_screen ("\nSystem bit %S"+str(sbit)+" is set to False")	
	else:
		write_screen ("\nSystem bit %S"+str(sbit)+" is set to True")	
	time.sleep(0.2)
	return response

##########################################
#  MONITOR SYSTEM BIT 
##########################################
def monitor_systembit(action, sbit, value=0):
    if (FwId=="2.70"):
		code1=FW27Code+" 50 15 00" 
    else:
		code1="01 50 15 00"

    if (action=="read"):
	code = code1 + " 03 01 01 00 00 0D 00 03 01 00 00 0C 00 15 01 00 2A 00"
	sb=BytetoHex(sbit+4)+" 00 00 00 0C 00 01 05 01 04 00 00 00 01"

	#Please monitor this system bit:	
	response=send_command(code+sb)

	time.sleep(0.3)

	#What are the values of the monitored bits?	
	packet=code1 + " 02 09 01 0C 00 01 00 07"
	response=send_command(packet)

	while (len(response)<=48):
		response=send_command(packet)
		
	time.sleep(0.3)
	
	UMAS_packet=get_UMAS_packet(response)
	
	#print (UMAS_packet)
	bit=HextoByte(UMAS_packet[10:12])

	#print (str(bit))

	if ((bit%2)==0):
		write_screen ("\nSystem bit %S"+str(sbit)+" is set to False")	
	else:
		write_screen ("\nSystem bit %S"+str(sbit)+" is set to True")	

	return (bit%2)
    elif (action=="write"):
	code = code1 + " 03 01 02 0D 00 0D 00 03 02 00 00 0D 00 14 01 00 2A 00"
	sb=BytetoHex(sbit+4)+" 00 00 00 0C 00 01 "
	if (value==0):
		sb=sb+ " 00 "
	else:
		sb=sb+ " 01 "
		
	tail="05 01 04 00 00 00 01"
	
	response=send_Command(code+sb+tail)
	time.sleep(0.3)


##########################################
#  MONITOR SYSTEM WORD
##########################################
def monitor_systembit(action, sword, value=0):
    if (FwId=="2.70"):
		code1=FW27Code+" 50 15 00" 
    else:
		code1="01 50 15 00"

    if (action=="read"):
	code = code1 + " 03 01 "
	variable="01 00 00 0D "
	action="00 03 03 00 00 0C 00 15 "
	systemword="02 00 2B 00 "
	sw=InttoHex((2*sword)+80)+" 00 00 "
	tail="0C 00 01 05 01 04 00 00 00 03"

	#Please monitor this system bit:	
	response=send_command(code+variable+action+systemword+sw+tail)

	time.sleep(0.3)

	#What are the values of the monitored bits?	
	packet=code1 + " 02 09 01 0C 00 02 00 07"
	response=send_command(packet)

	while (len(response)<=48):
		response=send_command(packet)
		
	time.sleep(0.3)
	
	UMAS_packet=get_UMAS_packet(response)
	
	#print (UMAS_packet)
	word=HextoByte(UMAS_packet[10:14])

	#print (str(bit))

	return (HextoInt(word,"LITTLE-ENDIAN"))

    elif (action=="write"):
	code = code1 + " 04 01 "
	variable="02 0e 00 0e "
	action=" 00 03 02 00 00 0e 00 14 "
	systemword="02 00 2B 00 "
	sw=InttoHex((2*sword)+80)+" 00 00 "
	unknown="0C 00 01 "
	value_hex=InttoHex(value,"LITTLE-ENDIAN")
	tail=" 05 01 04 00 00 00 02 "
	tail2="05 01 04 00 00 00 01"
		
	response=send_Command(code+variable+actionl+systemword+sw+unknown+value +tail+tail2)
	time.sleep(0.3)


##########################################
#  SET SYSTEM BIT VALUE
##########################################
def set_systembit(sbit,val):
	write_screen ("\nSetting system bit "+str(sbit)+" to "+str(val))
		
	if (FwId=="2.70"):
		code=FW27Code+" 23" 
	else:
		code="00 23"

	#unknown="C4 48 C4 37"

	CRC_Int1=HextoInt(CRC32[0:4],"LITTLE-ENDIAN")
	CRC_Int2=HextoInt(CRC32[4:8],"LITTLE_ENDIAN")
	Doble=2*((65536*CRC_Int2)+CRC_Int1)
	CRC_Int2=Doble//65536
	CRC_Int1=Doble%65536
	New_CRC=InttoHex(CRC_Int1,"LITTLE-ENDIAN")+" "+InttoHex(CRC_Int2,"LITTLE-ENDIAN")
	
	systembitcode="01 2A"
	if (val):
		hexval="01"
	else:
		hexval="00"

	send_command(code+New_CRC+"01"+systembitcode+"00 "+BytetoHex(sbit+4)+"00 00 00"+hexval)
	check_error("\nError:Could not set system bit %S"+str(sbit)+" information")

	write_screen("\nSystem bit "+str(sbit)+" set OK")
	time.sleep(0.2)

##########################################
#  GET SYSTEM WORD VALUE
##########################################
def get_systemword(sword):
	if (FwId=="2.70"):
		code=FW27Code+" 22" 
	else:
		code="00 22"

	CRC_Int1=HextoInt(CRC32[0:4],"LITTLE-ENDIAN")
	CRC_Int2=HextoInt(CRC32[4:8],"LITTLE_ENDIAN")
	Doble=2*((65536*CRC_Int2)+CRC_Int1)
	CRC_Int2=Doble//65536
	CRC_Int1=Doble%65536
	New_CRC=InttoHex(CRC_Int1,"LITTLE-ENDIAN")+" "+InttoHex(CRC_Int2,"LITTLE-ENDIAN")
	
	#unknown="C4 48 C4 37"
	systemwordcode="02 2B"
	if (sword<88):
		sword_hex="00 00"+BytetoHex((2*sword)+80)
	else:
		sword_hex="01 00"+BytetoHex((2*sword)+80-256)
	
	how_many_words_to_read=" 00 01 "	
	
	packet_received=send_command(code+New_CRC+"01"+systemwordcode+how_many_words_to_read+sword_hex)
	time.sleep(0.2)
	if (len(packet_received)<=48):
		packet_received=send_command(code+New_CRC+"01"+systemwordcode+how_many_words_to_read+sword_hex)
		time.sleep(0.2)

	UMAS_packet=get_UMAS_packet(packet_received)
	check_error("\nError:Could not retrieve system word %SW"+str(sword)+" information")
	response=HextoInt(UMAS_packet[4:8],"LITTLE-ENDIAN")
	write_screen ("\nSystem word %SW"+str(sword)+" is set to "+str(response))	
	time.sleep(0.2)
	return response

##########################################
#  SET SYSTEM WORD VALUE
##########################################
def set_systemword(sword,val):
	time.sleep(0.2)
	write_screen ("\nSetting system word "+str(sword)+" to "+str(val))
	if (FwId=="2.70"):
		code=FW27Code+" 23" 
	else:
		code="00 23"

	CRC_Int1=HextoInt(CRC32[0:4],"LITTLE-ENDIAN")
	CRC_Int2=HextoInt(CRC32[4:8],"LITTLE_ENDIAN")
	Doble=2*((65536*CRC_Int2)+CRC_Int1)
	CRC_Int2=Doble//65536
	CRC_Int1=Doble%65536
	New_CRC=InttoHex(CRC_Int1,"LITTLE-ENDIAN")+" "+InttoHex(CRC_Int2,"LITTLE-ENDIAN")
	
	#unknown="C4 48 C4 37"
	systemwordcode="02 2B"
	sword_hex=InttoHex((2*sword)+80,"LITTLE-ENDIAN")
	val_hex=InttoHex(val,"LITTLE-ENDIAN")

	#00 23-CRC-01 02 2B 00-WORD-00 00 00-VAL LITTLE ENDIAN
	how_many_values_to_set="01"
	cad=(code+New_CRC+how_many_values_to_set+systemwordcode+"00"+sword_hex+" 00 00"+val_hex)

	packet_received=send_command(cad)
	time.sleep(0.2)
	if (len(packet_received)<=48):
		packet_received=send_command(cad)
		time.sleep(0.2)

	check_error("\nError:Could not set system word %SW"+str(sword)+" information")
	write_screen("\nSystem word "+str(sword)+" set OK with val "+val_hex)
	time.sleep(0.2)

##########################################
# Start_PLC
##########################################
def start_plc(ignore_error=True):
	write_screen("\nStarting PLC..")

	dot()
	send_keep_alive();
	#time.sleep(0.5)
	#send_command("00 58 07 01 80 00 00 00 00 FB 00")
	time.sleep(0.5)
	dot()
	send_command("00 03 00")
	time.sleep(0.5)
	send_keep_alive();
	time.sleep(0.5)
	dot()
	if (FwId=="2.70"):
		packet_received=send_command(FW27Code+"40 FF 00")
	else:
		packet_received=send_command("00 40 FF 00")
	time.sleep(0.5)
	cadn=str(packet_received)[46:60].encode("HEX").replace('0x','')
	if (cadn.find("fd")>0):
		print ("\nERROR: An error ocurred while starting PLC")
		
	send_keep_alive();
	time.sleep(0.5)

##########################################
# Stop_PLC
##########################################
def stop_plc():
	write_screen("\nStopping PLC..")

	send_command("00 58 01 00 00 00 00 FF FF 00 70")
	time.sleep(0.3)
	send_command("00 58 07 01 80 00 00 00 00 FB 00")
	time.sleep(0.3)
	dot()
	send_keep_alive();
	time.sleep(0.3)
	send_command("00 58 07 01 80 00 00 00 00 FB 00")
	time.sleep(0.3)
	if is_running():
		if (FwId=="2.70"):
			send_command(FW27Code+" 41 FF 00")
		else:
			send_command("01 41 FF 00")
		time.sleep(0.3)
		check_error ("\nERROR: An error ocurred while stopping PLC")
		write_screen("\nPLC stopped successfully")
	else:
		write_screen("\nAlready stopped")

	dot()
	send_keep_alive();
	time.sleep(0.3)

##########################################
# Is PLC Running a strategy
##########################################
def is_running():
	packet_received=send_keep_alive()
	time.sleep(0.4)
 	cadn=str(packet_received).encode("HEX").replace('0x','')
	if (cadn[-12:-10] == "02"):
		return True
	else:
		return False

def get_blocksize_str():
	return blocksize_str
