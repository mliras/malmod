#!/usr/bin/env python
#---------------------------------------------------------------------------# 
# import the various server implementations
#---------------------------------------------------------------------------# 
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
#from pymodbus.client.sync import ModbusUdpClient as ModbusClient
#from pymodbus.client.sync import ModbusSerialClient as ModbusClient

from pymodbus.diag_message import *
from pymodbus.file_message import *
from pymodbus.other_message import *
from pymodbus.mei_message import *

from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.diag_message import *
import time

#######################################
#LEER REGISTROS DE ENTRADA (FUNC 4)
#######################################
#print "############################################"
#print "#LEER REGISTROS DE ENTRADA (FUNC 4)
#print "############################################"
#address = 0x01
#count   = 1
#result  = client.read_input_registers(address, count)
#print result.registers

#decoder = BinaryPayloadDecoder.fromRegisters(result.registers, endian=Endian.Little)
#decoded = {
    #'string': decoder.decode_string(8),
    #'float': decoder.decode_32bit_float(),
    #'16uint': decoder.decode_16bit_uint(),
    #'8int': decoder.decode_8bit_int(),
    #'bits': decoder.decode_bits(),
#}
#print "-" * 60
#print "Decoded Data"
#print "-" * 60
#for name, value in decoded.iteritems():
#    print ("%s\t" % name), value

##############################################
#LEER IDENTIFICACION DEL DISPOSITIVO (FUNC 43)
##############################################
def leer_id():
	rq = ReadDeviceInformationRequest()
	rr = client.execute(rq)
	for x in range(0,len(rr.information)):
		print (rr.information[x]),
	print 2*""
	print 2*""


#========================================================================
#                              COILS
#========================================================================
############################
# LEER COILS (FUNC 01)
############################
def leer_varios_coils(initial_coil, num_coils, slave):
	rr = client.read_coils(initial_coil, num_coils, unit=slave)
	if debug:
		print "==> Leyendo", num_coils, " coils comenzando por el ",initial_coil, " del esclavo", slave

		for x in range(1,num_coils+1):
			if rr.bits[x-1]:
				print "1",
			else:
				print "0",
		print ""
		print ""
	#time.sleep(1)

############################
# ESCRIBIR UN COIL (FUNC 05)
############################
def escribir_coil(num_coil, value, slave):
	if value<>0:
		value=1
	rq = client.write_coil(num_coil, value,unit=slave)
	if debug:
		print "==> Escribiendo el valor ", value, " en el coil ", num_coil , " del esclavo ", slave
		print 2*""
		print 2*""

############################
# ESCRIBIR VARIOS COILS (FUNC 15)
############################
def escribir_varios_coils(initial_coil, values, slave):
	#rq = client.write_coils(1, [False]*8, unit=0x01)
	rq = client.write_coils(initial_coil, values, unit=slave)
	if debug:
		print ("==> Escribiendo los siguientes valores desde el coil ", initial_coil, " del esclavo ", slave)


#========================================================================
#                             INPUTS 
#========================================================================
############################
# LEER INPUTS (FUNC 02)
############################
def leer_inputs(initial_input, num_inputs, slave):
	rr = client.read_discrete_inputs(initial_input,num_inputs, unit=slave)
	if debug:
		print "==> Leyendo los inputs ", initial_input, " al ", initial_input+num_inputs,""
	
		for x in range(1,num_inputs+1):
			if rr.bits[x-1]:
				print "1",
			else:
				print "0",
		print 3*""
		print 2*""

#========================================================================
#                             REGISTROS 
#========================================================================
############################
# ESCRIBIR UN REGISTRO (FUNC 06)
############################
def escribir_registro(register, value, slave):
	rq = client.write_register(register, value,unit=slave)
	if debug:
		print "==> Escribiendo el registro ", register, "con el valor ", value, " en el esclavo ", slave , ""

############################
# READ HOLDING REGISTERS (FUNC 03)
############################
def leer_registros_rw(initial_register, num_registers, slave):
	rr = client.read_holding_registers(initial_register,num_registers, unit=slave)
	if debug:
		print "==> Leyendo ", num_registers, " registros de E/S desde el registro ", initial_register, " en el esclavo ", slave , ""
		if len(rr.registers)>0:
			for x in range(1,num_registers):
				print rr.registers[x-1],
			print 2*""
			print 2*""

############################
# ESCRIBIR VARIOS REGISTROS (FUNC 16)
############################
def escribir_registros(initial_register, values, slave):
#rq = client.write_registers(1, [10]*8, unit=0x01)
	rq = client.write_registers(initial_register, values,unit=slave)
	if debug:
		print "==> Escribiendo desde el registro", initial_register, " del esclavo ", slave, "con los valores:"
		print values
		print 2*""

############################
# LEER REGISTROS DE ENTRADA (FUNC 04)
############################
def leer_registros_lectura(initial_register, num_registers, slave):
	rr = client.read_input_registers(initial_register,num_registers, unit=slave)
	if debug:
		print "==> Leyendo ", num_registers, " de LECTURA desde el registro ", initial_register, " en el esclavo ", slave , ""
		if rr:
			for x in range(1,num_registers):
				print rr.registers[x-1],
			print 2*""

############################
# LEER y escribir registros (FUNC 23)
############################

def lee_escribe_registros(initial_read_register, num_read_register, initial_write_register, values, slave):
	arguments = {
    	'read_address':    initial_read_register,
    	'read_count':      num_read_register,
    	'write_address':   initial_write_register,
    	#'write_registers': [20]*8,
    	'write_registers': values,
    	'unit': slave,
	}

	rq = client.readwrite_registers(**arguments)

	#assert(rq.function_code < 0x80)     # test that we are not an error
	#assert(rq.registers == [20]*8)      # test the expected value
	#assert(rr.registers == [20]*8)      # test the expected value

#---------------------------------------------------------------------------# 
# diagnostic requests
#---------------------------------------------------------------------------# 
def get_diagnostics():
	rq = ReturnQueryDataRequest()
	rr = client.execute(rq)
	#assert(rr.message[0] == 0x0000)               # test the resulting message

	rq = RestartCommunicationsOptionRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	#assert(rr.message == 0x0000)                  # test the resulting message

	rq = ReturnDiagnosticRegisterRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference

	rq = ChangeAsciiInputDelimiterRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference

	rq = ForceListenOnlyModeRequest()
	client.execute(rq)                             # does not send a response

	rq = ClearCountersRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference

	rq = ReturnBusCommunicationErrorCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference

	rq = ReturnBusExceptionErrorCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ReturnSlaveMessageCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ReturnSlaveNoResponseCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ReturnSlaveNAKCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ReturnSlaveBusyCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ReturnSlaveBusCharacterOverrunCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ReturnIopOverrunCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = ClearOverrunCountRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference
	
	rq = GetClearModbusPlusRequest()
	rr = client.execute(rq)
	#assert(rr == None)                            # not supported by reference

	print "KKK"

def Other_requests():
	rq = ReportSlaveIdRequest()
	rr = client.execute(rq)
	#assert(rr == None)                              # not supported by reference
	#assert(rr.function_code < 0x80)                # test that we are not an error
	#assert(rr.identifier  == 0x00)                 # test the slave identifier
	#assert(rr.status  == 0x00)                     # test that the status is ok

	rq = ReadExceptionStatusRequest()
	rr = client.execute(rq)
	#assert(rr == None)                             # not supported by reference
	#assert(rr.function_code < 0x80)                 # test that we are not an error
	#assert(rr.status == 0x55)                       # test the status code
	
	rq = GetCommEventCounterRequest()
	rr = client.execute(rq)
	#assert(rr == None)                              # not supported by reference
	#assert(rr.function_code < 0x80)                # test that we are not an error
	#assert(rr.status == True)                      # test the status code
	#assert(rr.count == 0x00)                       # test the status code
	
	rq = GetCommEventLogRequest()
	rr = client.execute(rq)
	#assert(rr == None)                             # not supported by reference
	#assert(rr.function_code < 0x80)                # test that we are not an error
	#assert(rr.status == True)                      # test the status code
	#assert(rr.event_count == 0x00)                 # test the number of events
	#assert(rr.message_count == 0x00)               # test the number of messages
	#assert(len(rr.events) == 0x00)                 # test the number of events



#---------------------------------------------------------------------------# 
# configure the client logging
#---------------------------------------------------------------------------# 
import logging
logging.basicConfig()
log = logging.getLogger()
#log.setLevel(logging.DEBUG)

#---------------------------------------------------------------------------# 
# choose the client 
#---------------------------------------------------------------------------# 
#
#    client = ModbusClient('localhost', retries=3, retry_on_empty=True)
#---------------------------------------------------------------------------# 
client = ModbusClient('10.3.1.205', port=502)
#client = ModbusClient(method='ascii', port='/dev/pts/2', timeout=1)
#client = ModbusClient(method='rtu', port='/dev/pts/2', timeout=1)
client.connect()
k=0
debug=True

#l={98+k,76+k,54+k,32+k,10+k,987+k,654+k,321+k}
l={6757,2340,340,8730,0,0,0,0}

print "======================"
print "Con el Tofino activado"
print "======================"

leer_id()

#while (k<9):

leer_registros_rw(1,len(l),0x01)
#	leer_varios_coils(0,16,0x00)

#escribir_registros(1, l, 0x01)
#	escribir_coil(k, 0, 0x01)
	
#	leer_registros_rw(1,len(l),0x01)
#	leer_varios_coils(0,16,0x00)
#	k=k+1
#	time.sleep(1)
#	print "=============================="


client.close()
