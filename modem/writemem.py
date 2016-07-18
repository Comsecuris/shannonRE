#!/usr/bin/env python

import serial
import io
import sys

def usage():
	print "%s <device> <0xdeadbeef> <val>"
	sys.exit(0)

def main():
	if len(sys.argv) < 4:
		usage()

	ser = serial.Serial()
	ser.port = sys.argv[1]
	ser.baudrate = 11520
	ser.parity = serial.PARITY_NONE
	ser.bytesize = serial.EIGHTBITS
	ser.stopbits = serial.STOPBITS_ONE
	ser.timeout = 1.5
	ser.xonxoff = False
	ser.rtscts = False
	ser.dsrdtr = False

	try:
		ser.open()
	except Exception as e:
		print str(e)
		sys.exit(1)

	ea = sys.argv[2]
	if ea.startswith("0x"):
		ea = ea[2:]

	val = sys.argv[3]
	if val.startswith("0x"):
		val = val[2:]

	ser.write(("AT+HREGWRITE=%s=%s\r" %(ea, val)))

	rsp = ser.readline() # 0xX = 0xY
	print rsp
	ser.close()

if __name__=="__main__":
	main()
