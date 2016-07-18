#!/usr/bin/env python
# NOTE: sometimes the serial was hanging during experimentation. unclear why.
# NOTE: restarting the script usually fixes this

import struct
import serial
import io
import sys

def usage():
	print "%s <device> <0xdeadbeef> <size> <outputfile>"
	sys.exit(0)

def main():
	if len(sys.argv) < 5:
		usage()

	ser = serial.Serial()
	ser.port = sys.argv[1]
	ser.baudrate = 11520
	ser.parity = serial.PARITY_NONE
	ser.bytesize = serial.EIGHTBITS
	ser.stopbits = serial.STOPBITS_ONE
	ser.timeout = 0.5
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

	size = int(sys.argv[3])
	ea = int(ea, 16)

	end = ea + size

	outfile = sys.argv[4]
	f = open(outfile, 'wb')

	while ea < end:
		ser.write(("AT+HREGREAD=%x\r" %(ea)))

		rsp = ser.readline() # first line will be empty
		rsp = ser.readline() # 0xX = 0xY

		try:
			val = rsp.split("x")[2].strip()
		except:
			continue

		print "%x> 0x%s" % (ea, val)
		f.write(struct.pack("<L", int(val, 16)))
		ea += 4

	ser.close()
	f.close()
	print "content written to %s" %(sys.argv[4])

if __name__=="__main__":
	main()
