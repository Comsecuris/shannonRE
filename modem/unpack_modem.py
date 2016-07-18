import os
import struct
import sys

class TOC:
	def __init__(self, fstream, fpos = None):
		try:
			if fpos != None:
				fstream.seek(fpos)
			self.buf = fstream.read(32)
		except Exception:
			print "Not enough bytes in stream"
			self.buf = []

	def unpack(self):
		self.name = str(self.buf[:12]).strip("\x00")
		self.start = struct.unpack("i", self.buf[12:16])[0] 
		self.size = struct.unpack("i", self.buf[20:24])[0]
		self.unk1 = struct.unpack("i", self.buf[24:28])[0]
		self.id = struct.unpack("i", self.buf[28:32])[0]

	def pprint(self):
		print "name: %s" % self.name
		print "start offset: 0x%08x" % self.start
		print "size: 0x%08x" % self.size
		print "unk: 0x%08x" % self.unk1
		print "id: %d" % self.id

class IMG:
	def __init__(self, fstream, hdr):
		fstream.seek(hdr.start)
		self.buf = fstream.read(hdr.size)

	def unpack(self):
		return

	def write(self, dst):
		with open(dst + ".bin", "wb") as f:
			f.write(self.buf)

class BOOT(IMG):
	def unpack(self):
		print 'foobarbaz'

def unpack_toc_struct(fmw, name):
	hdr = TOC(fmw)
	hdr.unpack()
	hdr.pprint()
	assert(hdr.name == name)
	return hdr

def unpack_img(fmw, hdr, Type):
	img = Type(fmw, hdr)
	img.unpack()
	return img

def help():
	print "%s <input>" %(sys.argv[0])
	sys.exit(0)

def main():
	if len(sys.argv) < 2:
		help()

	path = sys.argv[1]
	fmw = open(path, "rb")

	toc_hdr = unpack_toc_struct(fmw, "TOC")
	boot_hdr = unpack_toc_struct(fmw, "BOOT")
	main_hdr = unpack_toc_struct(fmw, "MAIN")
	nv_hdr = unpack_toc_struct(fmw, "NV")
	offset_hdr = unpack_toc_struct(fmw, "OFFSET")

	boot_img = unpack_img(fmw, boot_hdr, BOOT)
	boot_img.write("boot")
	
	main_img = unpack_img(fmw, main_hdr, IMG)
	main_img.write("main")	

	fmw.close()

if __name__ == "__main__":
	main()
