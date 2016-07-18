# © Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils


'''
Overlaping regions are applied here:http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/CIHFFIDG.html
tl;dr: higher region number (e.g. region 6) takes priority over lower (e.g. region 5).
This means that if region 6 is a subset of region 5, than accesses to region 6 are covered by region 6 attributes, the
rest of region 5 (not part of region 6) are covered by region 5 attributes.
'''

class Region:

	'''
	MPU_region_config <2, 0x4800000, 0x1A, 8, 0x300, 0x1000, 0, 0, 0, 1>
	MPU_region_config <3, 0x30000000, 0x36, 0, 0x300, 0x1000, 0, 0, 0, 1>
	MPU_region_config <4, 0x40000000, 0x34, 0x28, 0x300, 0, 0, 0, 1, 1>

	num, addr, size, TEX = {0, 8, 0x20, 0x28}, AP , XN = {0x1000,0}, S = 0, C = 0, B = {0,1}, en


	. ..11 .... 11.. = 0x30c

	=> XN == 0 (bit 12)
	=> AP = rw/ (bits 8-10)
	=> B = 0
	=> C = 0
	=> S = 1
	=> TEX = 001 (bits 3-5)

	to make TEX 100 instead:

	. ..11 ..1. .1.. = 0x324



	TEX = {0, 8, 0x20, 0x28}
	.... 1... = 8
	..1. .... = 0x20
	..1. 1... = 0x28
	=> bits 5-3 => TEX


	AP = {0x300, 0x600}
	..11 .... .... = 0x300
	.11. .... .... = 0x600
	=> bits 8-10 => AP


	XN = {0x1000, 0}
	...1 .... .... .... = 0x1000
	bit 12 => XN

	B = {0, 1}
	...1 = 1
	bit 0 => B

	Two things are left: 
	- bit 2 is S
	- bit 1 is C

	TEX & C & B encoding is in http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/Cacgehgd.html.

	S and C are always 0 in the table; so we have to guess which is which.
	But given the ordering, it has to be S then C.

	'''
	
	def __init__(self, addr = -1):

		if (addr == -1):
			print "NEW REGION"

			self.DRBAR = 0
			self.parse_DRBAR()

			self.DRSR = 0
			self.parse_DRSR()

			self.DRACR = 0
			self.parse_DRACR()

			self.DRNR = 0
			self.parse_DRNR()

			return

		print "NEXT REGION"		

		#base address register
		self.DRBAR = idc.Dword(addr+4)
		self.parse_DRBAR()

		#region size and enable register
		self.DRSR = idc.Dword(addr+2*4) + idc.Dword(addr+9*4)
		self.parse_DRSR()

		#region number register
		self.DRNR = idc.Dword(addr)
		self.parse_DRNR()

		#region access control register
		self.DRACR = idc.Dword(addr+3*4) + idc.Dword(addr+4*4) + idc.Dword(addr+5*4) + idc.Dword(addr+6*4) + idc.Dword(addr+7*4) + idc.Dword(addr+8*4)
		self.parse_DRACR()


		

	def parse_DRNR(self):
		self.num = self.DRNR

	def set_DRNR(self, num):
		self.DRNR = num
		self.num = self.DRNR

	def parse_DRBAR(self):
		self.addr = self.DRBAR

	def set_DRBAR(self, addr):
		self.DRBAR = addr
		self.addr = self.DRBAR

	def parse_subregions(self):
		'''
		All the mpu RSRs are set as one byte, so only bits 0-7 are set.
		This means no subregion is ever disabled.
		Anyway, we implemented this.
		'''

		subregions = (self.DRSR & 0xFFFF) >> 8
		self.disabled_subregions = map(lambda x: (subregions >> x) & 1, range(0, 8))

	#not implementeted, because we don't have a need to ever disable subregions
	def set_subregions(self):
		pass

	def parse_size(self):
		size = (self.DRSR >> 1) & 0x1F

		#we could do this with math instead as 2^(val-0b111)*256, but this way it's more obvious.
		size_map = {
				0b00000 : ('unpredictable!', -1),
				0b00001 : ('unpredictable!', -1),
				0b00010 : ('unpredictable!', -1),
				0b00011 : ('unpredictable!', -1),
				0b00100 : ('unpredictable!', -1),
				0b00101 : ('unpredictable!', -1),
				0b00110 : ('unpredictable!', -1),
				0b00111 : ('256B (0x%08x)' % 256, 256),
				0b01000 : ('512B (0x%08x)' % (256*2), (256*2)),
				0b01001 : ('1 KB (0x%08x)' % (256*(2**2)), (256*(2**2))),	
				0b01010 : ('2 KB (0x%08x)' % (256*(2**3)), (256*(2**3))),		
				0b01011 : ('4 KB (0x%08x)' % (256*(2**4)), (256*(2**4))),	
				0b01100 : ('8 KB (0x%08x)' % (256*(2**5)), (256*(2**5))),	
				0b01101 : ('16 KB (0x%08x)' % (256*(2**6)), (256*(2**6))),
				0b01110 : ('32 KB (0x%08x)' % (256*(2**7)), (256*(2**7))),
				0b01111 : ('64 KB (0x%08x)' % (256*(2**8)), (256*(2**8))),
				0b10000 : ('128 KB (0x%08x)' % (256*(2**9)), (256*(2**9))),
				0b10001 : ('256 KB (0x%08x)' % (256*(2**10)), (256*(2**10))),
				0b10010 : ('512 KB (0x%08x)' % (256*(2**11)), (256*(2**11))),
				0b10011 : ('1 MB (0x%08x)' % (256*(2**12)), (256*(2**12))),
				0b10100 : ('2 MB (0x%08x)' % (256*(2**13)), (256*(2**13))),
				0b10101 : ('4 MB (0x%08x)' % (256*(2**14)), (256*(2**14))),	
				0b10110 : ('8 MB (0x%08x)' % (256*(2**15)), (256*(2**15))),	
				0b10111 : ('16 MB (0x%08x)' % (256*(2**16)), (256*(2**16))),
				0b11000 : ('32 MB (0x%08x)' % (256*(2**17)), (256*(2**17))),
				0b11001 : ('64 MB (0x%08x)' % (256*(2**18)), (256*(2**18))),
				0b11010 : ('128 MB (0x%08x)' % (256*(2**19)), (256*(2**19))),
				0b11011 : ('256 MB (0x%08x)' % (256*(2**20)), (256*(2**20))),
				0b11100 : ('512 MB (0x%08x)' % (256*(2**21)), (256*(2**21))),
				0b11101 : ('1 GB (0x%08x)' % (256*(2**22)), (256*(2**22))),
				0b11110 : ('2 GB (0x%08x)' % (256*(2**23)), (256*(2**23))),
				0b11111 : ('4 GB (0x%08x)' % (256*(2**24)), (256*(2**24)))
		}

		self.size = size_map[size]

	def set_size(self, size):

		size_map = {
				0b00000 : ('unpredictable!', -1),
				0b00001 : ('unpredictable!', -1),
				0b00010 : ('unpredictable!', -1),
				0b00011 : ('unpredictable!', -1),
				0b00100 : ('unpredictable!', -1),
				0b00101 : ('unpredictable!', -1),
				0b00110 : ('unpredictable!', -1),
				0b00111 : ('256B (0x%08x)' % 256, 256),
				0b01000 : ('512B (0x%08x)' % (256*2), (256*2)),
				0b01001 : ('1 KB (0x%08x)' % (256*(2**2)), (256*(2**2))),	
				0b01010 : ('2 KB (0x%08x)' % (256*(2**3)), (256*(2**3))),		
				0b01011 : ('4 KB (0x%08x)' % (256*(2**4)), (256*(2**4))),	
				0b01100 : ('8 KB (0x%08x)' % (256*(2**5)), (256*(2**5))),	
				0b01101 : ('16 KB (0x%08x)' % (256*(2**6)), (256*(2**6))),
				0b01110 : ('32 KB (0x%08x)' % (256*(2**7)), (256*(2**7))),
				0b01111 : ('64 KB (0x%08x)' % (256*(2**8)), (256*(2**8))),
				0b10000 : ('128 KB (0x%08x)' % (256*(2**9)), (256*(2**9))),
				0b10001 : ('256 KB (0x%08x)' % (256*(2**10)), (256*(2**10))),
				0b10010 : ('512 KB (0x%08x)' % (256*(2**11)), (256*(2**11))),
				0b10011 : ('1 MB (0x%08x)' % (256*(2**12)), (256*(2**12))),
				0b10100 : ('2 MB (0x%08x)' % (256*(2**13)), (256*(2**13))),
				0b10101 : ('4 MB (0x%08x)' % (256*(2**14)), (256*(2**14))),	
				0b10110 : ('8 MB (0x%08x)' % (256*(2**15)), (256*(2**15))),	
				0b10111 : ('16 MB (0x%08x)' % (256*(2**16)), (256*(2**16))),
				0b11000 : ('32 MB (0x%08x)' % (256*(2**17)), (256*(2**17))),
				0b11001 : ('64 MB (0x%08x)' % (256*(2**18)), (256*(2**18))),
				0b11010 : ('128 MB (0x%08x)' % (256*(2**19)), (256*(2**19))),
				0b11011 : ('256 MB (0x%08x)' % (256*(2**20)), (256*(2**20))),
				0b11100 : ('512 MB (0x%08x)' % (256*(2**21)), (256*(2**21))),
				0b11101 : ('1 GB (0x%08x)' % (256*(2**22)), (256*(2**22))),
				0b11110 : ('2 GB (0x%08x)' % (256*(2**23)), (256*(2**23))),
				0b11111 : ('4 GB (0x%08x)' % (256*(2**24)), (256*(2**24)))
		}

		self.size = size_map[size]

		self.DRSR = (self.DRSR & 0xFFFFFFC1) + (size << 1)
		#.... .... .... .... .... .... ..XX XXX.


	def parse_en(self):
		self.en = self.DRSR & 1

	def set_en(self, enabled):
		self.en = enabled
		self.DRSR = (self.DRSR & 0xFFFFFFFE) + self.en
		#.... .... .... .... .... .... .... ...X

	def parse_DRSR(self):
		self.parse_subregions()
		self.parse_size()
		self.parse_en()

	def parse_TEX_C_B(self):
		#bit 0 is B, bit 1 is C, bit 3-5 is TEX
		self.TEX = (self.DRACR >> 3) & 0b111
		self.B = (self.DRACR) & 1
		self.C = (self.DRACR >> 1 ) & 1
		self.TEX_C_B = (self.TEX << 2) + (self.C << 1) + self.B

		caching_policy = {
			0b00000 : "Strongly Ordered, Shareable",
			0b00001 : "Shareable Device",
			0b00010 : "Reserved",
			0b00011 : "Not implemented!",
			0b00100 : "Outer and Inner Non-cachable Normal",
			0b00101 : "Reserved",
			0b00110 : "Reserved",
			0b00111 : "Outer and Inner write-back, write-allocate, Normal",
			0b01000 : "Non-shareable Device",
			0b01001 : "Reserved",
			0b01010 : "Reserved",
			0b01011 : "Reserved",
			0b01100 : "Reserved",
			0b01101 : "Reserved",
			0b01110 : "Reserved",
			0b01111 : "Reserved",
			0b10000 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Non-cachable", "Non-cachable"), 
			0b10001 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Non-cachable", "Write-back, write-allocate"),
			0b10010 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Non-cachable", "Reserved"),
			0b10011 : "Non implemented!",
			0b10100 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Write-back, write-allocate", "Non-cachable"),
			0b10101 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Write-back, write-allocate", "Write-back, write-allocate"),
			0b10110 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Write-back, write-allocate", "Reserved"),
			0b10111 : "Non implemented!",
			0b11000 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Reserved","Non-cachable"),
			0b11001 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Reserved", "Write-back, write-allocate"),
			0b11010 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Reserved", "Reserved"),
			0b11011 : "Non implemented!",
			0b11100 : "Non implemented!",
			0b11101 : "Non implemented!",
			0b11110 : "Non implemented!",
			0b11111 : "Non implemented!"
		}

		self.TEX_C_B = caching_policy[self.TEX_C_B]

	def set_TEX_C_B(self, TEX, C, B):

		caching_policy = {
			0b00000 : "Strongly Ordered, Shareable",
			0b00001 : "Shareable Device",
			0b00010 : "Reserved",
			0b00011 : "Not implemented!",
			0b00100 : "Outer and Inner Non-cachable Normal",
			0b00101 : "Reserved",
			0b00110 : "Reserved",
			0b00111 : "Outer and Inner write-back, write-allocate, Normal",
			0b01000 : "Non-shareable Device",
			0b01001 : "Reserved",
			0b01010 : "Reserved",
			0b01011 : "Reserved",
			0b01100 : "Reserved",
			0b01101 : "Reserved",
			0b01110 : "Reserved",
			0b01111 : "Reserved",
			0b10000 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Non-cachable", "Non-cachable"), 
			0b10001 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Non-cachable", "Write-back, write-allocate"),
			0b10010 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Non-cachable", "Reserved"),
			0b10011 : "Non implemented!",
			0b10100 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Write-back, write-allocate", "Non-cachable"),
			0b10101 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Write-back, write-allocate", "Write-back, write-allocate"),
			0b10110 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Write-back, write-allocate", "Reserved"),
			0b10111 : "Non implemented!",
			0b11000 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Reserved","Non-cachable"),
			0b11001 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Reserved", "Write-back, write-allocate"),
			0b11010 : "Normal, outer cache policy: %s inner cache policy: %s" % ("Reserved", "Reserved"),
			0b11011 : "Non implemented!",
			0b11100 : "Non implemented!",
			0b11101 : "Non implemented!",
			0b11110 : "Non implemented!",
			0b11111 : "Non implemented!"
		}

		self.TEX = TEX
		self.C = C
		self.B = B
		self.TEX_C_B = (self.TEX << 2) + (self.C << 1) + self.B
		self.TEX_C_B = caching_policy[self.TEX_C_B]
		self.DRACR = (self.DRACR & 0xFFFFFFC4) + (self.TEX << 3) + (self.C << 1) + self.B
		#.... .... .... .... .... .... ..TT T.CB

	def parse_XN(self):
		self.XN = (self.DRACR >> 12) & 1

	def set_XN(self, XN):
		self.XN = XN & 1
		self.DRACR = (self.DRACR & 0xFFFFEFFF)
		#.... .... .... .... ...X .... .... ....

	def parse_AP(self):
		self.AP = (self.DRACR >> 8) & 0b111

		access_permissions = {
				0b000 : "Privileged: %s User: %s" % ("No access", "No access"),
				0b001 : "Privileged: %s User: %s" % ("Read/Write", "No access"),
				0b010 : "Privileged: %s User: %s" % ("Read/Write", "Read Only"),
				0b011 : "Privileged: %s User: %s" % ("Read/Write", "Read/Write"),
				0b100 : "Reserved!",
				0b101 : "Privileged: %s User: %s" % ("Read Only", "No access"),
				0b110 : "Privileged: %s User: %s" % ("Read Only", "Read Only"),
				0b111 : "Reserved!"
		}

		self.AP = access_permissions[self.AP]

	def set_AP(self, AP):
		access_permissions = {
				0b000 : "Privileged: %s User: %s" % ("No access", "No access"),
				0b001 : "Privileged: %s User: %s" % ("Read/Write", "No access"),
				0b010 : "Privileged: %s User: %s" % ("Read/Write", "Read Only"),
				0b011 : "Privileged: %s User: %s" % ("Read/Write", "Read/Write"),
				0b100 : "Reserved!",
				0b101 : "Privileged: %s User: %s" % ("Read Only", "No access"),
				0b110 : "Privileged: %s User: %s" % ("Read Only", "Read Only"),
				0b111 : "Reserved!"
		}
		self.AP = access_permissions[AP]
		self.DRACR = (self.DRACR & 0xFF) | (self.DRACR & 0xFFFFF800) | (AP << 8)
		#.... .... .... .... .... .XXX .... ....

	def parse_S(self):

		self.shareable = (self.DRACR >> 2) & 1

	def set_S(self, S):
		self.shareable = S & 1
		self.DRACR = (self.DRACR & 0xFFFFFFFB) + (self.shareable << 2)
		#.... .... .... .... .... .... .... .X..

	def parse_DRACR(self):
		self.parse_TEX_C_B()
		self.parse_XN()
		self.parse_AP()
		self.parse_S()

	def pprint(self):

		print "Region num: %d" % 		self.num

		print "DRBAR (R0): 0x%08x" % self.DRBAR
		print "DRSR (R1): 0x%08x" % self.DRSR
		print "DRACR (R2): 0x%08x" % self.DRACR
		print "DRNR (R3): 0x%08x" % self.DRNR


		print "\tRegion addr:\t\t0x%08x-0x%08x" % (self.addr, self.addr+self.size[1])
		print "\tRegion size:\t\t%s" % self.size[0]
		print "\tRegion enabled:\t%d" % self.en
		print "\tDisabled subregions:\t%s" % str(self.disabled_subregions)
		print "\tRegion share-able:\t%d" % self.shareable
		print "\tRegion XN:\t\t%d" % self.XN
		print "\tRegion AP:\t\t%s" % self.AP
		print "\tRegion TEX,C,B:\t%s" % self.TEX_C_B

		'''
		if (self.num == 5):
			#self.set_AP(0b011)
			#print "\tnew DRACR (R2): 0x%08x" % self.DRACR
		'''


def parse_mpu():
	"""
	NOTE: to find this symbol, run find_mcr.py and look for the MPU config instructions.
	Backtrace that function to a wrapper; backtrace that one to the MPU initialization function,
	which calls the wrapper in a loop using values from an array. That array is MPU_region_configs.
	"""
	mpu_struct_addr = idc.LocByName("MPU_region_configs")

	if mpu_struct_addr == 0xFFFFFFFF:
		print "NOTE: to find this symbol, run find_mcr.py and look for the MPU config instructions.\nBacktrace that function to a wrapper; backtrace that one to the MPU initialization function,\nwhich calls the wrapper in a loop using values from an array. That array is MPU_region_configs."
		return

	while(1):
		r = Region(mpu_struct_addr)
		if r.num == 0xFF:
			print "Delimiter found!"
			break
		else:
			r.pprint()			

		mpu_struct_addr += 40

	new_region = Region()
	new_region.set_DRNR(14)
	new_region.set_DRBAR(0x404E6000) 	# mo_call_establishment_trace_setup_msg
	new_region.set_size(0b01011) 		# 256*(2**4) aka 0x1000 aka 4096 bytes
	new_region.set_en(1)				# enabled
	new_region.set_TEX_C_B(0b001,0,0)	# non-cacheble
	new_region.set_XN(0)				# no XN bit
	new_region.set_AP(0b011) 			# RW
	new_region.set_S(1)					# shareable

	new_region.pprint()

if __name__ == "__main__":
	parse_mpu()
