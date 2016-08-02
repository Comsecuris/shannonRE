# (C) Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils

"""
NOTE: set your log path
"""
LOG_PATH = "."

'''
determine if a dword is a return address or not:
 - odd value (b/c of Thumb and BX LR)
 - & fffffffe points to a code segment
 - within code segment points to a function
 - within function points to an instruction that is preceeded by a call instruction
'''
def ret_addr(ea):

	#we can't assume Thumb only, so we also keep ARM cases, just adjust addr in Thumb cases
	if (ea % 2) != 0:
		ea -= 1

	'''
	#calculating code segment ranges every time is wasteful
	code_segs = []
	for s in idautils.Segments():
		if idaapi.segtype(s) == idaapi.SEG_CODE:
			s_end = idc.GetSegmentAttr(s, SEGATTR_END)
			code_segs.append({"start" : s, "end" : s_end})

	if not reduce(lambda x, y: x or y, map(lambda x: (x["start"] <= ea) and (x["end"] > ea), code_segs)):
		return False
	'''

	#this is-in-function check is enough (segment check redundant) if we trust function ID'ing anyway.

	f_ea = idaapi.get_func(ea)
	if not f_ea:
		return False

	#Preceding or Previous?
	#	Not necessarily all preceding will be a call to a ret instruction,
	#	but "the" prev should be always the one.
	i = idautils.DecodePreviousInstruction(ea)
	if i and "BL" in idc.GetMnem(i.ea):
		return True

	return False

'''
find all return addresses within a segment
'''
def find_ret_addrs(s):
	s_addr = s
	addrs = []

	s_start = s_addr
	s_end = idc.GetSegmentAttr(s_start, SEGATTR_END)

	while (s_addr < s_end):

		d = Dword(s_addr)
		if ret_addr(d):
			addrs.append(s_addr)
		s_addr += 4

	return addrs

'''
logging functions
'''

def log_stack_addrs(stack_addrs):

	print len(stack_addrs)

	f = open("%s/%s" % (LOG_PATH, "stack_all"), "wb")

	for a in stack_addrs:
		#s = "[0x%08x] ret address 0x%08x to function %s" % (a, Dword(a), str(idc.GetFunctionName(Dword(a))))
		s = "[0x%08x] %s+0x%x" % (a, str(idc.GetFunctionName(Dword(a))), Dword(a) - idaapi.get_func(Dword(a)).startEA)
		f.write(s)
		f.write("\n")

	f.close()

def log_stack_chains(chains):

	f = open("%s/%s" % (LOG_PATH, "stack_chains"), "wb")

	long_chains = 0

	for c in chains:
		if len(c) > 3:
			long_chains += 1
		for a in c:
			if type(a) == type("x"):
				s = a
			else:
				s = "[0x%08x] %s+0x%x" % (a, str(idc.GetFunctionName(Dword(a))), Dword(a) - idaapi.get_func(Dword(a)).startEA)

			#print s
			f.write(s)
			f.write("\n")
		f.write("\n")


	print "%d chains found" % len(chains)
	print "%d long chains" % long_chains

	f.close()


'''
scan data segments for dwords that contain return addresses
'''
def scan_for_stacks():

	def preceeding_call(ea):
		p = idautils.DecodePreviousInstruction(ea)
		if p and "BL" in idc.GetMnem(p.ea):
			return str(idc.GetOpnd(p.ea, 0))
		else:
			return ""

	def jumps_to(f, t):
		f_ea = idc.LocByName(f)
		t_ea = idc.LocByName(t)

		for start,end in idautils.Chunks(f_ea):
			ea = start
			while (ea < end):
				i = idautils.DecodeInstruction(ea)

				#Functions have data chunks in them, these are offsets and dwords. skipping 4 ahead seems like a safe choice.
				if type(i) == type(None):
					ea += 4
					continue

				#detect if instruction is a jump to t_ea
				m = idc.GetMnem(ea)
				if idc.GetMnem(ea) == "LDR" and idc.GetOpnd(ea, 0) == "PC" and t in idc.GetOpnd(ea, 1):
					return True
				elif idc.GetMnem(ea) == "BX" and idc.GetOpnd(ea, 0) == t:
					return True

				try:
					ea += i.size
				except:
					print "0x%08x" % ea
					print "DecodeInstruction failed!"
					print i.size

		return False

	#return True if the function at ea has an indirect jump, like BX Reg
	#    (This is not so simple, e.g. we don't want to include jumptables etc... for now it is just this simple implementation.)
	def jumps_to_reg(ea):
		return False

	stack_addrs = []
	for s in idautils.Segments():
		if idaapi.segtype(s) != idaapi.SEG_CODE:
			print "starting scanning segment at 0x%08x" % s
			addrs = find_ret_addrs(s)
			print "found %d return addresses in segment" % len(addrs)
			stack_addrs += addrs

	log_stack_addrs(stack_addrs)

	print "okay, stored all occurences. let's find viable call chains."

	chain = []
	chains = []

	for i in range(len(stack_addrs)):

		#if this is the last one, just add to chain if had to and finish.
		if (i == (len(stack_addrs) - 1) ):
			if len(chain) > 0:
				chain.append(addr)
				chains.append(chain)
			continue

		addr = stack_addrs[i]
		ret_addr = Dword(addr) & 0xFFFFFFFE #adjust Thumb addresses
		to_f = str(idc.GetFunctionName(ret_addr))

		next_ret_addr = Dword(stack_addrs[i+1]) & 0xFFFFFFFE #adjust Thumb addresses

		pre_f = preceeding_call(next_ret_addr)
		if pre_f == to_f:
			chain.append(addr)

		elif jumps_to(pre_f, to_f):
			chain.append("direct jump")
			chain.append(addr)

		elif jumps_to_reg(pre_f):
			chain.append("indirect_jump?")
			chain.append(addr)
 
		#no bonus, need to start a new chain at next_ret_addr

		else:
			# if there is an existing chain, that means this addr was connected to the previous, so can be added into the chain.
			if len(chain) > 0:
				chain.append(addr)
				chains.append(chain)
			
			chain = []

	print "found all chains, logging..."

	log_stack_chains(chains)

	print "... and done!"

scan_for_stacks()
