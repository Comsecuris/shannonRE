# (C) Copyright 2015/2016 Comsecuris UG
'''

Control Registers for ARM 7/9/A/R/M-series are different, have to be implemented separately.

This supports ARM R7 and ARM11 so far.

'''


import idaapi
import idc
import idautils

######## Configuration Options ########


DEBUG = False
ADD_COMMENT = True
CPU = "ARM11"

######## ARM11 CP15 Registers ########

CONTROL_OP        = 1
CONTROL_TTB_OP    = 2
DOMAIN_CONTROL_OP = 3
FAULT_STATUS_OP   = 5
FAULT_ADDR_OP     = 5
CACHE_OP          = 7
TLB_OP            = 8
DATA_LD_OP		  = 9
MEM_OP		  	  = 10
ID_OP			  = 13
C15_OP			  = 15

PERF_MON_OP		  = 12 #CRm value, not CRn value

######## ARM9 CP15 Registers ########

R7_SYSTEM_FEATURE_OP	= 0
R7_SYSTEM_CONTROL_OP	= 1
R7_FAULT_STATUS_OP		= 5
R7_MPU_OP				= 6
R7_CACHE_OP				= 7
R7_PERF_OP				= 9
R7_ID_OP				= 13
R7_DBG_INT_OP			= 15


######## ARM11 CP15 MCR Instruction Parsers ########

# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360f/I1014942.html
# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/CACBFJFA.html
# MCR p15,0, <Rd>, c7, <CRm>, <Opcode_2>
def parse_cache_op(mcr):
	# combination of crm and opcode_2
	# luckily these are unique so we are not getting
	# screwed by using a set below as key type
	cache_ops = {
		(0, 4)  : "Wait For Interrupt",
		(5, 0)  : "Invalidate Entire Instruction Cache. Also flushes the branch target cache",
		(5, 1)  : "Invalidate Instruction Cache Line (using MVA)",
		(5, 2)  : "Invalidate Instruction Cache Line (using Set/Way)",
		(5, 4)  : "Flush Prefetch Buffer[1]",
		(5, 6)  : "Flush Entire Branch Target Cache",
		(5, 7)  : "Flush Branch Target Cache Entry",
		(6, 0)  : "Invalidate Entire Data Cache",
		(6, 1)  : "Invalidate Data Cache Line (using MVA)",
		(6, 2)  : "Invalidate Data Cache Line (using Set/Way)",
		(7, 0)  : "Invalidate Both Caches. Also flushes the branch target cache",
		(8, 0)  : "VA to PA translation with privileged read permission check",
		(8, 1)  : "VA to PA translation with privileged write permission check",
		(8, 2)  : "VA to PA translation with user read permission check",
		(8, 3)  : "VA to PA translation with user write permission check",
		(10, 0) : "Clean Entire Data Cache",
		(10, 1) : "Clean Data Cache Line (using MVA)",
		(10, 2) : "Clean Data Cache Line (using Set/Way)",
		(10, 4) : "Data Synchronization Barrier /a",
		(10, 5) : "Data Memory Barrier /a",
		(14, 0) : "Clean and Invalidate Entire Data Cache",
		(14, 1) : "Clean and Invalidate Data Cache Line (using MVA)",
		(14, 2) : "Clean and Invalidate Data Cache Line (using Set/Way)"
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return cache_ops[(crm, op)]

def parse_control_ttb_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHGFCGF.html
	if not (mcr['crm'] == 0 and mcr['opcode2'] == 0):
		return "invalid control op"

	if mcr['crm'] == 0 and mcr['opcode2'] == 0:
		return "Write Translation Table Base Register 0"
	elif mcr['crm'] == 0 and mcr['opcode2'] == 1:
		return "Write Translation Table Base Register 1"
	elif mcr['crm'] == 0 and mcr['opcode2'] == 2:
		return "Write Translation Table Base Control Register 0"

	return ""

def parse_control_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/CHDHEACG.html
	if not (mcr['crm'] == 0 and mcr['opcode2'] == 0):
		return "invalid control op"

	return "Write Control Register configuration data (MMU,Cache,..)"

def parse_domain_control_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360f/I1014942.html
	if not (mcr['crm'] == 0 and mcr['opcode2'] == 0):
		return "invalid control op"

	return "Write Domain Access Control Register configuration data"

def parse_tlb_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0344h/I1001599.html
	# combination of crm and opcode_2
	# luckily these are unique so we are not getting
	# screwed by using a set below as key type
	tlb_ops = {
		(5, 0)  : "Invalidate Inst-TLB",
		(5, 1)  : "Invalidate Inst-TLB entry (MVA)",
		(5, 2)  : "Invalidate Inst-TLB (ASID)",
		(6, 0)  : "Invalidate Data-TLB",
		(6, 1)  : "Invalidate Data-TLB entry (MVA)",
		(6, 2)  : "Invalidate Data-TLB (ASID)",
		(7, 0)  : "Invalidate Inst-TLB and Data-TLB",
		(7, 1)  : "Invalidate Inst-TLB and Data-TLB entry (MVA)",
		(7, 2)  : "Invalidate Inst-TLB and Data-TLB (ASID)"
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return tlb_ops[(crm, op)]

def parse_fault_status_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BHCEDIAA.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BHCBCBBB.html
	ops = {
		(0, 0)  : "Write Data Fault Status Register",
		(0, 1)  : "Write Instruction Fault Status Register"
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

def parse_fault_addr_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BHCDIIIH.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BHCDJDCG.html
	ops = {
		(0, 0)  : "Write Fault Address Register",
		(0, 1)  : "Write Watchpoint Fault Address Register"
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

def parse_data_ld_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHBHCID.html
	ops = {
		(0, 0)  : "Write Data Cache Lockdown Register"
 	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

def parse_mem_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHGFCGF.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHGFCGF.html
	ops = {
		(0, 0)  : "Write TLB Lockdown victim",
		(2, 0)  : "Write Primary Memory Region Remap Register",
		(2, 1)  : "Write Normal Memory Region Remap Register"

	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

def parse_id_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BHCGADDD.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BHCFCGDJ.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/CACEAIHG.html
	ops = {
		(0, 0)  : "Write FCSE PID Register", #this can modify how virt addresses are translated, used by fast context switches
		(0, 1)  : "Write Context ID Register" #ARM maps ASID+virt addr to phys address, ASID is from the Context ID
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

def parse_perf_mon_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHCJBAA.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHGFCGF.
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHJEEHJ.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHHEDCE.html
	ops = {
		0  : "Write Performance Monitor Control Register",
		1  : "Write Cycle Counter Register",
		2  : "Write Count Register 0",
		3  : "Write Count Register 1"
	}

	crm = mcr['crm']
	assert(crm == PERF_MON_OP)
	op  = mcr['opcode2']

	return ops[op]

def parse_tlb_lock_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHGFCGF.html
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360e/BIHGFCGF.html
	ops = {
		(1, 0)  : "Write TLB Debug Control Register",
		(4, 2)  : "Select Lockdown TLB Entry for Read",
		(4, 4)  : "Select Lockdown TLB Entry for Write",
		(5, 2)  : "Write Lockdown TLB VA Register",
		(6, 2)  : "Write Lockdown TLB PA Register",
		(7, 2)  : "Write Lockdown TLB attributes Register",
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

def parse_c15_op(mcr):
	if mcr['crm'] == PERF_MON_OP:
		return parse_perf_mon_op(mcr)
	else:
		return parse_tlb_lock_op(mcr)

######## ARM9 CP15 MCR Instruction Parsers ########


def parse_r7_system_control_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/BGBICDGG.html
	ops = {
		(0, 0)  : "Write System Control Register",				#Bit12: I Cache enable; Bit0: MPU enable
		(0, 1)  : "Write Auxiliary Control Register",		
		(0, 2)  : "Write Coprocessor Access Control Register"
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]	

def parse_r7_mpu_op(mcr):
	# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/BGBFBCFF.html
	ops = {
		(0, 0)  : "Write Data Fault Address Register",
		(0, 2)  : "Write Instruction Fault Address Register",		
		(1, 0)  : "Write MPU Region Base Address Register",			#set base address of region selected by RGNR
		(1, 2)  : "Write MPU Region Size and Enable Register",		#set size and enable the region selected by RGNR
		(1, 4)  : "Write MPU Region Access Control Register",		#set access control for the region selected by RGNR
		(2, 0)  : "Write MPU Region Number Register"				#RGNR: this is a selector for one of 12 or 16 regions.
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return ops[(crm, op)]

# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/BGBGEGJJ.html
# MCR p15,0, <Rd>, c7, <CRm>, <Opcode_2>
def parse_r7_cache_op(mcr):
	cache_ops = {
		(0, 4)  : "No Operation",
		(1, 0)  : "Invalidate all instruction caches to PoU Inner Shareable",
		(1, 6)  : "Invalidate entire branch predictor array Inner Shareable",
		(5, 0)  : "Invalidate entire instruction cache",						# BINGO, this is what we want ideally
		(5, 1)  : "Invalidate instruction cache by VA to PoU",
		(5, 4)  : "Invalidate entire branch predictor array",
		(5, 6)  : "Flush Branch Target Cache Entry",
		(5, 7)  : "Invalidate MVA from branch predictors",
		(6, 0)  : "This is not valid in R7!!! ? In ARM11, it is Invalidate Entire Data Cache",
		(6, 1)  : "Invalidate Data Cache Line by VA to PoC",
		(6, 2)  : "Invalidate Data Cache Line by Set/Way",
		(10, 0) : "This is not valid in R7!!! ? In ARM11, it is Clean Entire Data Cache",
		(10, 1) : "Clean Data Cache Line to PoC by VA",
		(10, 2) : "Clean Data Cache Line by Set/Way)",
		(10, 4) : "Data Synchronization Barrier",
		(10, 5) : "Data Memory Barrier",
		(11, 1) : "Clean data or unified cache line by VA to PoU",
		(14, 1) : "Clean and Invalidate Data Cache Line by VA to PoC",
		(14, 2) : "Clean and Invalidate Data Cache Line by Set/Way"
	}

	crm = mcr['crm']
	op  = mcr['opcode2']

	return cache_ops[(crm, op)]

######## ARM CPU Family Definitions ########


reg_class_dict = {
					"ARM11" : {
								"reg_classes" : {
													CONTROL_OP,
													CONTROL_TTB_OP,
													DOMAIN_CONTROL_OP,
													FAULT_STATUS_OP,
													FAULT_ADDR_OP,
													CACHE_OP,
													TLB_OP,
													DATA_LD_OP,
													MEM_OP,
													ID_OP,
													C15_OP
								},
								"parsers" : {
													CONTROL_OP : parse_control_op,
													CONTROL_TTB_OP : parse_control_ttb_op,
													DOMAIN_CONTROL_OP : parse_domain_control_op,
													FAULT_STATUS_OP : parse_fault_status_op,
													FAULT_ADDR_OP : parse_fault_addr_op,
													CACHE_OP : parse_cache_op,
													TLB_OP : parse_tlb_op,
													DATA_LD_OP : parse_data_ld_op,
													MEM_OP : parse_mem_op,
													ID_OP : parse_id_op,
													C15_OP : parse_c15_op 
								}
					},
					"ARM_R7" : {
								"reg_classes" : {
													R7_SYSTEM_FEATURE_OP,
													R7_SYSTEM_CONTROL_OP,
													R7_FAULT_STATUS_OP,
													R7_MPU_OP,
													R7_CACHE_OP,
													R7_PERF_OP,
													R7_ID_OP,
													R7_DBG_INT_OP
								},
								"parsers" 	  : {	R7_SYSTEM_FEATURE_OP : None,
													R7_SYSTEM_CONTROL_OP : parse_r7_system_control_op,	
													R7_FAULT_STATUS_OP : None,
													R7_MPU_OP : parse_r7_mpu_op,
													R7_CACHE_OP : parse_r7_cache_op,
													R7_PERF_OP : None,
													R7_ID_OP : None,
													R7_DBG_INT_OP : None			
								}
					}
}


######## Utility Functions ########

def find_mcr():
	ins = []
	for seg_ea in Segments():
		for head in Heads(seg_ea, SegEnd(seg_ea)):
			if isCode(GetFlags(head)):
				i = DecodeInstruction(head)
				if i.itype in [idaapi.ARM_mcr, idaapi.ARM_mcr2]:
					ins.append(i)

	return ins

'''
Parses the mcr. If Cn is not in reg_classes, MCR is skipped
'''
def parse_mcr(i, reg_classes):
	parsed_ea = {}

	# sanity check
	op3 = i.Operands[3]
	if op3.type != idaapi.o_void:
		raise("should not happen")

	op0 = i.Operands[0]
	op1 = i.Operands[1]
	op2 = i.Operands[2]

	# MCR      op1{cond} coproc, #opcode1, Rt, CRn, CRm{, #opcode2}
	# MCR p15, 0, R3,c9,c1, 1
	# instruction:
	#     itype: o_idpspec2
	#     p15 is fixed operand, not recorded
	# operand0:
	#     type: o_imm
	# operand1:
	#     type: o_idpspec2
	#         c9: specflag1
	#         c1: specflag2
	#         r3: reg
	# operand2:
	#     type: o_imm

	parsed_ea['coproc'] = "p15"
	parsed_ea['opcode1'] = op0.value
	parsed_ea['rt'] = op1.reg
	parsed_ea['crn'] = op1.specflag1
	parsed_ea['crm'] = op1.specflag2
	parsed_ea['opcode2'] = op2.value

	if DEBUG == True:
		print "%x (%x): op0: %x(%d), op1: %x(%d), op2: %x(%d), op3: %x(%d)" %(i.ea, i.auxpref, op0.value, op0.type, op1.value, op1.type, op2.value, op2.type, op3.value, op3.type)
		print "%x %x %x %x %x %x %x" %(op1.specflag1, op1.specflag2, op1.specflag3, op1.specflag4, op1.specval, op1.reg, op1.flags)

	CRn = parsed_ea['crn']

	if CRn not in reg_classes:
		return False

	#this is not supposed to happen, we did something wrong
	if CRn not in reg_class_dict[CPU]["reg_classes"]:
		print "CPU: %s Cn: %d" % (CPU, CRn)
		raise("Invalid Cn for CPU!")

	func = reg_class_dict[CPU]["parsers"][CRn]
	if func:
		s = func(parsed_ea)
		print_mcr_op(i, parsed_ea, s)
		return True

	else:
		#this mcr is unimplemented currently
		print "Unimplemented mcr!"

	return False


def print_func_props(i):
	f_sea = GetFunctionAttr(i.ea, FUNCATTR_START)
	f_eea = GetFunctionAttr(i.ea, FUNCATTR_END)
	f_nam = GetFunctionName(i.ea)

	print "\t%s() %x-%x (%d bytes)" %(f_nam, f_sea, f_eea, f_eea-f_sea)

def print_mcr_op(i, mcr, s):
	print "%x: %s (using r%d)" %(i.ea, s, mcr['opcode1'])
	if ADD_COMMENT:
		idc.MakeComm(i.ea, s)

def find_ops(instructions, reg_classes = reg_class_dict[CPU]["reg_classes"]):
	done_funcs = []
	for i in instructions:
		f_sea = GetFunctionAttr(i.ea, FUNCATTR_START)
		matched = parse_mcr(i, reg_classes)

		if not matched:
			continue

		if f_sea not in done_funcs:
			print_func_props(i)
			done_funcs.append(f_sea)



######## ARM Revision Specific Functions ########

def find_arm11_cache_ops(instructions):
	find_ops(instructions, [CONTROL_OP, CONTROL_TTB_OP, DOMAIN_CONTROL_OP, FAULT_ADDR_OP, CACHE_OP, TLB_OP, ID_OP])

def find_arm11_all_ops(instructions):
	global CPU

	CPU = "ARM11"
	find_ops(instructions)

def find_arm_R7_all_ops(instructions):
	global CPU

	CPU = "ARM_R7"
	find_ops(instructions, [R7_SYSTEM_FEATURE_OP, R7_SYSTEM_CONTROL_OP, R7_FAULT_STATUS_OP, R7_MPU_OP, R7_CACHE_OP, R7_PERF_OP, R7_ID_OP, R7_DBG_INT_OP])

######## main ########

def main():
	instructions = find_mcr()
	cache_ops = find_arm_R7_all_ops(instructions)

	print "Finished!"

if __name__ == "__main__":
	main()
