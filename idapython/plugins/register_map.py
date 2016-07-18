# © Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils

VERSION="D_OCT_MR"

'''
NOTE: In order to get the register map base addr:
- follow svc vector (at 0x40000000+8)
- follow that to svc_inner
- in svc_inner, grabe the svc_table address (it's 3 dwords right after the short instruction sequence)
- follow svc_table to 2nd function in it
- in that function, grab the register map address (it's the LDR R12'd dword)
'''

if VERSION == "D_OCT_MR":
	NORM_BASE = 0x4183BEB0
elif VERSION == "D_NOV_MR":
	NORM_BASE = 0x4338735C
elif VERSION == "D_FEB_MR":
	NORM_BASE = 0x431C5274
else:
	NORM_BASE = 0x4338735C

SVC_BASE = NORM_BASE + 72
USR_BASE = NORM_BASE + 60
ABT_BASE = NORM_BASE + 84
UND_BASE = NORM_BASE + 96
IRQ_BASE = NORM_BASE + 104

register_map = {
	'r0'          : NORM_BASE,
	'r1'          : NORM_BASE + 4,
	'r2'          : NORM_BASE + 8,
	'r3'          : NORM_BASE + 12,
	'r4'          : NORM_BASE + 16,
	'r5'          : NORM_BASE + 20,
	'r6'          : NORM_BASE + 24,
	'r7'          : NORM_BASE + 28,
	'r8'          : NORM_BASE + 32,
	'r9'          : NORM_BASE + 36,
	'r10'         : NORM_BASE + 40,
	'r11'         : NORM_BASE + 44,
	'r12'         : NORM_BASE + 48,
	'r15_pc'      : NORM_BASE + 52,
	'cpsr'        : NORM_BASE + 56,
	'r13_sp_svc'  : SVC_BASE,
	'r14_lr_svc'  : SVC_BASE + 4,
	'r13_sp_usr'  : USR_BASE,
	'r14_lr_usr'  : USR_BASE + 4,
	'spsr_abt'    : ABT_BASE,
	'r13_sp_abt'  : ABT_BASE + 4,
	'r14_lr_abt'  : ABT_BASE + 8,
	'spsr_und'    : UND_BASE,
	'r13_sp_und'  : UND_BASE + 4,
	'r14_lr_und'  : UND_BASE + 8,
	'spsr_irq'    : IRQ_BASE,
	'r13_sp_irq'  : IRQ_BASE + 4,
	'r14_lr_irq'  : IRQ_BASE + 8
}

def name_registers():
	for (reg, addr) in register_map.iteritems():
		idc.MakeName(addr, reg)

def print_registers():
	for (reg, addr) in register_map.iteritems():
		print "%s: 0x%08x" %(reg, idc.Dword(addr))

name_registers()

print_registers()

idc.Jump(NORM_BASE)
