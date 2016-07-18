# © Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils

#list of task names to print stack traces for
NAMES = ["MM"]

#whether to assign function names to entry functions
RENAME = False

'''
determine if a dword is a return address or not:
 - & fffffffe points to a code segment
 - within code segment points to a function
 - within function points to an instruction that is preceeded by a call instruction
'''
def ret_addr(ea):

	#we can't assume Thumb only, so we also keep ARM cases, just adjust addr in Thumb cases
	if (ea % 2) != 0:
		ea -= 1

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

def print_call_trace(stack_top, stack_base):

	addr = stack_top
	print '0x%08x - 0x%08x' % (stack_top, stack_base)
	while (addr >= stack_base):

		if ret_addr(Dword(addr)):
			s = "[0x%08x] %s+0x%x" % (addr, str(idc.GetFunctionName(Dword(addr))), Dword(addr) - idaapi.get_func(Dword(addr)).startEA)
 			print s
		addr -= 4
	pass

'''
finding task_struct_head: it is referenced by create_task_struct(), like this (at the end of the snippet):
int __fastcall create_task_struct(int task_struct_ptr, int a2, __int16 a3, int stack_bottom, int stack_size_in_dwords, int a6, int task_start_fn_ptr, int a8, int a9, int a10)
{
  (...)

  task_struct = (int *)task_struct_ptr;
  stack_base_ = stack_bottom + 8;
  *(_DWORD *)stack_bottom = 0xDEADBEEF;
  *(_DWORD *)(stack_bottom + 4) = 0xDEADBEEF;
  v22 = acquire_lock_2();
  j_memcpy_wrapper((char *)task_struct + 92, v11, 8);
  v14 = (unsigned __int16)(word_4800450 + 1);
  word_4800450 += 2;
  v15 = (unsigned __int16)word_4800450;
  *((_WORD *)task_struct + 7) = v14;
  *((_WORD *)task_struct + 6) = v15;
  *((_WORD *)task_struct + 8) = v10;
  *((_WORD *)task_struct + 10) = v14;
  *((_WORD *)task_struct + 9) = v15;
  *((_WORD *)task_struct + 11) = v10;
  task_struct[6] = 1 << (31 - (v15 >> 5));
  task_struct[7] = 1 << (31 - (v15 & 0x1F));
  task_struct[8] = (int)&dword_4802BB8[v15 & 0x1F];
  task_struct[9] = task_start_fn_ptr;
  stack_top_ = stack_base_ + 4 * (stack_size_in_dwords - 8) - 4;// calc stack top. not sure why -8.
  task_struct[21] = a6;
  task_struct[10] = stack_top_;
  task_struct[22] = a8;
  task_struct[12] = stack_top_;
  task_struct[14] = 0;
  task_struct[11] = stack_base_;
  task_struct[15] = 0;
  task_struct[16] = 0;
  task_struct[17] = 0;
  task_struct[20] = 0;
  task_struct[26] = a9;
  place_item_on_list((std_doubly_linked_list_elem *)&task_struct_head, (std_doubly_linked_list_elem *)task_struct); //!!!  here
  (...)


Finding create_task_struct() is easy, it is called from a wrapper, which is called last by the init function that starts the main task;
this can be found easily because it references the strings "sysmem", "usysmem", and "mainTask". So in the function referencing mainTask,
the call that references it is the create_task_struct()'s wrapper.
'''
def task_scan():
	head_addr = idc.LocByName("task_struct_head")

	if head_addr == 0xffffffff:
		print "Please supply task_struct_head address! This is referenced from create_task_struct()"
		return

	next_task = idc.Dword(head_addr)

	num_tasks = 0
	magic = 0x5441534b #"TASK"
	while (next_task != head_addr):

		#print "##################################"

		#print "next task at 0x%08x" % next_task
		num_tasks += 1

		m = idc.Dword(next_task + 4*2)
		assert(m == magic)

		name = idc.GetString(next_task + 4*23)
		print "task name is %s" % name


		'''
		idc.MakeUnknown(next_task, 0x80, idaapi.DOUNK_DELNAMES)
		r = idc.MakeStruct(next_task, "task_struct")

		if not r:
			print "Make Struct Failed at 0x%08x!" % next_task
			print "task name is %s" % name
		'''

		stack_top = idc.Dword(next_task + 4*10)
		stack_base = idc.Dword(next_task + 4*11)

		#if name in NAMES:
			#print "scanning stack for call trace"
			#print_call_trace(stack_top, stack_base)
		print "stack_top: 0x%08x stack_base: 0x%08x" % (stack_top, stack_base)

		beef1 = idc.Dword(stack_base - 4)
		beef2 = idc.Dword(stack_base - 8)

		if beef1 != 0xdeadbeef or beef2 != 0xdeadbeef:
			print "STACK OVERFLOW: %x %x" %(beef1, beef2)

		common_task = idc.Dword(next_task + 4*26)
		print "common_task struct is at 0x%08x" % common_task

		#Main and HSIR{0,1,2} are not common tasks, do not have this
		if common_task != 0:

			entry_func = idc.Dword(common_task + 4*12)
			print "entry function address is 0x%08x" % entry_func
			name = idc.GetFunctionName(entry_func)
			if name == "":
				print "entry function not defined yet! doing it now.."
				idc.MakeFunction(entry_func & 0xFFFFFFFE)
			print "entry function is %s" % idc.GetFunctionName(entry_func)

			if RENAME:
				#now rename the entry function as <task_name>_task_entry
				name = name.strip() + "_task_entry"
				print "new name: %s" % name
				idc.MakeName(entry_func & 0xFFFFFFFE, name)

		

		next_task = idc.Dword(next_task)

	print "Finished, %d tasks found." % num_tasks


task_scan()
