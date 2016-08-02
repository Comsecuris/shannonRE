# (C) Copyright 2015/2016 Comsecuris UG
# The intention of this script is to come up with function labels based on strings within the binary
# For this we use simple heuristics and back-tracing of function arguments
import os
import idautils
import idc
import idaapi
import json
import re

IDAStrings = []

exact_name = 0
misc_name = 0
fuzzy_path_name = 0
fuzzy_long_path_name = 0

def trace_arg_bwd(ea, arg_num):

	ARCH = "ARM32"
	CALL_ARGS = {"ARM32" : ["R0", "R1", "R2", "R3"]}

	args = CALL_ARGS[ARCH]
	
	if (len(args) <= arg_num):
		arg_into = "SP"
		arg_offs = ((arg_num - len(args))) * 4
	else: 
		arg_into = CALL_ARGS[ARCH][arg_num]
		arg_offs = 0

	func = idaapi.get_func(ea)
	fc = idaapi.FlowChart(func)

	for block in fc:
		if block.startEA <= ea and block.endEA > ea:
			break


	#original sink
	arg_in = set([arg_into])

	while (ea >= block.startEA):

		#print "0x%08x %s" % (ea, idc.GetDisasm(ea))

		############ BEGINNING OF TRACING ############

		mnem = idc.GetMnem(ea)

		if mnem == "MOV":
			arg_to = idc.GetOpnd(ea, 0)
			arg_from = idc.GetOpnd(ea, 1)


			#propagate to new register
			if arg_to in arg_in:
				arg_in.add(arg_from)
			#note: if arg_from is in arg_in, but arg_to isn't, we don't add arg_to to the sinks, because we are going backwards,
			#so we know that's not the one that ended up being used.

		elif mnem == "LDR":

			arg_to = idc.GetOpnd(ea, 0)
			arg_from = idc.GetOpnd(ea, 1)

			if ARCH == "ARM32":

				if arg_to in arg_in:
					#now there should be a a DataRef here to a string.
					#we want the data reference that is of type 1 (Data_Offset), as oppossed to 1 (Data_Read)
					refs = [r for r in idautils.XrefsFrom(ea) if r.type == 1]
					if len(refs) == 1:
						#print "There is only one data offset reference from here, if it is a string we are done."
						for s in IDAStrings:
							if s.ea == refs[0].to:
								return str(s)

		elif mnem == "ADR" or mnem == "ADR.W":
			#print "ADR instruction!"

			arg_to = idc.GetOpnd(ea, 0)
			arg_from = idc.GetOpnd(ea, 1)

			if ARCH == "ARM32":

				if arg_to in arg_in:
					#now there should be a a DataRef here to a string.
					#we want the data reference that is of type 1 (Data_Offset), as oppossed to 1 (Data_Read)
					refs = [r for r in idautils.XrefsFrom(ea) if r.type == 1]
					if len(refs) == 1:
						#print "There is only one data offset reference from here, if it is a string we are done."
						for s in IDAStrings:
							if s.ea == refs[0].to:
								return str(s)

		elif mnem == "ADD":

			arg_to = idc.GetOpnd(ea, 0)
			arg_from = idc.GetOpnd(ea, 1)

			if ARCH == "ARM32":

				if arg_from == "PC" and arg_to in arg_in:

					#now there should be a a DataRef here to a string.
					if sum(1 for _ in idautils.DataRefsFrom(ea)) == 1:
						for ref in idautils.DataRefsFrom(ea):
							#get string at ref
							for s in IDAStrings:
								if s.ea == ref:
									return str(s)

		############ END OF TRACING ############

		if ea == block.startEA:

			#For some reason, block.preds() seems to be broken. I get 0 predecessors to every block. So for now, we limit to same block.
			#Also idaapi.decode_preceding_instruction is annoying, because if there are more than 1 preceding, it just shows the first one only.
			#So this is getting around the preds() not working.

			preds = []
			for b in fc:
				for s in b.succs():
					if s.startEA == block.startEA:
						#this is a predecessor block to us
						preds.append(b)

			if len(preds) == 1:
				#print "1 predecessor, continuing there"
				block = preds[0]
				i = idautils.DecodePreviousInstruction(block.endEA)
				ea = block.endEA - i.size

			else:
				#print "0 or multiple predecessor blocks, givin up."
				return ""

		else:
			i = idautils.DecodePreviousInstruction(ea)
			ea -= i.size

 	return ""

#######################################################################################################################################


#This returns the functions that call f_ea
def find_callers(f_ea):
	callers = set(map(idaapi.get_func, CodeRefsTo(f_ea, 0)))
	parents = []
	for ref in callers:
		if not ref:
			continue
		parents.append(ref.startEA)

	return parents

#This returns the call site within function f_ea that calls the function target_f_ea
def find_caller(f_ea, target_f_ea):
	f = idaapi.get_func(f_ea)
	if not f:
		return None

	for caller in set(CodeRefsTo(target_f_ea, 0)):
		if f.startEA <= caller and f.endEA > caller:
			return caller

	return None


# this function should return the name that should be used instead
# or null if none was found
def overwrite_name_by_arg(f_ea):

	# There are several functions that give some labeling info about the caller
	# But most don't give us more than the by-reference pathname labeling already.

	# These always give extra info

	## dbg_trace_args_something_wrapper_0-6: a function name

	# This sometimes gives extra info

	## print_0: a function name - but not always

	# These give extra info if we combine the basename and the linenumber

	## fatal_error: a file basename and a linenumber
	## dbg_log_something: a file name (sometimes a basename, sometimes a path) and a linenumber
	## assert_failed: a full path (we would get that already) and a linenunber
	## sub_400B0C24: a file name (sometimes a basename, sometimes a path) and a linenumber

	# These give no extra info, we can discard them

	## sub_4084D288: a full path (we would get that already)
	## malloc, free: a full path (we would get that already)
	## rrc_system_services_something__3: a full path (we would get that already)

	# For now we only use the ones that directly give extra info in arg0 always, so the dbg_trace wrappers.
	# IMPORTANT NOTE: IDA will not know the two labels, you will have to find
	# them manually. The below list is also not complete.  For each of these
	# functions (and there is definitely more), look for the following string,
	# go to it's cross reference, and label the function for this code to work.
	# We didn't put in automation for this anymore. Sorry about that :)
	#
	# For dbg_trace_args_something_wrapper:
	#     - look for "mm_InitGmmServiceReq" string
	#     - next branch will go to dbg_trace_args_something_wrapper (the aforementioned string is the second argument)
	# For dbg_trace_args_something_wrapper_0:
	#     - look for "ds_mm_InitGmmServiceReq" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the second argument)
	# For dbg_trace_args_something_wrapper_1:
	#     - look for "mm_CoordinateRatChange" string
	#     - next branch will go to dbg_trace_args_something_wrapper_1 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_2:
	#     - look for "mm_DecodeRrReleaseIndMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_4:
	#     - look for "sm_GetPdpAddressPtr" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the second argument)
	# For dbg_trace_args_something_wrapper_5:
	#     - look for "sms_DecodeMmRelIndMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_6:
	#     - look for "sms_DecodeUbmcDataIndMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_7:
	#     - look for "ds_mm_DecodeGmmSnReestReqMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the first argument)

	arg_funcs = {
		
		idc.LocByName('dbg_trace_args_something_wrapper') : 1,
		idc.LocByName('dbg_trace_args_something_wrapper_0') : 1,
		idc.LocByName('dbg_trace_args_something_wrapper_1') : 0,
		idc.LocByName('dbg_trace_args_something_wrapper_2') : 0,
		idc.LocByName('dbg_trace_args_something_wrapper_4') : 1,
		idc.LocByName('dbg_trace_args_something_wrapper_5') : 0,
		idc.LocByName('dbg_trace_args_something_wrapper_6') : 0,
		idc.LocByName('dbg_trace_args_something_wrapper_7') : 0,

		#idc.LocByName('dbg_trace_args_something_wrapper') : 1,
		#idc.LocByName('sub_40676D04') : 1,
		#idc.LocByName('sub_40D20ECA') : 0,
		#idc.LocByName('sub_40D20EAC') : 0

		#idc.LocByName('print_0') : 0,

		#idc.LocByName('fatal_error') : 1,
		#idc.LocByName('assert_failed') : 1,
		#idc.LocByName('sub_408AB208') : 1,
		#idc.LocByName('sub_400B0C24') : 1,

		#idc.LocByName('sub_4084D288') : 1,
		#idc.LocByName('j_free') : 1,
		#idc.LocByName('rrc_system_services_something__3') : 1,
	}

	for target_f_ea, arg_n in arg_funcs.iteritems():
		if f_ea in find_callers(target_f_ea):
			caller_ea = find_caller(f_ea, target_f_ea)
			#print "Should replace name of 0x%08x with arg #%d in call of 0x%08x" %(f_ea, arg_n, target_f_ea)
			new_name = trace_arg_bwd(caller_ea, arg_n)

			if new_name == "":
				return None
			elif " " in new_name: #sanity check that name works as a function name
				return None
			elif ("sub_" in idc.GetFunctionName(f_ea)) or ("_something" in idc.GetFunctionName(f_ea)):
				print "Found new name: %s" % new_name
				return new_name
			else:
				print "Found same name %s as %s" % (new_name, idc.GetFunctionName(f_ea))
				return new_name

	return None

def str_fun_xrefs():
	str_fun_xref = {}
	for s in IDAStrings:
		for ref in idautils.DataRefsTo(s.ea):
			f = idaapi.get_func(ref)
			if not f:
				continue

			if idc.GetMnem(ref) == "":
				continue

			f_ea = f.startEA
			try:
				#because we are only carrying the string value itself, duplications should be removed.
				#This is important because of OFFS/ADR instruction double references being very typical,
				#and multiple allocations/frees in same function causing extra references too.
				str_fun_xref[f_ea].add(str(s))
			except:
				str_fun_xref[f_ea] = set([str(s)])

	return str_fun_xref

def path_misc_strings(str_l):
	path_strings = []
	misc_strings = []
	for s in str_l:
		if "../" in s and os.path.splitext(s)[1] == ".c":
			path_strings.append(s)
		else:
			misc_strings.append(s)

	return (path_strings, misc_strings)

def module_path(p):

	p_path = os.path.dirname(p)
	# the following heuristic to get rid of cruft in the path name
	# is based on the following logic:
	# strings cpcrash_dump_20150609-2313.log|grep '\.\./'|grep -vE "(code/|src/|Source/|Src|Inc)" |wc -l
	# 41
	# this shows that almost all file paths (and I didn't even only look at .c here)
	# have the common structure, which we can nicely strip away
	replace_str = ["../", "/src", "/Src", "/code", "/Code", "/Inc"]
	for rp in replace_str:
		p_path = p_path.replace(rp, "")

	# based on the strings that we see in the paths, we take the last 5 path
	# elements for the caller
	p_path = "_".join(p_path.split('/')[-5:])

	return p_path

# returns function and function caller name
def function_label(p_strings, m_strings, f_ea):
	p_str_len = len(p_strings)
	m_str_len = len(m_strings)
	p_name = None
	f_name = None
	m_name = None
	global exact_name, misc_name, fuzzy_path_name, fuzzy_long_path_name

	#Locate a possible more unique function name than what we can derive from generic or path strings
	overwrite_name = overwrite_name_by_arg(f_ea)

	if p_str_len == 1:
		exact_name += 1

		m_name = module_path(p_strings[0])

		if type(overwrite_name) == type(None):
			f_name = os.path.basename(p_strings[0])
			f_name = "%s_something" % os.path.splitext(f_name)[0]
			f_name = "%s_%s" % (m_name, f_name)

		else:
			f_name = overwrite_name

		p_name = "calls_%s" % f_name


	elif p_str_len == 2 and "../../../HEDGE/GL1/GPHY/L1X/Code/Src/l1x_srch_tch.c" in p_strings:
		#That's just an IDA messup! Ghetto way of skipping it
		if "../../../HEDGE/GL1/GPHY/L1X/Code/Src/l1x_srch_tch.c" in p_strings[0]:
			name = p_strings[1]
		else:
			name = p_strings[0]

		exact_name +=1
		m_name = module_path(name)

		if type(overwrite_name) == type(None):
			f_name = os.path.basename(name)
			f_name = "%s_something" % os.path.splitext(f_name)[0]
			f_name = "%s_%s" % (m_name, f_name)
		else:
			f_name = overwrite_name

		p_name = "calls_%s" % f_name


	elif p_str_len == 0:

		def accept_string(s):
			if len(s) < 5:
				return False
			#be alphanumberic or "_"
			elif not re.match(r'^[a-zA-Z0-9_]+$', s):
				return False
			#have consonant
			elif not re.match(r'.*[bcdfghjklmnpqrstvwxyz].*', s.lower()):
				return False
			#have vowel
			elif not re.match(r'.*[aeiou].*', s.lower()):
				return False
			return True

		if type(overwrite_name) != type(None):
			m_name = "misc"
			p_name = None
			f_name = overwrite_name
			exact_name += 1

		elif m_str_len == 1 and accept_string(m_strings[0]):

			f_name = "misc_%s_something" % m_strings[0]
			p_name = None
			m_name = "misc"
			misc_name += 1

		# if we have a small number of strings
		# and these are small, we can try to
		# use these!
		elif m_str_len > 1 and m_str_len <= 3:

			m_strings = filter(accept_string, set(m_strings))
			if len(m_strings) > 0:
				f_name = "_".join(set(m_strings))
				f_name = "misc_%s_something" % f_name
				p_name = None
				m_name = "misc"

				if len(f_name) > 30:
					f_name = None
					m_name = None

				else:
					misc_name += 1


	#### These 2 cases here were all cleaned up, we no longer need them, hence everything is assigned None in them.

	# if we have less than 3 file names we
	# try a combination of these
	# for the parent we are lazy and take the part of from the first path
	elif p_str_len > 1 and p_str_len < 3:

		#These cases are all just mistakes by IDA, so this case actually does not exist in the binary at all.
		fuzzy_path_name += 1
		f_name = "_".join(set([os.path.splitext(os.path.basename(str(p)))[0] for p in p_strings]))
		f_name = "%s_something" % f_name
		f_name = "%s_%s" % (module_path(str(p_strings[0])), f_name)
		p_name = "calls_%s" % f_name

		print "Hey look, a function with two paths names at 0x%08x, would become %s" % (f_ea, f_name)
		print p_str_len, p_strings

		f_name = None
		p_name = None
		m_name = None
		

	# as a last resort we just take the first of these and name them
	# so this is visible
	elif p_str_len >= 3:

		#There is one hitting this by mistake and one that is a very unique function that we named manually. So no need for this.
		fuzzy_long_path_name += 1
		f_name = os.path.basename(str(p_strings[0]))
		f_name = "calls_%s_something" % os.path.splitext(f_name)[0]
		p_name = "calls_%s_c_%s" % (module_path(str(p_strings[0])), f_name)

		#print "Hey look, a fuzzy long path name: %s at 0x%08x, would become %s" % (f_name, f_ea, f_name)
		#print len(p_strings), p_strings

		f_name = None
		p_name = None
		m_name = None

	return (f_name, p_name, m_name)

def apply_labels(fun_names):
	new_sub = 0
	new_som = 0
	new_oth = 0

	named_overwrittens = []

	for f_ea, name in fun_names.iteritems():
		name = re.sub('[^a-zA-Z0-9_]+', '', name)
		curr_name = idaapi.get_func_name(f_ea)
		if curr_name.startswith("sub_"):
			new_sub += 1
		elif "_something" in curr_name:
			new_som += 1
		else:
			new_oth += 1
			named_overwrittens.append(curr_name)
			#so we don't overwrite these
			continue

		# stats counting aside, make sure we don't overwrite non-sub
		# functions from e.g. our IDC assignments
		if not curr_name.startswith("sub_") and not "_something" in curr_name:
			continue

		ret = idc.LocByName(name)
		count = 1
		while (ret != 0xffffffff):
			count += 1
			ret = idc.LocByName(name + "__" + "%d" % count)
		idc.MakeName(f_ea, name + ("__%d" % count)*(count > 1))


def log_statistics(fun_name, parent_labels):

	global exact_name, misc_name, fuzzy_path_name, fuzzy_long_path_name

	print len(fun_name)
	print "%d exact names" % exact_name
	print "%d misc names" % misc_name
	print "%d fuzzy path names" % fuzzy_path_name
	print "%d fuzzy long path names" % fuzzy_long_path_name
	print "total labeled functions: %d" %(exact_name + fuzzy_path_name + fuzzy_long_path_name + misc_name)
	print "total labeled parents: %d" % parent_labels

def label_functions():

	global IDAStrings

	print "Collecting string references ..."

	for s in idautils.Strings():
		IDAStrings.append(s)

	str_fun_xref = str_fun_xrefs()
	fun_name = {}
	fun_parent_name = {}
	fun_module_name = {}
	parent_labels = 0

	print "Creating labels for functions ..."

	for f_ea, str_l in str_fun_xref.iteritems():
		(path_strings, misc_strings) = path_misc_strings(str_l)
		(f_name, p_name, m_name) = function_label(path_strings, misc_strings, f_ea)
		if f_name != None:
			fun_name[f_ea] = f_name
			fun_parent_name[f_ea] = p_name
			fun_module_name[f_ea] = m_name

	print "Assigning labels ..."

	# we apply the parents after we labeled the strings
	# and dont label the callers right away. otherwise
	# we could overwrite function names that already had an exact name
	for f_ea, name in fun_parent_name.iteritems():
		#None for functions labels from misc strings,
		#i.e. only labeling parents of pathname-labeled functions
		if name != None:
			for p in find_callers(f_ea):
				# make sure we dont overwrite a function that already had an exact name
				# Note: a function that calls both e.g. malloc() and a module specific
				#		 function will be luck-of-the-draw which one its named after
				if p not in fun_name.keys():
					fun_name[p] = name
					parent_labels += 1
				#if not given a module name yet
				if p not in fun_module_name.keys():
					fun_module_name[p] = fun_module_name[f_ea] #parent goes into same module as called child its labeled after

	print "Applying labels to the idb ..."

	apply_labels(fun_name)

	print "Assigning module names to unlabeled functions ..."

	for f_ea in Functions():
		if f_ea not in fun_module_name.keys():
			fun_module_name[f_ea] = "unk"

		elif type(fun_module_name[f_ea]) == type(None):
			fun_module_name[f_ea] = "unk"

	print "Logging statistics ..."

	log_statistics(fun_name, parent_labels)

	print "... and done!"
	return

label_functions()


"""
class function_labeler_plugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "foo"
	help = "bar"
	wanted_name = "function labeler"
	wanted_hotkey = "Alt-F8"

	def init(self):
		return idaapi.PLUGIN_OK

	def run(self, arg):
		label_functions()

	def term(self):
		pass


def PLUGIN_ENTRY():
	return function_labeler_plugin()
"""
