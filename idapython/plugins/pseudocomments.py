# (C) Copyright 2015/2016 Comsecuris UG
# this script can export comments from decompiled functions
# and reapply them
import idaapi
import idc
import idautils

import pickle

from os.path import expanduser
from idaapi import Choose

def export_user_variables(ct, f_ea):
	# heavily based on https://idapython.googlecode.com/svn-history/r380/trunk/examples/vds4.py
	class dump_lvar_info_t(idaapi.user_lvar_visitor_t):
		def __init__(self):
			idaapi.user_lvar_visitor_t.__init__(self)
			return
		def get_info_qty_for_saving(self):
			print "qty"
			return 0
		def get_info_for_saving(self, lv):
			return False
		def handle_retrieved_info(self, lv):
			try:
				print "%x %x %x %x" % (lv.ll.get_regnum(), lv.ll.get_reg1(), lv.ll.get_reg2(), lv.ll.get_value())
				print lv.ll.location
				print "Lvar defined at %x (%x)" % (lv.ll.defea, f_ea)
				print >>f, "Lvar defined at %x (%x)" % (lv.ll.defea, f_ea)
				if len(str(lv.name)):
					print "  Name: %s" % (str(lv.name), )
					print >>f, "  Name: %s" % (str(lv.name), )
				#if len(str(lv.type)):
				##~ print_type_to_one_line(buf, sizeof(buf), idati, .c_str());
				#	print "  Type: %s" % (str(lv.type), )
				#	print >>f, "  Type: %s" % (str(lv.type), )

				##print lv.ll.is_reg_var()
				##i = idaapi.lvars_t()
				##print i.find_lvar(lv.ll.defea)
				#lvs = ct.get_lvars()
				#lv_new = lvs.find(lv.ll)
				#if lv_new.name == "foobar":
				#	lv_new.clr_user_name()
				#	lv_new.name = "bliblablub"
				## this is changing the name, when hovering the mouse on it, this is visible
				## however its not saved. why?
				#lv_new.set_user_name()

				# unfortunately the mapping is useless as this is not exported from cfunc_t
				#lm = idaapi.lvar_mapping_t()
				#idaapi.lvar_mapping_insert(ct.lvar_t, c)

#Lvar defined at 400000f
#  Name: foobar
#  Type: <idaapi.tinfo_t; proxy of <Swig Object of type 'tinfo_t *' at 0xd5eef08> >
#<idaapi.lvar_saved_info_t; proxy of <Swig Object of type 'lvar_saved_info_t *' at 0xd5eeba8> >
#<idaapi.lvar_locator_t; proxy of <Swig Object of type 'lvar_locator_t *' at 0xd5eef08> >

			except:
				traceback.print_exc()
			return 0
		def handle_retrieved_mapping(self, lm):
			return 0
		def get_info_mapping_for_saving(self):
			return None

	dli = dump_lvar_info_t();
	idaapi.restore_user_lvar_settings(ct.entry_ea, dli)
	f.close()

def export_pseudocomments_from_fun(f_ea):
	d = {}
	d[f_ea] = {}

	#f_ea = 0x040033EC
	print "Attempting to decompile %x" % f_ea
	try:
		ct = idaapi.decompile(f_ea)
	except idaapi.DecompilationFailure:
		print "error during decompilation (IDA API)"
		return d

	user_cmts = ct.user_cmts
	num_cmts = idaapi.user_cmts_size(user_cmts)

	#export_user_variables(ct, f_ea)

	print "Function 0x%08x has %d pseudocomments" % (f_ea, num_cmts)

	it = idaapi.user_cmts_begin(user_cmts)

	#while it != idaapi.user_cmts_end(user_cmts)
	i = 0
	while (i < num_cmts):
		t = idaapi.user_cmts_first(it)  #treeloc_t
		c = idaapi.user_cmts_second(it) #user_cmts_t

		print "Comment: %s at addr: 0x%08x itp: %d" % (c.c_str(), t.ea, t.itp)

		d[f_ea][i] = {"ea" : t.ea, "comment": c.c_str(), "itp": t.itp}

		i += 1
		it = idaapi.user_cmts_next(it)

	return d

def export_pseudocomments(out_file):
	d = {}

	with open(out_file, "wb") as f:
		for f_ea in Functions(): #[0x4000000]:
			#if f_ea == 0xc638:
			d = dict(export_pseudocomments_from_fun(f_ea), **d)

		pickle.dump(d, f)

def import_pseudocomments_to_fun(f_ea, d):
	if d == {}:
		#print "skipping %x, empty" % f_ea
		return

	print "Attempting to decompile %x" % f_ea
	try:
		ct = idaapi.decompile(f_ea)
	except idaapi.DecompilationFailure:
		print "error during decompilation (IDA API)"
		return

	# i dont know when this happens, but for 404E1404, which is not really a function
	# this is triggered
	if not ct or ct.user_cmts == None:
		print "failed obtaining user cmts at %x" % f_ea
		return

	user_cmts = ct.user_cmts

	it = idaapi.user_cmts_begin(user_cmts)

	for i in d.iterkeys():
		t = idaapi.treeloc_t()
		t.ea = d[i]["ea"]
		t.itp = d[i]["itp"]
		c = idaapi.citem_cmt_t(d[i]["comment"])

		idaapi.user_cmts_insert(user_cmts, t, c)

def import_pseudocomments(in_file):
	with open(in_file, "rb") as f:
		d = pickle.load(f)

		for f_ea in d.keys():
			import_pseudocomments_to_fun(f_ea, d[f_ea])

def pickle_file(s):
	f = idc.AskFile(s == 2, ".pkl", "Please select destination/source")
	return f

def import_export():
	ch = Choose([], "Dump/Restore pseudocode details", 1)
	ch.list = ["Import", "Export"]
	ch.width = 25
	ch.deflt = 1

	c = ch.choose()
	if c > 0:
		pkl_file = pickle_file(c)
		if not pkl_file:
			print "error with file choice"
			return
		if c == 1:
			import_pseudocomments(pkl_file)
		elif c == 2:
			export_pseudocomments(pkl_file)
	else:
		print "moep"

import_export()
