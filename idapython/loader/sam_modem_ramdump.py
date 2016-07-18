# © Copyright 2015/2016 Comsecuris UG
import idaapi
from idc import *
import struct

LTEVER_MAGIC = "\x00ETL\x00REV"

def accept_file(li, n):
	retval = 0

	if n > 0:
		return retval

	li.seek(8*4)

	if li.read(8) == LTEVER_MAGIC:
		retval = "Samsung Shannon CP Dump"

	'''
	else:
		li.seek(8*4)
		for i in range(8):
			print "0x%02x" % ord(li.read(1))
		print "those were the bytes"
	'''

	return retval

def create_modem_hdr_struct():
	hdr_st_id = GetStrucIdByName("hdr_str")
	if hdr_st_id != -1:
		DelStruc(hdr_st_id)

	hdr_st_id = AddStrucEx(-1, "hdr_str", 0)
	#print AddStrucMember(hdr_st_id, "magic", -1, (FF_ASCI|FF_DATA)&0xFFFFFFFF, ASCSTR_C, 4)
	print AddStrucMember(hdr_st_id, "lte", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "ver", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "date_ptr", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "date", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "size", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "load_addr", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "unk1", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print AddStrucMember(hdr_st_id, "unk2", -1, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)


def add_modem_hdr_struct(offs):
	offset = offs
	MakeStruct(offset, "hdr_str")


segments = [
			{"start" : 0x40000000, "len" : 0xE7617C, "name" : ".text", "type" : "CODE"},
			{"start" : 0x40E7617C, "len" : 0x7189E84, "name" : ".data", "type" : "DATA"},
			{"start" : 0x4000000, "len" : 0xE7C4, "name" : ".text_2", "type" : "CODE"},
			{"start" : 0x400E7C4, "len" : 0x183C, "name" : ".data_2", "type" : "DATA"},
			{"start" : 0x4800000, "len" : 0x4000, "name" : ".data_3", "type" : "DATA"},
			{"start" : 0xE0000000, "len" : 0x57000, "name" : ".data_4", "type" : "DATA"},
			{"start" : 0x2F00, "len" : 0x100, "name" : ".data_5", "type" : "DATA"}
]

def load_file(li, neflags, format):

	idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)

	offs = 0

	for s in segments:
		start = s["start"]
		length = s["len"]
		name = s["name"]
		seg_type = s["type"]

		li.file2base(offs, start, start+length, True)
		idaapi.add_segm(0, start, start+length, name, seg_type)

		offs += length

	create_modem_hdr_struct()
	add_modem_hdr_struct(8*4 + segments[0]["start"]) #this might fail unless we carve out a DATA segment from the CODE segment for it.
	
	print "Samsung Shannon image loaded."
	return 1
