# (C) Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils

def def_functions(s_start):

    num_added_functions = 0

    s_addr = s_start
    s_end = idc.GetSegmentAttr(s_start, SEGATTR_END) #idc.SegEnd(segm)
    print "0x%08x 0x%08x" % (s_start, s_end) 
    
    while (s_addr < s_end):

        print "Testing address 0x%08x" % s_addr
        
        #optimization assumes that function chunks are consecutive (no "function-in-function" monkey business)
        if (idaapi.get_func(s_addr)):
            
            next_func = idc.NextFunction(s_addr)

            ea = s_addr
            for c in idautils.Chunks(s_addr):
                #only use chunks in lookahead that do not jump over the next function and that are not smaller than where we are atm.
                if (c[1] > ea) and (c[1] <= next_func):
                    ea = c[1]
            if ea == s_addr:
                s_addr += 2
            else:
                s_addr = ea            
            #s_addr += 4
            continue
            
        else:
            #This is not a good optimization, there WILL be data refs to function start addresses sometimes.
            '''
            if sum(1 for _ in (CodeRefsTo(s_addr, 1))) != 0:
                s_addr += 4
                continue
            '''
            #also add STMFD 
            if ((idc.GetMnem(s_addr) == "STM") and ("SP!" in idc.GetOpnd(s_addr, 0)) and ("LR" in idc.GetOpnd(s_addr, 1))) or (((idc.GetMnem(s_addr) == "PUSH") or (idc.GetMnem(s_addr) == "PUSH.W") or (idc.GetMnem(s_addr) == "STR.W") ) and ("LR" in idc.GetOpnd(s_addr, 0))):
                print "Found function at 0x%08x" % s_addr
                idc.MakeFunction(s_addr)
                f = idaapi.get_func(s_addr)
                if (type(f) == type(None)):
                    print "Failed to create function! Undefined instructions?"
                    s_addr += 2
                else:
                    num_added_functions += 1
                    ea = -1
                    for c in idautils.Chunks(s_addr):
                        if c[1] > ea:
                            ea = c[1]
                    if ea != -1:
                        s_addr = ea
                    #failed?
                    else:
                        s_addr += 2
            else:
                s_addr += 2

    print "finished segment"
    return num_added_functions
 

num_total_added_functions = 0
for s in idautils.Segments():
    s_start = s   
    if idaapi.segtype(s_start) == idaapi.SEG_CODE:
        print "starting segment at 0x%08x" % s_start
        num_total_added_functions += def_functions(s)

print "Added %d functions in total" % num_total_added_functions
