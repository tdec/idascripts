# LCA scan IDA helper script
# 
# Copyright (c) F-Secure Corporation
#
# Use of this source code is governed by the license
# that can be found in the LICENSE file

from __future__ import print_function
import idc
import idautils
import ida_entry
import ida_kernwin

# This script finds the lowest common ancestor functions for 2 defined function
# calls. Example, function calling both CreateFileW and Closehandle down the
# line.

# set interactive to True to be asked for the function names in a pop up
interactive = False

# Function names we're looking for if interactive = False

fname = "LoadLibraryW"
fname2 = "CreateFontW"


def traverse(name):
    _set = set()
    queue = list()
    processed = set()

    print("[+] Looking for %s" % (name), end="")
    wf_addr = idc.get_name_ea_simple(name)
    print(" found at: %08x" % (wf_addr))
    queue.append(wf_addr)
    processed.add(wf_addr)

    while queue:
        # print("%d more in Q1" % len(queue))
        wf_addr = queue.pop()
        # print("Popped %08x - %s" % (wf_addr, get_name(wf_addr)))

        for xref in idautils.XrefsTo(wf_addr, 1):
            if xref.iscode == 1:
                fn_entry = idc.first_func_chunk(xref.frm)
                fn_name = get_name(fn_entry)
                _set.add(fn_entry)
                if fn_entry not in entrypoints and fn_entry not in processed:
                    queue.append(fn_entry)
                    processed.add(fn_entry)
                # else:
                #    print("Entrypoint detected as calling function")

                # print("%s : %08x(%s) -> %08x -> %08x" %
                #    (fn_name, fn_entry, fn_entry, xref.frm, xref.to))
    return _set


print("========== LCA function scan ==========")

if interactive:
    fname = ida_kernwin.ask_text(0, "",
                                 "Give the name of the first function call")
    fname2 = ida_kernwin.ask_text(0, "",
                                  "Give the name of the second function call")

# Create a set containing all entry points to the binary,
# we need to stop recursive processing when we encounter them

entrypoints = set()
for e in Entries():
    entrypoints.add(e[2])

# Traverse references to entrypoints

set1 = traverse(fname)
set2 = traverse(fname2)

# Traverse the first set to see which are also found in the second set
if set1 and set2:
    print("[+] Functions found leading to both %s and %s:" % (fname, fname2))
    for result in set1.intersection(set2):
        n = get_name(result)
        print("[*] \t0x%08x %s" % (result, n))
else:
    print("Function calls or no results found")
