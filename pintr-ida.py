#!/usr/bin/python
# -*- coding: utf-8 -*-

import idc
import idaapi
import idautils

import re
import struct

PINTRIDA_VERSION = "0.1.1"

MAX_LOOP_COUNT = 5

COLOR_DEFAULT       = 0xDDDDDD # gray
COLOR_DEPEND_INPUT  = 0xBBBBFF # red
COLOR_STATIC        = 0xCCFFFF # yellow

def isAlmostEqual(data1, data2):
    if not data1 and not data2: return True
    if data1 == data2: return True

    if data1 and data2:
        if data1.find(data2) >= 0: return True
        if data2.find(data1) >= 0: return True

    return False

def isJcc(ins):
    if ins and ins.find("j") == 0: return True
    return False

def isCall(ins):
    if ins and ins in ["call"]: return True
    return False

def isRet(ins):
    if ins and ins in ["ret"]: return True
    return False

def isNop(ins):
    if ins and ins in ["nop"]: return True
    return False

def getComment(pc):
    comment = idaapi.get_cmt(pc, False)
    comment = comment if comment else ""
    return comment

def setComment(pc, comment):
    idaapi.set_cmt(pc, comment, False)

def setColor(pc, color):
    idc.set_color(pc, idc.CIC_ITEM, color)

def UnsignedToSigned(line):
    match = re.search(r":(ffffffffffff[0-9a-fA-F]{4})}", line)
    if match:
        val = "-" + hex(0x10000000000000000 - int(match.group(1), 16))[2:]
        line = re.sub(r":(ffffffffffff[0-9a-fA-F]{4})}", ":" + val + "}", line)

    match = re.search(r":(ffff[0-9a-fA-F]{4})}", line)
    if match:
        val = "-" + hex(0x100000000 - int(match.group(1), 16))[2:]
        line = re.sub(r":(ffff[0-9a-fA-F]{4})}", ":" + val + "}", line)

    return line

def getInst(line):
    match = re.search(r"\|([0-9a-fA-F]*)\|([\s\S]*)\|", line)

    if not match:
        return None, None

    pc = int(match.group(1), 16)
    disas = match.group(2)
    ins = disas[:disas.find(" ")]

    return pc, ins

def getValue(line):
    match = re.search(r"{([\S]*)}<={([\S]*)}", line)

    if not match:
        return None, None

    dst = match.group(1)
    src = match.group(2)

    return src, dst

def genNewComment(pc, ins, src, dst, eaCountMaps):
    def matchInsForSrc(ins):
        if ins and ins in ["push", "cmp", "test"]: return True
        return False

    def matchInsForDst(ins):
        if ins in ["lea", "add", "sub", "pop"]: return True
        if ins in ["and", "or", "xor"]: return True
        if ins.find("sh") == 0: return True
        if ins.find("ro") == 0: return True
        if ins.find("mov") == 0: return True
        return False

    if not isJcc(ins):
        if eaCountMaps[pc] == MAX_LOOP_COUNT + 1:
            return "..."

        if eaCountMaps[pc] > MAX_LOOP_COUNT + 1:
            return ""

    if matchInsForDst(ins): return f"{{{dst}}}"
    if matchInsForSrc(ins): return f"{{{src}}}"
    if isJcc(ins): return ""
    if isCall(ins): return f"\n{{{src}}}"
    if isRet(ins): return ""
    if isNop(ins): return ""

    return f"{{{dst}}}<={{{src}}}"

def readTraceLog(filename, readIndex):
    global dynamicInfoMaps
    global jccMaps

    if readIndex not in [0, 1, 2]:
        return False

    def initLine(line):
        line = line.strip().replace("_", ":")
        line = UnsignedToSigned(line)
        return line

    eaCountMaps = {}
    (prev_pc, prev_ins) = (None, None)

    for line in open(filename):
        line = initLine(line)

        pc, ins = getInst(line)
        src, dst = getValue(line)

        if not pc:
            continue

        if pc not in eaToDynamicInfo:
            eaToDynamicInfo[pc] = ["", "", ""]

        eaCountMaps[pc] = eaCountMaps.setdefault(pc, 0) + 1
        eaToDynamicInfo[pc][readIndex] += genNewComment(pc, ins, src, dst, eaCountMaps)

        if isJcc(ins):
            jccMaps[pc] = True

        if isJcc(prev_ins):
            if f"->{pc:X} " not in eaToDynamicInfo[prev_pc][readIndex]:
                eaToDynamicInfo[prev_pc][readIndex] += f"->{pc:X} "

        (prev_pc, prev_ins) = (pc, ins)

def updateComment():
    global eaToDynamicInfo

    for pc, comments in eaToDynamicInfo.items():
        if comments[0]:
            setComment(pc, comments[0])
            setColor(pc, COLOR_DEFAULT)

        if comments[0].find("->") >= 0 or comments[1].find("->") >= 0 or comments[2].find("->") >= 0:
            cmt = re.findall("(->[0-9a-fA-F]+)", comments[0])
            cmt += re.findall("(->[0-9a-fA-F]+)", comments[1])
            cmt += re.findall("(->[0-9a-fA-F]+)", comments[2])
            setComment(pc, " ".join(list(set(cmt))))

        if sum([1 if x else 0 for x in comments]) == 1:
            setColor(pc, COLOR_DEFAULT)
            continue

        if isAlmostEqual(comments[0], comments[1]):
            if isAlmostEqual(comments[0], comments[2]):
                setColor(pc, COLOR_STATIC)
            else:
                setColor(pc, COLOR_DEPEND_INPUT)
                setComment(pc, "*" + getComment(pc))

def patch(ea):
    origBytes = idc.ida_bytes.get_bytes(ea, 8)
    comment = getComment(ea)

    instStart = idc.ida_bytes.get_item_head(ea)
    instSize = idc.ida_bytes.get_item_size(instStart)

    if comment and comment.count("->") != 1:
        return

    if not comment:
        return

    def isShortJmp(bytes):
        shortJmpList = [struct.pack("B", x) for x in range(0x70, 0x80)]
        return bytes[0:1] in shortJmpList

    def isJmp(bytes):
        jmpList = [b"\x0F" + struct.pack("B", x) for x in range(0x80, 0x90)]
        return bytes[0:2] in jmpList

    if hex(ea + instSize)[2:].upper() in comment:
        if isShortJmp(origBytes):
            patchSize = 2
            patchData = b"\x90\x90"
        elif isJmp(origBytes):
            patchSize = 6
            patchData = b"\x90"*6
        else:
            return

    else:
        if isShortJmp(origBytes):
            patchSize = 1
            patchData = b"\xEB"
        elif isJmp(origBytes):
            patchSize = 2
            patchData = b"\x90\xE9"
        else:
            return

    nextAddr = ea + patchSize
    instStart = idc.ida_bytes.get_item_head(nextAddr)

    if idc.ida_bytes.is_code(idc.ida_bytes.get_flags(instStart)):
        if instStart < nextAddr:
            instSize = idc.ida_bytes.get_item_size(instStart)
            fillSize = (instStart + instSize) - nextAddr
            idc.ida_auto.auto_make_code(nextAddr)

    idc.ida_bytes.patch_bytes(ea, patchData)
    idc.ida_auto.auto_mark_range(ea, ea + patchSize, idc.ida_auto.AU_USED)

class MyForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        idaapi.Form.__init__(self, r"""
Select 3 pintr trace log files:
 -  Input of the second trace should be the same as the first
 -  Input of the third trace should be the different from the first

<#Select a file to open#Log file 1:{traceLog1}>
<#Select a file to open#Log file 2:{traceLog2}>
<#Select a file to open#Log file 3:{traceLog3}>
""", {
            'traceLog1': idaapi.Form.FileInput(open=True),
            'traceLog2': idaapi.Form.FileInput(open=True),
            'traceLog3': idaapi.Form.FileInput(open=True),
        })

eaToDynamicInfo = {}
jccMaps = {}

def main():
    global f

    f = MyForm()
    f.Compile()

    f.traceLog1.value = "*.log"
    f.traceLog2.value = "*.log"
    f.traceLog3.value = "*.log"

    if f.Execute() == 1:
        traceLog1 = f.traceLog1.value
        traceLog2 = f.traceLog2.value
        traceLog3 = f.traceLog3.value

        print(f"Trace Log 1: {traceLog1}")
        print(f"Trace Log 2: {traceLog2}")
        print(f"Trace Log 3: {traceLog3}")

    f.Free()

    readTraceLog(traceLog1, 0)
    readTraceLog(traceLog2, 1)
    readTraceLog(traceLog3, 2)

    updateComment()

    for ea in jccMaps.keys():
        patch(ea)

    print("Finished")

class pintr_ida(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "Pintr to IDA"
    wanted_hotkey = ""

    def init(self):
        global pintr_ida_init

        if "pintr_ida_init" not in globals():
            print("Pintr to IDA v{} (c) Hiroki Hada".format(PINTRIDA_VERSION))

        pintr_ida_init = True

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        main()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return pintr_ida()




