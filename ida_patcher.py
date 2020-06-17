from __future__ import print_function
from idaapi import *
from idc import *


def hl(visited_blocks):
    func, blocks = visited_blocks
    func = get_func(func)
    fc = FlowChart(func, flags=FC_PREDS)
    for block in fc:
        for addr in range(block.startEA, block.endEA, 4):
            SetColor(addr, CIC_ITEM, 0xffffff)
    for start, end in blocks:
        for addr in range(start, end, 4):
            SetColor(addr, CIC_ITEM, 0x00ff00)


def redefine(func):
    del_func(func)
    MakeFunction(func)


def redefine_cb(func):
    redefine(func)
    return -1


def p(patches):
    func = patches[0]
    for addr, value in patches[1]:
        patch_dword(addr, value)
    f = get_func(func)
    start = f.startEA
    end = f.endEA
    register_timer(100, lambda func=start: redefine_cb(func))
    register_timer(200, lambda func=start: redefine_cb(func))


class patched_bytes_visitor(object):
    def __init__(self):
        self.skip = 0
        self.patch = 0

    def __call__(self, ea, fpos, o, v, cnt=()):
        print("Revert %x" % ea)
        revert_byte(ea)
        return 0


def unpatch(func_addr):
    f = get_func(func_addr)
    function_chunks = []
    func_iter = func_tail_iterator_t(f)
    status = func_iter.main()
    while status:
        chunk = func_iter.chunk()
        function_chunks.append((chunk.startEA, chunk.endEA))
        status = func_iter.next()
    for start, end in function_chunks:
        unpatch_range(start, end)
    start, end = f.startEA, f.endEA
    register_timer(100, lambda func=start: redefine_cb(func))
    register_timer(200, lambda func=start: redefine_cb(func))


def unpatch_range(start=0, end=BADADDR):
    v = patched_bytes_visitor()
    r = visit_patched_bytes(start, end, v)
