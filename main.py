#!/usr/bin/env python3

import angr
import sys
import functools
import itertools

from config import *
from patch import PatchManager
from exploration_techniques import UnboundConditions, AntiLoop
from utils import RangeKeyDict, cc_str


class Successor:
    def __init__(self, dispatcher_state, controls, dispatchers):
        self.dispatcher_state = dispatcher_state
        self.controls = controls
        self.dispatchers = dispatchers
        self._target_addr = None

    def get_id(self):
        return frozenset(self.controls.items())

    def get_target(self, loop_count=None):
        if self._target_addr is None or loop_count is not None:
            sm = self.dispatcher_state.project.factory.simgr(self.dispatcher_state.copy())
            sm.one_active.inspect.__init__()
            solver = sm.one_active.solver
            for control_reg, block_id in self.controls.items():
                block_id_bvv = solver.BVV(block_id, 32)
                setattr(sm.one_active.regs, control_reg, block_id_bvv)
            while self.dispatchers.get(sm.one_active.addr) is not None:
                start, end, _ = self.dispatchers.get(sm.one_active.addr)
                sm.run(until=lambda lsm: not (start <= lsm.one_active.addr < end))
                if loop_count is not None:
                    loop_count -= 1
                    if loop_count == 0:
                        return sm.one_active.addr
            self._target_addr = sm.one_active.addr
        return self._target_addr

    def __format__(self, formatstr):
        controls = ", ".join(f"{reg}:{val:x}" for reg, val in self.controls.items())
        return f"{controls} --> {self.get_target():x} (through {self.dispatcher_state.addr:x})"


def deobfuscate_function(p, addr, funcs=None):
    if funcs is None:
        funcs = []
    funcs = [a for a in funcs if a != addr]  # filter out current function

    state0 = p.factory.blank_state(
        addr=addr,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.CALLLESS,
        },
    )

    pm = PatchManager(p, new_seg=0x50000 + addr)
    jumpmap = dict()
    visited_blocks = list()
    dispatchers = RangeKeyDict()
    sm = p.factory.simgr(state0)
    sm.use_technique(UnboundConditions(p))
    sm.use_technique(AntiLoop())
    step_func = lambda lsm: stepper(lsm, jumpmap, dispatchers, funcs, visited_blocks)

    def until_func(lsm):
        lsm.move(from_stash="unconstrained", to_stash="active", filter_func=lambda s: s.regs.ip.concrete)
        return len(lsm.active) == 0

    sm.run(step_func=step_func, until=until_func)
    p._sim_procedures = {}

    # dispatcher-dispatcher merging
    for predecessor_last_addr, successors in list(jumpmap.items()):
        if dispatchers.get(predecessor_last_addr) is not None:
            start, _, _ = dispatchers.get(predecessor_last_addr)
            if predecessor_last_addr != start:
                del jumpmap[predecessor_last_addr]
                continue
        tmp_successors = [(successor_id, successor, 1) for successor_id, successor in successors.items()]
        for successor_id, successor, loop_count in tmp_successors:
            successor_addr = successor.get_target(loop_count=loop_count)
            if dispatchers.get(successor_addr) is not None:  # successor is the second dispatcher
                start, end, _ = dispatchers.get(successor.dispatcher_state.addr)
                print(
                    f"Predecessor {predecessor_last_addr:x} jumps to dispatcher {successor_addr:x} through dispatcher {start:x}")
                del successors[successor_id]
                next_dispatcher_successors = itertools.chain.from_iterable(
                    [jumpmap.get(i, {}).values() for i in range(start + 4, end + 4, 4)])
                for next_successor in next_dispatcher_successors:
                    new_successor = Successor(successor.dispatcher_state,
                                              {**next_successor.controls, **successor.controls}, dispatchers)
                    tmp_successors.append((new_successor.get_id(), new_successor, loop_count + 1))
                    successors[new_successor.get_id()] = new_successor

    print("JUMPMAP:")
    for predecessor_last_addr, successors in jumpmap.items():
        print(f"Predecessor {predecessor_last_addr:x}")
        for successor in successors.values():
            print(f"-- {successor}")
    if sm.errored:
        print("ERROR OCCURED WHILE STEPPING: ", sm.errored)
        raise Exception(str(sm.errored))
    generate_patches(pm, jumpmap)
    return pm.assemble_patches(), visited_blocks


def gen_transition_logic(addr, successors):
    code = ""
    counter = 0

    # analyze controls
    sub_values = {reg: None for successor in successors[:-1] for reg, val in successor.controls.items()}
    for successor in successors[:-1]:
        for reg, val in successor.controls.items():
            if sub_values[reg] is None or val < sub_values[reg]:
                sub_values[reg] = val

    # sub controls
    for reg, sub_val in sub_values.items():
        if sub_val > 0xffffff:
            code += f"and {reg}, {reg}, #0xffffff\n"
            counter += 1
        code += f"sub {reg}, {reg}, #{sub_val & 4095}\n"
        counter += 1
        if sub_val > 4095:
            code += f"sub {reg}, {reg}, #{(sub_val >> 12) & 4095}, lsl #12\n"
            counter += 1

    for successor in successors[:-1]:
        controls = list(successor.controls.items())
        control_reg, block_id = controls[0]
        if block_id - sub_values[control_reg] > 4095:
            raise Exception("Too big block_id")
        code += f"cmp {control_reg}, #{block_id - sub_values[control_reg]}\n"
        counter += 1
        for control_reg, block_id in controls[1:]:
            if block_id - sub_values[control_reg] > 31:
                raise Exception("Too big block_id")
            code += f"ccmp {control_reg}, #{block_id - sub_values[control_reg]}, #0, eq\n"
            counter += 1
        code += f"b.eq #{successor.get_target() - (addr + counter * 4)}\n"
        counter += 1
    code += f"b #{successors[-1].get_target() - addr}\n"
    counter += 1
    return code


# connects all predecessors with successors using jumpmap
# if predecessor maps to multiple successors, it will generate some logic to jump conditionally
def generate_patches(pm, jumpmap):
    for predecessor_last_addr, successors in jumpmap.items():
        if not successors:
            raise Exception(f"Predecessor {predecessor_last_addr:x} doesn't jump to any successors")
        targets = set(head.get_target() for head in successors.values())
        successors = list(successors.values())
        last_successor = successors[-1]
        predecessor_insn = pm.p.factory.block(predecessor_last_addr).capstone.insns[0]
        branch_code = lambda addr: f"b #{addr - predecessor_last_addr}"
        if predecessor_insn.insn_name() in ["cbz", "cbnz"]:
            branch_code = lambda \
                    addr: f"{predecessor_insn.insn_name()} {predecessor_insn.reg_name(predecessor_insn.operands[0].reg)}, #{addr - predecessor_last_addr}"
        elif predecessor_insn.insn_name() == "b":
            cc = "." + cc_str(predecessor_insn)
            if cc == ".invalid":
                cc = ""
            branch_code = lambda addr: f"b{cc} #{addr - predecessor_last_addr}"
        if len(targets) == 1:
            pm.patch(predecessor_last_addr, branch_code(last_successor.get_target()))
        else:
            logic = pm.write_new(functools.partial(gen_transition_logic, successors=successors))
            pm.patch(predecessor_last_addr, branch_code(logic))


# tracks access to dispatcher and save data to jumpmap
def dispatcher_hook(state, control_reg, jumpmap, dispatchers):
    safe_state = state.copy()
    block_ids = safe_state.solver.eval_upto(getattr(state.regs, control_reg), 10)
    predecessor_block = state.project.factory.block(state.history.parent.addr)
    predecessor_end = predecessor_block.capstone.insns[-1].address

    print(f"<< Hook at {state.addr:x}")

    if predecessor_end + 4 == state.addr and dispatchers.get(predecessor_end) is None:  # nobranch
        patch_addr = state.addr
    else:
        patch_addr = predecessor_end

    if jumpmap.get(patch_addr) is None:
        jumpmap[patch_addr] = dict()
    updated = False
    for block_id in block_ids:
        successor = Successor(state, {control_reg: block_id}, dispatchers)
        if jumpmap[patch_addr].get(successor.get_id()) is None:
            updated = True
            jumpmap[patch_addr][successor.get_id()] = successor
    if not updated:
        state.solver.add(state.solver.false)
        print(f">> Dropping {state.addr:x}")
        return

    print(f"From predecessor which ends at {predecessor_end:x} (will be patched at {patch_addr:x}):")
    predecessor_block.pp()
    print(f"Reached dispatcher at {state.addr:x}:")
    state.block().pp()
    print(f"Block ids are {block_ids}")
    print()


# main analyzer func, called before stepping each active state
def stepper(sm, jumpmap, dispatchers, funcs, visited_blocks):
    print(f"ACTIVE: {[hex(x.addr) for x in sm.active]}")

    for state in sm.active:
        if state.addr in funcs:
            sm.drop(lambda s: s.addr == state.addr)  # split functions from each other

        visited_blocks.append((state.addr, state.addr + state.block().size))

        dispatcher_data = [detect_func(state) for detect_func in PATTERNS]
        dispatcher_data = [[x] if type(x) is tuple else x for x in dispatcher_data if x is not None]
        if not any(dispatcher_data):
            continue
        if len(dispatcher_data) > 1:
            raise Exception(f"Detected too many patterns: {list(map(lambda f: f(state), PATTERNS))}")

        for start, end, control_reg in dispatcher_data[0]:
            if state.project.is_hooked(start):
                continue
            print(f"NEW DISPATCHER: from {start:x} to {end:x} with control_reg={control_reg}")
            if state.globals.get("nohook") is None:
                state.globals["nohook"] = set()
            state.globals["nohook"].update({i for i in range(start, end + 4, 4)})
            dispatchers.put(start, end + 4, None)
            state.project.hook(start, functools.partial(dispatcher_hook, control_reg=control_reg, jumpmap=jumpmap,
                                                        dispatchers=dispatchers))

    return sm


if __name__ == "__main__":
    p = angr.Project(LIB_PATH, auto_load_libs=False)
    offset = p.loader.main_object.mapped_base
    if len(sys.argv) not in [2, 3]:
        print(f"Usage: {sys.argv[0]} <addr> [address_to_avoid], for example {sys.argv[0]} b96c")
        sys.exit(1)
    func = offset + int(sys.argv[1], 16)
    funcs = [func]
    if len(sys.argv) > 2:
        funcs.append(offset + int(sys.argv[2], 16))
    patches, visited_blocks = deobfuscate_function(p, func, funcs)
    print("Patches:")
    print([func - offset, patches])
    print()
    print("Visited blocks:")
    print([func - offset, [(start - offset, end - offset) for start, end in visited_blocks]])
