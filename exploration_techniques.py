import angr
import functools
import logging
import pyvex
from utils import *


class AntiLoop(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, max_count=10):
        self.max_count = max_count
        self.counts = dict()
        self.logger = logging.getLogger("AntiLoop")

    def detect_cycle(self, sequence):
        if len(sequence) < 10:
            return None
        hare = 0
        for i, e in enumerate(sequence[3:]):
            if sequence[0] == e:
                hare = i + 3
                break
        if hare == 0:
            return None
        seq1 = sequence[:hare]
        seq2 = sequence[hare:]
        if len(seq1) > len(seq2):
            return None
        for a, b in zip(seq1, seq2):
            if a != b:
                return None
        return len(seq1)

    def step(self, sm, stash="active", **kwargs):
        for state in sm.stashes[stash]:
            addrs = state.history.bbl_addrs.hardcopy[::-1]
            lam = self.detect_cycle(addrs)
            if lam is not None:
                self.logger.warning(f"Dropping cycle {[hex(x) for i, x in enumerate(addrs) if i <= lam * 2]}")
                sm.drop(stash=stash, filter_func=lambda s: s.addr == state.addr)
        sm = sm.step(stash, **kwargs)
        return sm


class UnboundConditions(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, angr_proj):
        super(UnboundConditions, self).__init__()
        self.p = angr_proj
        self.logger = logging.getLogger("UnboundConditions")

    def current_insn(self, state):
        return self.insn_at_addr(state, state.inspect.instruction)

    def insn_at_addr(self, state, addr):
        insn = [i for i in state.block().capstone.insns if i.address == addr][0]
        return f"{addr:x}: {pretty_insn(insn)}"

    def find_exit_guards(self, state):
        banned = state.globals.get("nohook", set())
        for addr, ind, stmt in state.block().vex.exit_statements:
            if addr in banned:
                continue
            self.logger.debug(f"Found {self.insn_at_addr(state, addr)}")
            yield stmt.guard.tmp

    def expr_ite_fake_cond(self, state):
        expr = state.inspect.expr
        if isinstance(expr, pyvex.expr.ITE):
            banned = state.globals.get("nohook", set())
            if state.inspect.instruction in banned:
                return
            cond = state.solver.BVS('fake_cond', 1) != state.solver.BVV(0, 1)
            val = state.solver.If(cond, state.solver.BVV(1, 1), state.solver.BVV(0, 1))
            self.logger.debug(f"expr_ite_fake_cond triggered at {self.current_insn(state)}")
            state.scratch.store_tmp(expr.cond.tmp, val)

    def tmp_write_fake_cond(self, state):
        self.logger.debug(f"tmp_write_fake_cond triggered at {self.current_insn(state)}")
        if state.inspect.statement < len(state.block().vex.statements):
            state.block().vex.statements[state.inspect.statement].pp()
        cond = state.solver.BVS('fake_cond', 1)
        state.inspect.tmp_write_expr = cond

    def oneshot_bp(self, state, event_type, action, *args, **kwargs):
        def wrapper(state, action, bp, event_type):
            action(state)
            state.inspect.remove_breakpoint(event_type, bp)

        bp = state.inspect.b(event_type, *args, **kwargs)
        bp.action = functools.partial(wrapper, action=action, bp=bp, event_type=event_type)

    def step(self, sm, stash="active", **kwargs):
        for state in sm.stashes[stash]:
            state.inspect.__init__()
            state.inspect.b("expr", action=self.expr_ite_fake_cond, when=angr.BP_BEFORE)
            for tmp in self.find_exit_guards(state):
                self.oneshot_bp(state, "tmp_write", self.tmp_write_fake_cond, when=angr.BP_BEFORE, tmp_write_num=tmp)

        self.logger.debug("Stepping...")
        sm = sm.step(stash, **kwargs)
        self.logger.debug("Stepping complete")
        return sm
