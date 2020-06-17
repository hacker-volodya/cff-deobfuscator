import bisect
import capstone


class RangeKeyDict:
    def __init__(self):
        self._keys = []
        self._vals = []

    def put(self, start, end, val):
        i = bisect.bisect(self._keys, start)
        self._keys.insert(i, end)
        self._keys.insert(i, start)
        self._vals.insert(i // 2, val)

    def get(self, needle):  # start <= needle < end
        i = bisect.bisect(self._keys, needle)
        if i & 1 == 0:  # if needle is between ranges
            return None
        start = self._keys[i - 1]
        end = self._keys[i]
        val = self._vals[i // 2]
        return start, end, val


def cc_str(insn):
    consts = filter(lambda x: x.startswith("ARM64_CC_"), dir(capstone.arm64_const))
    cc_tbl = {getattr(capstone.arm64_const, c): c.strip("ARM64_CC_").lower() for c in consts}
    return cc_tbl[insn.cc]


def pretty_insn(insn):
    return f"{insn.insn_name()} {insn.op_str}"
