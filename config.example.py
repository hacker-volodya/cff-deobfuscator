import re

LIB_PATH = "../lib/jni/arm64-v8a/libnative.so"


def detect_ascb(state):
    b = state.block()
    pattern = re.compile(
        "and w\d{1,2}, (w\d{1,2}), #(?:0x)?[a-f0-9]+\n"
        "sub w\d{1,2}, w\d{1,2}, #(?:0x)?[a-f0-9]+\n"
        "cmp w\d{1,2}, #3\n"
        "b #0x[a-f0-9]+$"
    )
    asm = "\n".join([x.insn_name() + " " + x.op_str for x in b.capstone.insns])
    result = re.findall(pattern, asm)
    if len(result) != 1:
        return None
    b2 = state.project.factory.block(b.addr + b.size)
    return b.capstone.insns[-4].address, b2.capstone.insns[-1].address, result[0]


PATTERNS = [detect_ascb]
