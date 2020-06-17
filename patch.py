from keystone import *
import logging
import struct


class PatchManager:
    def __init__(self, angr_proj=None, offset=0x400000, new_seg=0x450000, arch=KS_ARCH_ARM64,
                 mode=KS_MODE_LITTLE_ENDIAN):
        self.ks = Ks(arch, mode)
        self.patches = dict()
        self.new_code = bytearray()
        self.new_addr = new_seg
        self.p = angr_proj
        self.logger = logging.getLogger("Patcher")
        self.offset = offset

    def assemble(self, code):
        try:
            return bytearray(self.ks.asm(code)[0])
        except keystone.KsError as e:
            raise Exception(f"Problem occured when assembling code:\n{code}") from e

    def patch(self, addr, code):
        if self.p is not None:
            insn = self.p.factory.block(addr).capstone.insns[0]
            self.logger.debug(f"{addr:x}: {insn.insn_name()} {insn.op_str} ---> {code}")
        else:
            self.logger.debug(f"{addr:x}: ---> {code}")
        if self.patches.get(addr) is not None:
            self.logger.warning(f"{addr:x} was already patched (bug?)")
        self.patches[addr] = code

    def write_new(self, code):  # race condition warning!
        addr = self.new_addr + len(self.new_code)
        self.new_code.extend(self.assemble(code(addr)))
        return addr

    def assemble_patches(self):
        return [(k - self.offset, struct.unpack("<I", self.assemble(v))[0]) for k, v in self.patches.items()] + [
            (self.new_addr - self.offset + i * 4, e) for i, e in
            enumerate(struct.unpack(f"<{len(self.new_code) // 4}I", self.new_code))]
