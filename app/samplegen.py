"""Deterministic synthetic ``.eh_frame`` sections for tests and the demo.

Everything is little-endian 32-bit DWARF with CIE version 1 and
absolute 32-bit CIE pointers — the exact dialect the analyzer accepts.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

# Opcodes (kept local so this module has no parser coupling).
ADV = 0x40
NOP = 0x00
ADV1 = 0x02
ADV2 = 0x03
ADV4 = 0x04
OFF_EXT = 0x05
RES_EXT = 0x06
UNDEF = 0x07
SAME = 0x08
REG = 0x09
REMEMBER = 0x0A
RESTORE = 0x0B
DEF_CFA = 0x0C
DEF_CFA_REG = 0x0D
DEF_CFA_OFF = 0x0E

RAX, RDX, RCX, RBX, RSI, RDI, RBP, RSP = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
RIP = 16


def uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = v & 0x7F
        v >>= 7
        sign = b & 0x40
        if (v == 0 and not sign) or (v == -1 and sign):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def _record(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body


def cie(initial: bytes, ra: int = RIP, code_align: int = 1,
        data_align: int = -8, augmentation: bytes = b"") -> bytes:
    body = struct.pack("<I", 0)  # CIE marker
    body += bytes([1])           # version 1
    body += augmentation + b"\x00"
    body += uleb(code_align) + sleb(data_align) + bytes([ra])
    body += initial
    return _record(body)


def fde(cie_offset: int, initial_location: int, address_range: int,
        insns: bytes) -> bytes:
    body = struct.pack("<I", cie_offset)  # absolute 32-bit CIE pointer
    body += struct.pack("<II", initial_location, address_range)
    body += insns
    return _record(body)


# ---------------------------------------------------------------------------
# Main demo / verification section
# ---------------------------------------------------------------------------

# FDE rows (code alignment 1, so the deltas are byte addresses):
#   loc 0: CIE initial -> CFA=rsp+8; rip=[CFA-8]; rbp=[CFA-16]
#   loc 1: def_cfa_offset 16; rbx=[CFA-24]
#   loc 2: remember; r12 same; r13 undefined; r14=register(r15);
#          def_cfa_register rbp        (CFA=rbp+16)
#   loc 3: restore_state  -> later PC falls back to the saved rules
#   loc 4: def_cfa_offset 24
def main_section() -> Tuple[bytes, dict]:
    init = bytes([
        DEF_CFA]) + uleb(RSP) + uleb(8) + bytes([
        0x80 | RIP]) + uleb(1) + bytes([
        0x80 | RBP]) + uleb(2)

    insns = b"".join([
        bytes([ADV | 1]),
        bytes([DEF_CFA_OFF]) + uleb(16),
        bytes([0x80 | RBX]) + uleb(3),
        bytes([ADV | 1]),
        bytes([REMEMBER]),
        bytes([SAME]) + uleb(R12),
        bytes([UNDEF]) + uleb(R13),
        bytes([REG]) + uleb(R14) + uleb(R15),
        bytes([DEF_CFA_REG]) + uleb(RBP),
        bytes([ADV | 1]),
        bytes([RESTORE]),
        bytes([ADV | 1]),
        bytes([DEF_CFA_OFF]) + uleb(24),
    ])
    c = cie(init)
    f = fde(0, 0x401000, 0x30, insns)
    data = c + f

    inputs = {
        # PC at loc 2: rewritten rules visible (CFA=rbp+16 etc.)
        "pc_rewritten": 0x401002,
        # PC at loc 3: evidence must be the restored snapshot
        # (CFA back to rsp+16, r12/r13/r14 rules gone).
        "pc_restored": 0x401003,
        "pc_miss": 0x402000,
        "registers_text": (
            "rsp=0x1000\nrbp=0x2000\nr12=0x222\nr15=0x444\nrbx=0x9\n"),
        "memory_text": (
            # loc-3 (restored) CFA = 0x1000+16 = 0x1010
            "0x1008=0x50000\n"   # rip [CFA-8]  -> caller PC at loc 3
            "0x1000=0x2000\n"    # rbp [CFA-16]
            "0xff8=0x333\n"      # rbx [CFA-24]
            # loc-2 (rewritten) CFA = 0x2000+16 = 0x2010
            "0x2008=0x50001\n"   # caller PC at loc 2
            "0x2000=0x1f00\n"    # rbp [CFA-16]
            "0x1ff8=0x334\n"     # rbx [CFA-24]
        ),
    }
    return data, inputs


# ---------------------------------------------------------------------------
# Nested remember/restore section
# ---------------------------------------------------------------------------

def nested_section() -> bytes:
    """Two nested snapshots with rule rewrites between them."""
    init = (bytes([DEF_CFA]) + uleb(RSP) + uleb(8)
            + bytes([0x80 | RIP]) + uleb(1))
    insns = b"".join([
        bytes([ADV | 1]),
        bytes([REMEMBER]),
        bytes([SAME]) + uleb(R12),           # A: r12 same
        bytes([ADV | 1]),
        bytes([REMEMBER]),
        bytes([UNDEF]) + uleb(R13),          # B: r13 undefined
        bytes([ADV | 1]),
        bytes([RESTORE]),                    # drop B, keep A
        bytes([ADV | 1]),
        bytes([RESTORE]),                    # drop A too
    ])
    return cie(init) + fde(0, 0x500000, 0x10, insns)


# ---------------------------------------------------------------------------
# Failure fixtures (each parser/reducer must reject with an offset)
# ---------------------------------------------------------------------------

def truncated_fde_section() -> bytes:
    """FDE length word promises more bytes than the section contains."""
    init = (bytes([DEF_CFA]) + uleb(RSP) + uleb(8)
            + bytes([0x80 | RIP]) + uleb(1))
    c = cie(init)
    f = fde(0, 0x600000, 0x10, bytes([ADV | 1]) + b"\x0e\x10")
    return c + f[:-3]  # chop the tail -> length overruns section


def dangling_cie_section() -> bytes:
    """FDE absolute pointer refers to a non-existent CIE offset."""
    init = (bytes([DEF_CFA]) + uleb(RSP) + uleb(8)
            + bytes([0x80 | RIP]) + uleb(1))
    c = cie(init)
    f = fde(0xDEAD, 0x700000, 0x10, bytes([ADV | 1]))
    return c + f


def truncated_uleb_section() -> bytes:
    """A high-bit ULEB128 runs into the record boundary."""
    # CIE: def_cfa with a register LEB that never terminates.
    body = struct.pack("<I", 0) + bytes([1]) + b"\x00"
    body += bytes([0x81, 0x80])  # code_align ULEB truncated start...
    # Ensure code_align itself is the truncated one: version,aug, then
    # the dangling LEB.
    return _record(body)


def truncated_sleb_section() -> bytes:
    """CIE data-alignment SLEB128 truncated at the record end."""
    body = struct.pack("<I", 0) + bytes([1]) + b"\x00"
    body += uleb(1)
    body += bytes([0x78 | 0x80])  # SLEB continuation, never finished
    return _record(body)


def stack_underflow_section() -> bytes:
    """restore_state with no matching remember_state."""
    init = (bytes([DEF_CFA]) + uleb(RSP) + uleb(8)
            + bytes([0x80 | RIP]) + uleb(1))
    insns = bytes([ADV | 1]) + bytes([RESTORE])
    return cie(init) + fde(0, 0x800000, 0x10, insns)


def unsupported_version_section() -> bytes:
    body = struct.pack("<I", 0) + bytes([3]) + b"\x00"
    body += uleb(1) + sleb(-8) + bytes([RIP])
    return _record(body)


def all_failure_sections() -> List[Tuple[str, bytes]]:
    return [
        ("truncated_fde", truncated_fde_section()),
        ("dangling_cie", dangling_cie_section()),
        ("truncated_uleb", truncated_uleb_section()),
        ("truncated_sleb", truncated_sleb_section()),
        ("stack_underflow", stack_underflow_section()),
        ("unsupported_version", unsupported_version_section()),
    ]


# ---------------------------------------------------------------------------
# Continuous-unwind fixtures (rbp-chained call stacks)
# ---------------------------------------------------------------------------

def _chain_cie() -> bytes:
    # CFA=rsp+8; rip=[CFA-8]; rbp=[CFA-16].
    init = (bytes([DEF_CFA]) + uleb(RSP) + uleb(8)
            + bytes([0x80 | RIP]) + uleb(1)
            + bytes([0x80 | RBP]) + uleb(2))
    return cie(init)


def _rbp_frame_insns(extra: bytes = b"") -> bytes:
    """loc>=1: CFA=rbp+16 — classic frame-pointer chain (saved rbp at
    [rbp], return address at [rbp+8]).  Every frame then recovers rbp
    and rip, which are exactly the inputs the next frame needs."""
    return (bytes([ADV | 1])
            + bytes([DEF_CFA_REG]) + uleb(RBP)
            + bytes([DEF_CFA_OFF]) + uleb(16)
            + extra)


def chain_section() -> Tuple[bytes, dict]:
    """Three rbp-chained frames; the outermost caller PC hits no FDE."""
    insns = _rbp_frame_insns()
    data = (_chain_cie()
            + fde(0, 0x401000, 0x40, insns)   # innermost
            + fde(0, 0x402000, 0x40, insns)   # middle
            + fde(0, 0x403000, 0x40, insns))  # outermost
    inputs = {
        "pc": 0x401001,
        "registers_text": "rbp=0x9000",
        "memory_text": (
            "0x9000=0x8000\n"    # [rbp]   saved rbp   -> frame 1 rbp
            "0x9008=0x402005\n"  # [rbp+8] return addr -> frame 1 PC
            "0x8000=0x7000\n"
            "0x8008=0x403003\n"  # -> frame 2 PC
            "0x7000=0x0\n"
            "0x7008=0x4fffff\n"  # outermost caller PC: misses every FDE
        ),
    }
    return data, inputs


def loop_section() -> Tuple[bytes, dict]:
    """One function whose unwind state alternates and then repeats."""
    data = _chain_cie() + fde(0, 0x404000, 0x40, _rbp_frame_insns())
    inputs = {
        "pc": 0x404001,
        "registers_text": "rbp=0x6000",
        "memory_text": (
            "0x6000=0x5000\n"
            "0x6008=0x404005\n"  # frame 1: PC=0x404005, rbp=0x5000
            "0x5000=0x6000\n"
            "0x5008=0x404001\n"  # frame 2+ states recur -> loop
        ),
    }
    return data, inputs


def spin_section() -> Tuple[bytes, dict]:
    """Caller PC equals the frame's own PC: unwinding makes no progress."""
    data = _chain_cie() + fde(0, 0x405000, 0x40, _rbp_frame_insns())
    inputs = {
        "pc": 0x405001,
        "registers_text": "rbp=0x4000",
        "memory_text": (
            "0x4000=0x3000\n"
            "0x4008=0x405001\n"  # caller PC == current PC
        ),
    }
    return data, inputs


def broken_chain_section() -> Tuple[bytes, dict]:
    """Frame 1 marks the return-address column undefined: the caller PC
    becomes unrecoverable *after* frame 0, so the whole chain must be
    discarded with the failing frame located."""
    inner = fde(0, 0x401000, 0x40, _rbp_frame_insns())
    broken = fde(0, 0x402000, 0x40,
                 _rbp_frame_insns(bytes([UNDEF]) + uleb(RIP)))
    data = _chain_cie() + inner + broken
    inputs = {
        "pc": 0x401001,
        "registers_text": "rbp=0x9000",
        "memory_text": (
            "0x9000=0x8000\n"
            "0x9008=0x402005\n"  # frame 1 PC lands in the broken FDE
        ),
    }
    return data, inputs
