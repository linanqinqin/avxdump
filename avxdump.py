#!/usr/bin/env python3
"""
avxdump.py: Analyze ELF binaries using pyelftools and Capstone to identify function boundaries with/without AVX usage.

Extracts function symbols, disassembles .text section, maps functions to instructions, and identify all AVX instructions.
Outputs JSON metadata with function information.
Outputs binary metadata with boundaries for sessions free of AVX usage. 
"""

import argparse
import json
import struct
import os
import sys

try:
    import capstone
except ImportError:
    print("[ERROR] capstone not available. Install with: pip install capstone", file=sys.stderr)
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("[ERROR] pyelftools not available. Install with: pip install pyelftools", file=sys.stderr)
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze ELF binary using pyelftools and Capstone",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("binary", help="Path to ELF binary file")
    parser.add_argument("-d", "--dump", type=str, default="", 
                       help="Comma-separated list of outputs to generate: 'func' for funcdump.json")
    return parser.parse_args()


def get_elf_info(elf: ELFFile) -> dict:
    """Extract basic ELF information: class, endianness."""
    info = {
        "class": "32-bit" if elf.elfclass == 32 else "64-bit",
        "endianness": "little" if elf.little_endian else "big",
    }
    return info


def get_text_section(elf: ELFFile) -> tuple:
    """Extract .text section information and static base address.
    
    The static base is taken from the executable PT_LOAD segment's p_vaddr,
    which allows constructing runtime addresses as: runtime_addr = static_addr - static_base + runtime_base
    
    Returns: (section, sh_offset, sh_addr, size, load_base)
    """
    text_sec = elf.get_section_by_name(".text")
    if text_sec is None:
        raise RuntimeError("No .text section found in ELF file")
    
    sh_offset = text_sec["sh_offset"]
    sh_addr = text_sec["sh_addr"]
    size = text_sec["sh_size"]
    
    # Get static base from executable PT_LOAD segment (preferred) for runtime address calculation
    # Look for PT_LOAD segments with PF_X (executable) flag
    exec_bases = []
    for seg in elf.iter_segments():
        p_type = seg["p_type"]
        if p_type != "PT_LOAD":
            continue
        # Check if segment is executable: PF_X == 0x1
        p_flags = int(seg["p_flags"]) if "p_flags" in seg.header else 0
        if p_flags & 0x1:  # PF_X flag set
            exec_bases.append(int(seg["p_vaddr"]))
    
    if not exec_bases:
        raise RuntimeError("No executable PT_LOAD segment found (PF_X flag). Cannot determine static base address.")
    
    # Use minimum p_vaddr from executable PT_LOAD segments as static base
    # This is the ONLY correct way to get the static base for runtime address calculation
    load_base = min(exec_bases)
    
    return text_sec, sh_offset, sh_addr, size, load_base


def collect_function_symbols(elf: ELFFile) -> list:
    """Collect all function symbols from .symtab and .dynsym.
    
    Returns list of dicts with: name, start_addr, size, binding
    """
    functions = []
    seen_addresses = set()  # Avoid duplicates from both .symtab and .dynsym
    
    # Process both .symtab and .dynsym if present
    for sec_name in [".symtab", ".dynsym"]:
        section = elf.get_section_by_name(sec_name)
        if section is None or not isinstance(section, SymbolTableSection):
            continue
        
        for symbol in section.iter_symbols():
            # Only collect STT_FUNC symbols
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            
            start_addr = symbol["st_value"]
            size = symbol["st_size"]
            binding = symbol["st_info"]["bind"]
            # Use .name property which automatically resolves from string table
            name = symbol.name or ""
            
            # Skip if no name or zero address
            if not name or start_addr == 0:
                continue
            
            # Avoid duplicates: prefer the one with a size if available
            if start_addr in seen_addresses:
                # Update if current has size and previous didn't
                existing = next((f for f in functions if f["start_addr"] == start_addr), None)
                if existing and size > 0 and existing["size"] == 0:
                    existing["size"] = size
                    existing["name"] = name
                    existing["binding"] = binding
                continue
            
            seen_addresses.add(start_addr)
            functions.append({
                "name": name,
                "start_addr": start_addr,
                "size": size,
                "binding": binding,
            })
    
    if not functions:
        print("[WARNING] No function symbols found in .symtab or .dynsym", file=sys.stderr)
        print("[WARNING] Binary may be stripped or lack symbol tables", file=sys.stderr)
    
    return functions


def disassemble_text(text_data: bytes, sh_addr: int) -> list:
    """Disassemble the .text section using Capstone.
    
    Returns list of dicts with: address, mnemonic, operands, size
    """
    # Initialize Capstone for x86_64
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    
    instructions = []
    for insn in md.disasm(text_data, sh_addr):
        instructions.append({
            "address": insn.address,
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
            "size": insn.size,
            "groups": insn.groups,
        })
    
    return instructions


def is_simd_instruction(insn) -> bool:
    """Check if an instruction is a SIMD instruction using Capstone groups and fallback catches."""
    simd_groups = {
        capstone.x86.X86_GRP_MMX,
        capstone.x86.X86_GRP_SSE1,
        capstone.x86.X86_GRP_SSE2,
        capstone.x86.X86_GRP_SSE3,
        capstone.x86.X86_GRP_SSE41,
        capstone.x86.X86_GRP_SSE42,
        capstone.x86.X86_GRP_SSE4A,
        capstone.x86.X86_GRP_AVX,
        capstone.x86.X86_GRP_AVX2,
        capstone.x86.X86_GRP_AVX512,
        capstone.x86.X86_GRP_FMA, 
        capstone.x86.X86_GRP_FMA4,
        capstone.x86.X86_GRP_F16C,
        capstone.x86.X86_GRP_XOP, 
    }
    CAPSTONE_MISSING_MNEMONICS_EXACT = {
        # Scalar conversions
        "cvtsi2ss", "cvtsi2sd", "cvtss2sd", "cvtsd2ss",
        "cvtps2pd", "cvtpd2ps",
        "cvtdq2ps", "cvtps2dq", "cvttps2dq",
        "cvtdq2pd", "cvtpd2dq", "cvttpd2dq",
        # Scalar arithmetic & compare
        "addss", "subss", "mulss", "divss", "sqrtss", "minss", "maxss",
        "addsd", "subsd", "mulsd", "divsd", "sqrtsd", "minsd", "maxsd",
        "comiss", "ucomiss", "comisd", "ucomisd",
        "rcpss", "rsqrtss", "roundss", "roundsd",
        # Control / state management
        "ldmxcsr", "stmxcsr",
        "fxsave", "fxrstor",
        "xsave", "xsaveopt", "xsavec", "xsaves",
        "xrstor", "xrstors",
        "xgetbv", "xsetbv",
        "vzeroupper", "vzeroall",
        # Logical / special
        "insertps", "ptest", "phminposuw",
        "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm",
        # Data moves and conversions
        "vmovdqu8", "vmovdqu16", "vmovdqu32", "vmovdqu64",
        "vpmovqd", "vpmovdb", "vpmovdw", "vpmovwb",
        "vpmovusdb", "vpmovusdw", "vpmovuswb",
        "vpextrw", "vextracti64x2", "vextracti32x4",
        "vextractf32x4", "vextractf64x2",
        "vpermt2b", "vpermt2w", "vpermt2d", "vpermt2q",
        "vpermi2b", "vpermi2w", "vpermi2d", "vpermi2q",
        "vpbroadcastb", "vpbroadcastw", "vpbroadcastd", "vpbroadcastq",
        "vcvtsi2sd", "vcvtsi2ss", "vcvttsd2usi", "vcvttss2usi",
        # AVX-512 mask moves/tests 
        "kmovb", "kmovw", "kmovd", "kmovq",
        "kortestb", "kortestw", "kortestd", "kortestq",
        "kandb", "kandw", "kandd", "kandq",
        "korb", "korw", "kord", "korq",
        "knotb", "knotw", "knotd", "knotq",
        "kxorb", "kxorw", "kxord", "kxorq",
        "kaddb", "kaddw", "kaddd", "kaddq",
        "kshiftlb", "kshiftlw", "kshiftld", "kshiftlq",
        "kshiftrb", "kshiftrw", "kshiftrd", "kshiftrq",
    }
    CAPSTONE_MISSING_MNEMONICS_SUBSTR = {
        "bf16",  # BF16 ops sometimes mid-name
        "amx",   # AMX tile ops
        "tile",  # e.g. tileloaddt1, tdpbf16ps
        "aes",
        "sha",
        "clmul",
    }
    CAPSTONE_MISSING_MNEMONICS_PREFIX = {
        "vpdp",        # VNNI: vpdpbusd, vpdpwssd...
        "vpclmul",     # carry-less multiply
        "vaes", "vsha",# AES/SHA
        "vnn",         # other VNNI-style
        "vcvtne",      # BF16/FP16 conversions
        "vpmovm2", "vpmovb2", # mask and mov variants
        "vp2intersect" # AVX-512 intersection ops
        "vgather", "vscatter",
    }
    SIMD_REGS = {
        "xmm", "ymm", "zmm", "tmm", "mm",
    }

    mnem = insn["mnemonic"].lower()
    ops = insn["operands"].lower()
    # Check if instruction belongs to any SIMD group
    if any(group in insn["groups"] for group in simd_groups):
        return True
    # Check if instruction is a missing SIMD instruction using exact match
    if mnem in CAPSTONE_MISSING_MNEMONICS_EXACT: 
        return True
    # Prefix match 
    if any(mnem.startswith(prefix) for prefix in CAPSTONE_MISSING_MNEMONICS_PREFIX):
        return True
    # Substring match for embedded tokens
    if any(tag in mnem for tag in CAPSTONE_MISSING_MNEMONICS_SUBSTR):
        return True
    # Final fallback: Check if instruction uses any SIMD registers
    if any(tag in ops for tag in SIMD_REGS):
        print(f"Found missing SIMD: {insn['address']:x} {mnem} {ops}")
        return True
    # k0..k7 (opmask) — look for whole-register tokens to avoid false hits
    # (Capstone usually prints like "k1", "k2{z}", etc.)
    if any(f"k{i}" in ops for i in range(8)):
        print(f"Found missing SIMD: {insn['address']:x} {mnem} {ops}")
        return True
    # MPX: technically part of xsave, but practically deprecated in modern Linux
    if any(f"bnd{i}" in ops for i in range(4)):
        print(f"Found missing SIMD: {insn['address']:x} {mnem} {ops}")
        return True

    return False

def map_functions_to_instructions(functions: list, instructions: list) -> list:
    """Map functions to their instructions.
    
    CRITICAL: ELF symbol table values are ground truth. This function only augments
    with instruction information if found. If instructions are not found, use None.
    
    For each function:
    - start_addr, end_addr, size come directly from ELF (ground truth)
    - Try to find first instruction at exactly start_addr (if not found, use None)
    - Try to find last instruction within bounds (if not found, use None)
    - Identify all SIMD instructions 
    - Count instructions within function range
    """
    # Create address->instruction mapping for quick lookup
    addr_to_insn = {insn["address"]: insn for insn in instructions}
    
    # Build sorted list of instruction addresses
    insn_addrs = sorted([insn["address"] for insn in instructions])
    
    result = []
    for func in functions:
        start_addr = func["start_addr"]
        size = func["size"]
        
        # CRITICAL: Only process functions with known size (size > 0)
        # Skip functions with unknown size to ensure 100% accuracy (ground truth from ELF)
        if size == 0:
            continue
        
        # ELF ground truth: start_addr and size come from symbol table
        # end_addr is exclusive: start_addr + size
        end_addr = start_addr + size
        func_end_bound = end_addr  # Exclusive bound
        
        # Try to find first instruction at exactly start_addr (ELF ground truth)
        # If not found at start_addr, use None (don't iterate to next instruction)
        first_insn = None
        if start_addr in addr_to_insn:
            first_insn = addr_to_insn[start_addr]
        
        # Try to find last instruction within function bounds [start_addr, end_addr)
        # Search in reverse order to find the highest address
        last_insn = None
        for addr in reversed(insn_addrs):
            if start_addr <= addr < func_end_bound:
                last_insn = addr_to_insn[addr]
                break
        
        # Count instructions within function range [start_addr, end_addr)
        num_insns = 0
        num_simd_insns = 0
        for addr in insn_addrs:
            if addr < start_addr:
                continue
            if addr >= func_end_bound:
                break
            num_insns += 1
            if is_simd_instruction(addr_to_insn[addr]):
                num_simd_insns += 1
        # insn_all = [f"{insn['address']:x}\t {insn['mnemonic']} {insn['operands']}".strip() for insn in instructions if start_addr <= insn["address"] < func_end_bound]
        # print(f"Function {func['name']}")
        # print('\n'.join(insn_all))
        # print("-" * 80)
        
        # Always include function (ELF ground truth), even if instructions not found
        result.append({
            "name": func["name"],
            "start_addr_hex": hex(start_addr),  # From ELF (ground truth)
            "end_addr_hex": hex(end_addr),      # From ELF: start_addr + size (exclusive)
            "size_hex": hex(size),              # From ELF (ground truth)
            "start_addr": start_addr,
            "end_addr": end_addr,
            "size": size,
            "first_insn": f"{first_insn['address']:x} {first_insn['mnemonic']} {first_insn['operands']}".strip() if first_insn else None,
            "last_insn": f"{last_insn['address']:x} {last_insn['mnemonic']} {last_insn['operands']}".strip() if last_insn else None,
            "num_insns": num_insns,
            "num_simd_insns": num_simd_insns,
        })
    
    return result


def write_output(binary_path: str, dump_opts: str, output_data: dict, function_data: list) -> None:
    """Write output files based on dump options.
    
    Args:
        binary_path: Path to the binary file
        dump_opts: Comma-separated string of output types (e.g., "func")
        output_data: Dictionary with binary metadata for JSON output
        function_data: List of function data dictionaries
    """
    dump_list = [opt.strip().lower() for opt in dump_opts.split(",") if opt.strip()] if dump_opts else []
    
    # Generate funcdump.json if 'func' is specified
    if "func" in dump_list:
        output_path = binary_path + ".funcdump.json"
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Function dump written to: {output_path}", file=sys.stdout)


def write_gprdump(gpr_path: str, function_data: list, load_base: int) -> int:
    """Generate <binary>.gprdump for functions with zero SIMD instructions.

    Steps:
    - Filter functions with num_simd_insns == 0
    - Merge overlapping or back-to-back ranges (A.end >= B.start)
    - adjust start and end addresses by load_base
    - Write pairs of uint64 little-endian (start-load_base,end-load_base) to <binary>.gprdump
    Returns the output file path.
    """
    # 1) Filter functions with num_simd_insns == 0
    zero_simd_funcs = [(f["start_addr"], f["end_addr"]) for f in function_data if f["num_simd_insns"] == 0] # [start, end) end is exclusive

    # 2) Merge overlapping or back-to-back ranges (A.end >= B.start)
    zero_simd_funcs.sort(key=lambda t: t[0])
    merged = []
    for s, e in zero_simd_funcs:
        if not merged:
            merged.append((s, e))
            continue
        ms, me = merged[-1]
        if me >= s:  # overlap or back-to-back (end is exclusive)
            # tmp debug
            # print(f"Merging {hex(ms)} {hex(me)} and {hex(s)} {hex(e)}")
            merged[-1] = (ms, max(me, e))
        else:
            merged.append((s, e))

    # 3) Write <binary>.gprdump: pairs of uint64 little-endian start,end
    with open(gpr_path, "wb") as gf:
        for s, e in merged:
            gf.write(struct.pack("<Q", s - load_base))
            gf.write(struct.pack("<Q", e - load_base))
    return len(merged)


def main() -> None:
    args = parse_args()
    
    if not os.path.isfile(args.binary):
        print(f"[ERROR] Binary not found: {args.binary}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Analyzing binary: {args.binary}", file=sys.stdout)
    
    # Open ELF file
    try:
        with open(args.binary, "rb") as f:
            elf = ELFFile(f)
            
            # Get ELF info
            elf_info = get_elf_info(elf)
            
            # Detect PIE (Position Independent Executable)
            # PIE binaries have e_type == ET_DYN (shared object type)
            e_type = elf.header["e_type"]
            is_pie = (e_type == "ET_DYN")
            pie_status = "PIE" if is_pie else "non-PIE"
            print(f"\tELF class: {elf_info['class']} \n\tEndianness: {elf_info['endianness']} \n\tType: {pie_status} (e_type={e_type})", file=sys.stdout)
            
            # Check architecture (basic check - machine type for x86_64)
            machine = elf.header["e_machine"]
            if elf_info["class"] != "64-bit" or machine not in ["EM_X86_64", 62]:  # 62 is EM_X86_64 constant
                print(f"[WARNING] This script is designed for x86_64 binaries (detected: {elf_info['class']}, machine={machine})", file=sys.stderr)
            
            # Get .text section
            text_sec, sh_offset, sh_addr, size, load_base = get_text_section(elf)
            print(f"\n.text section: ", file=sys.stdout)
            print(f"\tsh_offset=0x{sh_offset:x} \n\tsh_addr=0x{sh_addr:x} \n\tsize={size:x} \n\tp_vaddr=0x{load_base:x}", file=sys.stdout)
            
            # Read .text section data
            text_data = text_sec.data()
            if len(text_data) != size:
                print(f"[ERROR] Read {len(text_data)} bytes from .text section, expected {size} bytes", file=sys.stderr)
                sys.exit(1)
            
            # Collect function symbols
            functions = collect_function_symbols(elf)
            if not functions:
                print("[ERROR] No function symbols found. Cannot proceed.", file=sys.stderr)
                sys.exit(1)
            print(f"\nFunctions: ", file=sys.stdout)
            
            # Count functions with known size vs unknown size
            functions_with_size = sum(1 for f in functions if f["size"] > 0)
            functions_without_size = len(functions) - functions_with_size
            print(f"\t{functions_with_size} functions have known size \n\t{functions_without_size} have size=0 (will be skipped)", file=sys.stdout)
            if functions_with_size == 0:
                print("[WARNING] No functions with known size found. exiting...", file=sys.stderr)
                sys.exit(1)
            
            # Disassemble .text section
            instructions = disassemble_text(text_data, sh_addr)
            print(f"\t{len(instructions)} instructions", file=sys.stdout)
            
            # Map functions to instructions
            function_data = map_functions_to_instructions(functions, instructions)
            if len(function_data) != functions_with_size:
                print(f"[ERROR] Mapped {len(function_data)} functions, expected {len(functions)}", file=sys.stderr)
                sys.exit(1)
            
            # Count total SIMD instructions
            total_simd_insns = sum(func["num_simd_insns"] for func in function_data)
            functions_with_simd = sum(1 for func in function_data if func["num_simd_insns"] > 0)
            print(f"\t{total_simd_insns} total SIMD instructions \n\t{functions_with_simd} functions with SIMD instructions", file=sys.stdout)

            # Generate GPR dump (always generated, not controlled by -d)
            gpr_path = args.binary + ".gprdump"
            num_regions = write_gprdump(gpr_path, function_data, load_base)
            print(f"GPR dump written to: {gpr_path} ({num_regions} regions)", file=sys.stdout)
            
            # Write outputs based on -d option
            if args.dump:
                # Prepare output JSON 
                output = {
                    "binary": os.path.abspath(args.binary),
                    "arch": "x86_64",
                    "type": pie_status,
                    "load_base": hex(load_base),
                    "functions": function_data,
                }
                write_output(args.binary, args.dump, output, function_data)

    except Exception as e:
        print(f"[ERROR] Failed to analyze binary: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

