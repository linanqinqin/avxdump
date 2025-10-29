#!/usr/bin/env python3
"""
AVX Session Analysis Tool - Steps 1-3: Binary Discovery, SIMD Analysis, and CFG Building

This script implements the first three steps of static analysis for AVX/SSE usage sessions
in x86_64 ELF binaries:
1. Discovers the main binary and all its dependencies
2. Identifies SIMD instructions using Capstone disassembly
3. Builds control flow graphs using angr CFGFast analysis

Usage: python3 avxdump.py <binary_path>
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("Error: pyelftools not installed. Install with: pip install pyelftools")
    sys.exit(1)

try:
    import capstone
    from capstone import CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
except ImportError:
    print("Error: Capstone not installed. Install with: pip install capstone")
    sys.exit(1)

try:
    import angr
    from angr.analyses import CFGFast
except ImportError:
    print("Error: angr not installed. Install with: pip install angr")
    sys.exit(1)


class BinaryAnalyzer:
    """Analyzes ELF binaries and their dependencies."""
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.elf_file = None
        self.libraries = {}  # Dict[str, Dict] - library name -> info dict
        self.simd_instructions = {}  # Dict[str, List] - module -> list of SIMD instructions
        self.cfg_data = {}  # Dict[str, Dict] - module -> CFG information
        
        # Initialize Capstone disassembler
        self.cs = capstone.Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True  # Enable detailed instruction information
        
        # Open the ELF file
        if self.validate_binary():
            try:
                with open(self.binary_path, 'rb') as f:
                    self.elf_file = ELFFile(f)
                    print(f"Successfully opened binary: {self.binary_path}")
            except Exception as e:
                print(f"Error opening ELF file: {e}")
                self.elf_file = None
        
    def validate_binary(self) -> bool:
        """Validate that the binary exists and is a valid ELF file."""
        if not self.binary_path.exists():
            print(f"Error: Binary file '{self.binary_path}' does not exist")
            return False
            
        if not self.binary_path.is_file():
            print(f"Error: '{self.binary_path}' is not a file")
            return False
            
        try:
            with open(self.binary_path, 'rb') as f:
                # Check ELF magic number
                magic = f.read(4)
                if magic != b'\x7fELF':
                    print(f"Error: '{self.binary_path}' is not a valid ELF file")
                    return False
        except Exception as e:
            print(f"Error reading binary file: {e}")
            return False
            
        return True
    
    def open_binary(self) -> bool:
        """Open the main binary file using pyelftools."""
        try:
            self.elf_file = ELFFile(open(self.binary_path, 'rb'))
            print(f"Successfully opened binary: {self.binary_path}")
            return True
        except Exception as e:
            print(f"Error opening binary file: {e}")
            return False
    
    def get_dynamic_libraries(self) -> List[str]:
        """Extract DT_NEEDED entries from the dynamic section."""
        libraries = []
        
        try:
            # Find the dynamic section
            dynamic_section = self.elf_file.get_section_by_name('.dynamic')
            if not dynamic_section:
                print("Warning: No .dynamic section found (static binary?)")
                return libraries
            
            # Extract DT_NEEDED entries
            for tag in dynamic_section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    lib_name = tag.needed
                    libraries.append(lib_name)
                    print(f"Found dependency: {lib_name}")
            
            return libraries
            
        except Exception as e:
            print(f"Error reading dynamic section: {e}")
            return libraries
    
    def get_binary_info(self) -> Dict:
        """Get information about the main binary."""
        try:
            entry_point = self.elf_file.header.e_entry
            
            # Check if it's a PIE binary
            if self.elf_file.header.e_type == 'ET_DYN':
                print(f"PIE binary detected, entry point: 0x{entry_point:x}")
                binary_type = "PIE"
            else:
                print(f"Non-PIE binary, entry point: 0x{entry_point:x}")
                binary_type = "non-PIE"
            
            return {
                'type': binary_type,
                'entry_point': entry_point
            }
                
        except Exception as e:
            print(f"Error getting binary info: {e}")
            return {}
    
    def find_library_path(self, lib_name: str) -> Optional[str]:
        """Find the full path to a library using standard search paths and ldd."""
        # First try using ldd to get the exact path
        try:
            result = subprocess.run(['ldd', str(self.binary_path)], 
                                 capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n'):
                if lib_name in line:
                    # Parse ldd output: lib_name => /path/to/lib (0x...)
                    if '=>' in line:
                        path_part = line.split('=>')[1].strip()
                        if path_part.startswith('/'):
                            # Extract just the path part
                            path = path_part.split()[0]
                            if os.path.exists(path):
                                return path
            
        except subprocess.CalledProcessError as e:
            print(f"Warning: ldd failed: {e}")
        except FileNotFoundError:
            print("Warning: ldd not found, trying standard paths")
        
        # Fallback to standard library search paths
        search_paths = [
            '/lib/x86_64-linux-gnu',
            '/usr/lib/x86_64-linux-gnu', 
            '/lib64',
            '/usr/lib64',
            '/lib',
            '/usr/lib',
            '/usr/local/lib'
        ]
        
        for search_path in search_paths:
            potential_path = os.path.join(search_path, lib_name)
            if os.path.exists(potential_path):
                return potential_path
        
        print(f"Warning: Could not find library: {lib_name}")
        return None
    
    def get_library_info(self, lib_path: str) -> Dict:
        """Get information about a library."""
        try:
            with open(lib_path, 'rb') as f:
                elf_file = ELFFile(f)
                
                if elf_file.header.e_type == 'ET_DYN':
                    lib_type = "shared_library"
                    print(f"Shared library {lib_path}")
                else:
                    lib_type = "static_library"
                    print(f"Static library {lib_path}")
                
                return {
                    'type': lib_type,
                    'entry_point': elf_file.header.e_entry
                }
                    
        except Exception as e:
            print(f"Error getting library info for {lib_path}: {e}")
            return {}
    
    def analyze_dependencies(self) -> bool:
        """Analyze all dependencies."""
        print("\n=== Analyzing Dependencies ===")
        
        # Get the main binary info
        binary_info = self.get_binary_info()
        if binary_info:
            self.libraries[str(self.binary_path)] = {
                'path': str(self.binary_path),
                'type': 'main_binary',
                'binary_type': binary_info['type'],
                'entry_point': binary_info['entry_point']
            }
        
        # Get dynamic libraries
        lib_names = self.get_dynamic_libraries()
        
        for lib_name in lib_names:
            lib_path = self.find_library_path(lib_name)
            if lib_path:
                lib_info = self.get_library_info(lib_path)
                if lib_info:
                    self.libraries[lib_path] = {
                        'path': lib_path,
                        'type': lib_info['type'],
                        'name': lib_name,
                        'entry_point': lib_info['entry_point']
                    }
                    print(f"Added library: {lib_name} -> {lib_path}")
            else:
                print(f"Failed to locate library: {lib_name}")
        
        return len(self.libraries) > 0
    
    def get_executable_sections(self, elf_file) -> List[Tuple[int, int, str]]:
        """Get executable sections from an ELF file."""
        sections = []
        
        for section in elf_file.iter_sections():
            if section['sh_flags'] & 0x4:  # SHF_EXECINSTR flag
                sections.append((
                    section['sh_addr'],  # Virtual address
                    section['sh_size'],   # Size
                    section.name         # Section name
                ))
        
        return sections
    
    def is_simd_instruction(self, instruction) -> bool:
        """Check if an instruction is a SIMD instruction using Capstone groups."""
        # Capstone groups for SIMD instructions
        simd_groups = {
            capstone.x86.X86_GRP_SSE1,     # SSE
            capstone.x86.X86_GRP_SSE2,     # SSE2
            capstone.x86.X86_GRP_SSE3,     # SSE3
            capstone.x86.X86_GRP_SSE41,    # SSE4.1
            capstone.x86.X86_GRP_SSE42,    # SSE4.2
            capstone.x86.X86_GRP_AVX,      # AVX
            capstone.x86.X86_GRP_AVX2,     # AVX2
            capstone.x86.X86_GRP_AVX512,   # AVX512
            capstone.x86.X86_GRP_FMA,      # FMA
            capstone.x86.X86_GRP_F16C,     # F16C
        }
        
        # Check if instruction belongs to any SIMD group
        for group in instruction.groups:
            if group in simd_groups:
                return True
        
        return False
    
    def extract_register_info(self, instruction) -> Tuple[List[str], List[str]]:
        """Extract read and written registers from an instruction."""
        regs_read = []
        regs_write = []
        
        # Use the proper Capstone API: regs_access() method
        try:
            regs_read_ids, regs_write_ids = instruction.regs_access()
            
            # Convert register IDs to names
            for reg_id in regs_read_ids:
                reg_name = self.cs.reg_name(reg_id)
                if reg_name:
                    regs_read.append(reg_name)
            
            for reg_id in regs_write_ids:
                reg_name = self.cs.reg_name(reg_id)
                if reg_name:
                    regs_write.append(reg_name)
                    
        except Exception as e:
            # Fallback to manual extraction if regs_access() fails
            print(f"Warning: regs_access() failed, using fallback: {e}")
            regs_read, regs_write = self._extract_registers_fallback(instruction)
        
        return regs_read, regs_write
    
    def _extract_registers_fallback(self, instruction) -> Tuple[List[str], List[str]]:
        """Fallback method for register extraction using operand access flags."""
        regs_read_set = set()
        regs_write_set = set()
        
        # Import Capstone constants
        from capstone import CS_AC_READ, CS_AC_WRITE, CS_OP_REG, CS_OP_MEM
        
        for op in instruction.operands:
            if op.access & CS_AC_READ:
                # Operand is read - check if it's a register or memory
                if op.type == CS_OP_REG:
                    reg_id = op.value.reg
                    regs_read_set.add(reg_id)
                elif op.type == CS_OP_MEM:
                    # Memory operand: base/index registers are read
                    mem = op.value.mem
                    if mem.base != 0:
                        regs_read_set.add(mem.base)
                    if mem.index != 0:
                        regs_read_set.add(mem.index)
            
            if op.access & CS_AC_WRITE:
                # Operand is written - check if it's a register or memory
                if op.type == CS_OP_REG:
                    reg_id = op.value.reg
                    regs_write_set.add(reg_id)
                elif op.type == CS_OP_MEM:
                    # Memory destination: base/index registers are read (not written)
                    mem = op.value.mem
                    if mem.base != 0:
                        regs_read_set.add(mem.base)
                    if mem.index != 0:
                        regs_read_set.add(mem.index)
        
        # Convert register IDs to names
        regs_read = []
        regs_write = []
        
        for reg_id in regs_read_set:
            reg_name = self.cs.reg_name(reg_id)
            if reg_name:
                regs_read.append(reg_name)
        
        for reg_id in regs_write_set:
            reg_name = self.cs.reg_name(reg_id)
            if reg_name:
                regs_write.append(reg_name)
        
        return regs_read, regs_write
    
    def disassemble_module(self, module_path: str, module_info: Dict) -> List[Dict]:
        """Disassemble a module and find SIMD instructions."""
        simd_instructions = []
        
        try:
            with open(module_path, 'rb') as f:
                elf_file = ELFFile(f)
                
                # Get executable sections
                sections = self.get_executable_sections(elf_file)
                
                if not sections:
                    print(f"Warning: No executable sections found in {module_path}")
                    return simd_instructions
                
                print(f"Disassembling {module_path}...")
                
                for section_addr, section_size, section_name in sections:
                    # Read section data
                    section = elf_file.get_section_by_name(section_name)
                    if not section:
                        continue
                    
                    section_data = section.data()
                    
                    # Disassemble the section
                    for instruction in self.cs.disasm(section_data, section_addr):
                        if self.is_simd_instruction(instruction):
                            regs_read, regs_write = self.extract_register_info(instruction)
                            
                            simd_instruction = {
                                'address': instruction.address,
                                'mnemonic': instruction.mnemonic,
                                'operands': instruction.op_str,
                                'opcode': instruction.bytes.hex(),
                                'regs_read': regs_read,
                                'regs_write': regs_write,
                                'section': section_name,
                                'size': instruction.size
                            }
                            
                            simd_instructions.append(simd_instruction)
                
                print(f"Found {len(simd_instructions)} SIMD instructions in {module_path}")
                
        except Exception as e:
            print(f"Error disassembling {module_path}: {e}")
        
        return simd_instructions
    
    def analyze_simd_instructions(self) -> bool:
        """Analyze SIMD instructions in all modules."""
        print("\n=== Analyzing SIMD Instructions ===")
        
        for module_path, module_info in self.libraries.items():
            simd_instructions = self.disassemble_module(module_path, module_info)
            self.simd_instructions[module_path] = simd_instructions
        
        total_simd = sum(len(instructions) for instructions in self.simd_instructions.values())
        print(f"Total SIMD instructions found: {total_simd}")
        
        return total_simd > 0
    
    def get_target_type(self) -> str:
        """Determine if the target is a binary or library."""
        try:
            with open(self.binary_path, 'rb') as f:
                elf_file = ELFFile(f)
                
                if elf_file.header.e_type == 'ET_EXEC':
                    return 'executable'
                elif elf_file.header.e_type == 'ET_DYN':
                    # Check if it has an entry point - libraries typically have entry point 0
                    entry_point = elf_file.header.e_entry
                    if entry_point == 0:
                        return 'library'  # Shared library with no entry point
                    else:
                        return 'executable'  # PIE executable with entry point
                else:
                    return 'unknown'
                    
        except Exception as e:
            print(f"Error determining target type: {e}")
            return 'unknown'
    
    def get_metadata_filename(self) -> str:
        """Get the metadata filename for the target."""
        return f"{self.binary_path.name}.avxdump.json"
    
    def metadata_exists(self) -> bool:
        """Check if metadata file already exists."""
        metadata_file = self.get_metadata_filename()
        return os.path.exists(metadata_file)
    
    def analyze_cfg_module(self, module_path: str, module_info: Dict) -> Dict:
        """Analyze control flow graph for a module using angr CFGFast with robust error handling."""
        cfg_info = {
            'functions': {},
            'basic_blocks': {},
            'edges': [],
            'entry_points': [],
            'analysis_success': False,
            'analysis_method': 'none',
            'error_details': None
        }
        
        try:
            print(f"Building CFG for {module_path}...")
            
            # Load the binary with angr
            proj = angr.Project(module_path, auto_load_libs=False)
            
            # Try different CFG analysis strategies based on binary size
            binary_size = os.path.getsize(module_path)
            print(f"Binary size: {binary_size / (1024*1024):.1f} MB")
            
            # Strategy 1: Standard CFGFast with optimized parameters
            try:
                print("  Attempting CFGFast with optimized parameters...")
                cfg = proj.analyses.CFGFast(
                    force_complete_scan=False,  # Skip exhaustive scanning
                    resolve_indirect_jumps=False,  # Skip indirect jump resolution
                    indirect_jump_target_limit=1000,  # Limit indirect jump targets
                    exclude_sparse_regions=True  # Skip sparse regions
                )
                cfg_info['analysis_method'] = 'CFGFast_optimized'
                cfg_info['analysis_success'] = True
                print("  CFGFast analysis succeeded!")
                
            except Exception as e1:
                print(f"  CFGFast failed: {e1}")
                
                # Strategy 2: CFGFast with minimal parameters for large binaries
                if binary_size > 10 * 1024 * 1024:  # > 10MB
                    try:
                        print("  Attempting CFGFast with minimal parameters...")
                        cfg = proj.analyses.CFGFast(
                            force_complete_scan=False,
                            resolve_indirect_jumps=False,
                            indirect_jump_target_limit=100,  # Very low limit
                            exclude_sparse_regions=True
                        )
                        cfg_info['analysis_method'] = 'CFGFast_minimal'
                        cfg_info['analysis_success'] = True
                        print("  CFGFast minimal analysis succeeded!")
                        
                    except Exception as e2:
                        print(f"  CFGFast minimal failed: {e2}")
                        
                        # Strategy 3: Try CFGEmulated for very large binaries
                        try:
                            print("  Attempting CFGEmulated (slower but more robust)...")
                            cfg = proj.analyses.CFGEmulated(
                                starts=[proj.entry],  # Start from entry point
                                keep_state=True,
                                state_add_options=angr.options.unicorn,
                                context_sensitivity_level=0  # Minimal context sensitivity
                            )
                            cfg_info['analysis_method'] = 'CFGEmulated'
                            cfg_info['analysis_success'] = True
                            print("  CFGEmulated analysis succeeded!")
                            
                        except Exception as e3:
                            print(f"  CFGEmulated failed: {e3}")
                            
                            # Strategy 4: Fallback - extract basic function info from symbols
                            print("  Attempting fallback: extracting function info from symbols...")
                            try:
                                cfg_info = self._extract_functions_from_symbols(proj, module_path)
                                cfg_info['analysis_method'] = 'symbol_extraction'
                                cfg_info['analysis_success'] = True
                                print("  Symbol extraction succeeded!")
                                return cfg_info
                            except Exception as e4:
                                print(f"  Symbol extraction failed: {e4}")
                                cfg_info['error_details'] = f"All methods failed. CFGFast: {e1}, CFGFast_minimal: {e2}, CFGEmulated: {e3}, Symbols: {e4}"
                                return cfg_info
                else:
                    cfg_info['error_details'] = f"CFGFast failed: {e1}"
                    return cfg_info
            
            # Extract function information
            for func_addr, func in cfg.functions.items():
                func_info = {
                    'address': func_addr,
                    'name': func.name if func.name else f"sub_{func_addr:x}",
                    'size': func.size,
                    'basic_blocks': [],
                    'entry_block': func.startpoint.addr if func.startpoint else None
                }
                
                # Extract basic blocks for this function
                for block_addr in func.block_addrs:
                    # Find the block node in the CFG graph
                    block_node = None
                    for node in cfg.graph.nodes():
                        if hasattr(node, 'addr') and node.addr == block_addr:
                            block_node = node
                            break
                    
                    if block_node:
                        block_info = {
                            'address': block_addr,
                            'size': block_node.size if hasattr(block_node, 'size') else 0,
                            'instructions': [],
                            'successors': [],
                            'predecessors': []
                        }
                        
                        # Get instruction addresses in this block
                        if hasattr(block_node, 'instruction_addrs'):
                            for insn_addr in block_node.instruction_addrs:
                                block_info['instructions'].append(insn_addr)
                        
                        # Get successors and predecessors
                        for succ in cfg.graph.successors(block_node):
                            if hasattr(succ, 'addr'):
                                block_info['successors'].append(succ.addr)
                        
                        for pred in cfg.graph.predecessors(block_node):
                            if hasattr(pred, 'addr'):
                                block_info['predecessors'].append(pred.addr)
                        
                        func_info['basic_blocks'].append(block_info)
                        cfg_info['basic_blocks'][block_addr] = block_info
                
                cfg_info['functions'][func_addr] = func_info
            
            # Extract edges between basic blocks
            for edge in cfg.graph.edges():
                edge_info = {
                    'from': edge[0].addr,
                    'to': edge[1].addr,
                    'type': 'direct'  # Could be enhanced to detect jump types
                }
                cfg_info['edges'].append(edge_info)
            
            # Get entry points
            cfg_info['entry_points'] = list(cfg.functions.keys())
            
            print(f"CFG analysis completed for {module_path}:")
            print(f"  Functions: {len(cfg_info['functions'])}")
            print(f"  Basic blocks: {len(cfg_info['basic_blocks'])}")
            print(f"  Edges: {len(cfg_info['edges'])}")
            
        except Exception as e:
            print(f"Error building CFG for {module_path}: {e}")
            cfg_info['error'] = str(e)
        
        return cfg_info
    
    def _extract_functions_from_symbols(self, proj, module_path: str) -> Dict:
        """Fallback method: extract basic function information from symbols when CFG analysis fails."""
        cfg_info = {
            'functions': {},
            'basic_blocks': {},
            'edges': [],
            'entry_points': [],
            'analysis_success': False,
            'analysis_method': 'symbol_extraction',
            'error_details': None
        }
        
        try:
            # Extract function symbols
            function_count = 0
            
            # Get symbols from the binary
            for symbol in proj.loader.main_object.symbols:
                if symbol.is_function and symbol.resolvedby is not None:
                    func_addr = symbol.resolvedby.rebased_addr
                    func_name = symbol.name if symbol.name else f"sub_{func_addr:x}"
                    
                    func_info = {
                        'address': func_addr,
                        'name': func_name,
                        'size': 0,  # Unknown without CFG analysis
                        'basic_blocks': [],
                        'entry_block': func_addr
                    }
                    
                    cfg_info['functions'][func_addr] = func_info
                    function_count += 1
            
            # Add entry point
            if proj.entry:
                cfg_info['entry_points'] = [proj.entry]
            
            print(f"  Extracted {function_count} functions from symbols")
            cfg_info['analysis_success'] = True
            
        except Exception as e:
            print(f"  Symbol extraction error: {e}")
            cfg_info['error_details'] = str(e)
        
        return cfg_info
    
    def analyze_cfg(self) -> bool:
        """Analyze control flow graphs for all modules."""
        print("\n=== Building Control Flow Graphs ===")
        
        success_count = 0
        
        for module_path, module_info in self.libraries.items():
            cfg_info = self.analyze_cfg_module(module_path, module_info)
            self.cfg_data[module_path] = cfg_info
            
            if cfg_info['analysis_success']:
                success_count += 1
        
        print(f"CFG analysis completed for {success_count}/{len(self.libraries)} modules")
        
        return success_count > 0
    
    def analyze_simd_liveness(self) -> bool:
        """Perform liveness analysis on SIMD registers to identify AVX session boundaries."""
        print("\n=== Performing SIMD Register Liveness Analysis ===")
        
        self.avx_sessions = {}
        
        for module_path, cfg_data in self.cfg_data.items():
            if not cfg_data.get('analysis_success', False):
                print(f"Skipping {module_path} - CFG analysis failed")
                continue
                
            print(f"Analyzing liveness for {module_path}...")
            module_sessions = self._analyze_module_liveness(module_path, cfg_data)
            self.avx_sessions[module_path] = module_sessions
            
            total_sessions = len(module_sessions)
            print(f"Found {total_sessions} AVX sessions in {module_path}")
        
        total_sessions = sum(len(sessions) for sessions in self.avx_sessions.values())
        print(f"Total AVX sessions found: {total_sessions}")
        
        return total_sessions > 0
    
    def analyze_simd_simple(self) -> bool:
        """Simple AVX session detection: any function with SIMD instructions is an AVX session."""
        print("\n=== Performing Simple AVX Session Detection ===")
        
        self.avx_sessions = {}
        self.simple_mode_functions_with_simd = {}  # Track functions with SIMD per module
        
        for module_path, cfg_data in self.cfg_data.items():
            if not cfg_data.get('analysis_success', False):
                print(f"Skipping {module_path} - CFG analysis failed")
                continue
                
            print(f"Analyzing simple sessions for {module_path}...")
            module_sessions, functions_with_simd = self._analyze_module_simple(module_path, cfg_data)
            self.avx_sessions[module_path] = module_sessions
            self.simple_mode_functions_with_simd[module_path] = functions_with_simd
            
            total_sessions = len(module_sessions)
            print(f"Found {total_sessions} AVX sessions in {module_path}")
        
        total_sessions = sum(len(sessions) for sessions in self.avx_sessions.values())
        total_functions_with_simd = sum(functions_with_simd for functions_with_simd in self.simple_mode_functions_with_simd.values())
        print(f"Total AVX sessions found: {total_sessions}")
        print(f"Total functions with SIMD instructions: {total_functions_with_simd}")
        
        return total_sessions > 0
    
    def _analyze_module_simple(self, module_path: str, cfg_data: Dict) -> Tuple[List[Dict], int]:
        """Simple analysis: any function with SIMD instructions is an AVX session."""
        sessions = []
        
        # Get SIMD instructions for this module
        simd_instructions = self.simd_instructions.get(module_path, [])
        if not simd_instructions:
            return sessions, 0
        
        # Calculate base offset for PIE binaries
        base_offset = self._calculate_base_offset(cfg_data)
        
        # Group SIMD instructions by function using CFG data
        func_simd_instructions = self._group_simd_by_function(simd_instructions, cfg_data, base_offset)
        
        functions_with_simd = len(func_simd_instructions)
        print(f"Functions with SIMD instructions: {functions_with_simd}")
        
        # Create one session per function that has SIMD instructions
        for func_addr, func_simd_insns in func_simd_instructions.items():
            if not func_simd_insns:
                continue
            
            # Get function info from CFG data (if available)
            func_info = cfg_data['functions'].get(func_addr, {})
            func_name = func_info.get('name', f'func_0x{func_addr:x}')
            func_size = func_info.get('size', 0)
            
            # Check if this is an orphan session (no function info)
            is_orphan = func_addr not in cfg_data['functions']
            if is_orphan:
                func_name = f'orphan_0x{func_addr:x}'
                func_size = 0
            
            # Sort SIMD instructions by address
            func_simd_insns.sort(key=lambda x: x['address'])
            
            # Session spans from first to last instruction in the function
            # Use function boundaries if available, otherwise use instruction boundaries
            if func_size > 0:
                session_start = func_addr
                session_end = func_addr + func_size - 1  # Inclusive end address
            else:
                # Fallback: use instruction boundaries
                session_start = func_simd_insns[0]['address'] + base_offset
                session_end = func_simd_insns[-1]['address'] + base_offset
            
            # Collect all SIMD instructions in this function
            session_instructions = []
            for insn in func_simd_insns:
                session_instructions.append({
                    'address': insn['address'] + base_offset,
                    'mnemonic': insn['mnemonic'],
                    'operands': insn['operands'],
                    'opcode': insn['opcode'],
                    'regs_read': insn['regs_read'],
                    'regs_write': insn['regs_write']
                })
            
            session = {
                'start_address': session_start,
                'end_address': session_end,
                'function_name': func_name,
                'function_address': func_addr,
                'instructions': session_instructions,
                'instruction_count': len(session_instructions),
                'detection_method': 'simple_function_based'
            }
            
            sessions.append(session)
            
            print(f"  Function {func_name} (0x{func_addr:x}): {len(session_instructions)} SIMD instructions")
            print(f"    Session: 0x{session_start:x} - 0x{session_end:x}")
        
        return sessions, functions_with_simd
    
    def _analyze_module_liveness(self, module_path: str, cfg_data: Dict) -> List[Dict]:
        """Analyze liveness for a single module."""
        sessions = []
        
        # Get SIMD instructions for this module
        simd_instructions = self.simd_instructions.get(module_path, [])
        if not simd_instructions:
            return sessions
        
        # Calculate base offset once for the entire module
        base_offset = self._calculate_base_offset(cfg_data)
        
        # Group SIMD instructions by function
        func_simd_instructions = self._group_simd_by_function(simd_instructions, cfg_data, base_offset)
        
        # Analyze each function
        for func_addr, func_simd_insns in func_simd_instructions.items():
            if not func_simd_insns:
                continue
                
            func_sessions = self._analyze_function_liveness(func_addr, func_simd_insns, cfg_data, base_offset)
            sessions.extend(func_sessions)
        
        return sessions
    
    def _calculate_base_offset(self, cfg_data: Dict) -> int:
        """Calculate base address offset for PIE binaries."""
        base_offset = 0
        
        # Check basic blocks first (stored as dict: block_addr -> block_info)
        basic_blocks = cfg_data.get('basic_blocks', {})
        if basic_blocks:
            first_block_addr = min(basic_blocks.keys())
            if first_block_addr > 0x400000:  # PIE binary
                base_offset = first_block_addr - 0x1000  # Assume .text starts at 0x1000
                print(f"PIE binary detected, base offset: 0x{base_offset:x}")
        
        return base_offset
    
    def _group_simd_by_function(self, simd_instructions: List[Dict], cfg_data: Dict, base_offset: int) -> Dict:
        """Group SIMD instructions by function."""
        func_simd = {}
        
        functions = cfg_data.get('functions', [])
        
        # Track unassigned instructions
        unassigned_instructions = []
        for simd_insn in simd_instructions:
            insn_addr = simd_insn['address'] + base_offset  # Normalize address
            assigned = False
            
            # Find which function contains this instruction
            if isinstance(functions, dict):
                # Functions stored as dict
                for func_addr, func_info in functions.items():
                    func_start = func_info['address']
                    func_end = func_start + func_info.get('size', 0)
                    
                    if func_start <= insn_addr < func_end:
                        if func_addr not in func_simd:
                            func_simd[func_addr] = []
                        func_simd[func_addr].append(simd_insn)
                        assigned = True
                        break
            elif isinstance(functions, list):
                # Functions stored as list
                for func_info in functions:
                    func_start = func_info['address']
                    func_end = func_start + func_info.get('size', 0)
                    
                    if func_start <= insn_addr < func_end:
                        func_addr = func_start
                        if func_addr not in func_simd:
                            func_simd[func_addr] = []
                        func_simd[func_addr].append(simd_insn)
                        assigned = True
                        break
            
            # Collect unassigned instructions
            if not assigned:
                unassigned_instructions.append(simd_insn)
        
        # Create orphan sessions for unassigned instructions
        if unassigned_instructions:
            print(f"Creating orphan sessions for {len(unassigned_instructions)} unassigned SIMD instructions")
            # Use empirical threshold based on function span analysis (95th percentile)
            threshold = 1602  # bytes - covers 95% of function spans
            
            # Group unassigned instructions using distance-based clustering
            orphan_groups = self._cluster_instructions_by_distance(unassigned_instructions, base_offset, threshold)
            
            print(f"  Clustered into {len(orphan_groups)} groups using {threshold} byte threshold")
            
            for i, group in enumerate(orphan_groups):
                if group:
                    orphan_addr = group[0]['address'] + base_offset
                    func_simd[orphan_addr] = group
                    
                    # Show cluster details
                    if len(group) > 1:
                        first_addr = group[0]['address'] + base_offset
                        last_addr = group[-1]['address'] + base_offset
                        span = last_addr - first_addr
                        print(f"    Group {i+1}: {len(group)} instructions, span: {span} bytes (0x{first_addr:x}-0x{last_addr:x})")
                    else:
                        print(f"    Group {i+1}: {len(group)} instruction (singleton)")
        
        print(f"Functions with SIMD: {len(func_simd)}")
        for func_addr, insns in func_simd.items():
            print(f"  Function 0x{func_addr:x}: {len(insns)} SIMD instructions")
        
        return func_simd
    
    def _cluster_instructions_by_distance(self, instructions: List[Dict], base_offset: int, threshold: int) -> List[List[Dict]]:
        """
        Cluster SIMD instructions by address distance using a simple clustering algorithm.
        
        Args:
            instructions: List of SIMD instruction dictionaries
            base_offset: Base address offset for address normalization
            threshold: Maximum distance between instructions in the same cluster (bytes)
            
        Returns:
            List of instruction groups (clusters)
        """
        if not instructions:
            return []
        
        # Sort instructions by address
        sorted_instructions = sorted(instructions, key=lambda x: x['address'])
        
        clusters = []
        current_cluster = [sorted_instructions[0]]
        
        for i in range(1, len(sorted_instructions)):
            current_insn = sorted_instructions[i]
            prev_insn = sorted_instructions[i-1]
            
            # Calculate distance between consecutive instructions
            current_addr = current_insn['address'] + base_offset
            prev_addr = prev_insn['address'] + base_offset
            distance = current_addr - prev_addr
            
            if distance <= threshold:
                # Add to current cluster
                current_cluster.append(current_insn)
            else:
                # Start new cluster
                clusters.append(current_cluster)
                current_cluster = [current_insn]
        
        # Add the last cluster
        if current_cluster:
            clusters.append(current_cluster)
        
        return clusters
    
    def _analyze_function_liveness(self, func_addr: int, simd_instructions: List[Dict], cfg_data: Dict, base_offset: int) -> List[Dict]:
        """Analyze liveness for a single function."""
        sessions = []
        
        # Sort SIMD instructions by address
        simd_instructions.sort(key=lambda x: x['address'])
        
        # Get function's basic blocks
        func_info = cfg_data['functions'].get(func_addr, {})
        basic_blocks = func_info.get('basic_blocks', [])
        
        if not basic_blocks:
            return sessions
        
        # Perform liveness analysis
        liveness_info = self._compute_liveness(simd_instructions, basic_blocks, base_offset)
        
        # Identify session boundaries
        sessions = self._identify_session_boundaries(simd_instructions, liveness_info, base_offset)
        
        return sessions
    
    def _compute_liveness(self, simd_instructions: List[Dict], basic_blocks: List[Dict], base_offset: int) -> Dict:
        """Compute liveness information for SIMD registers using CFG-based analysis with function call handling."""
        print(f"\n=== DEBUG: Starting Liveness Analysis ===")
        print(f"SIMD instructions: {len(simd_instructions)}")
        print(f"Basic blocks: {len(basic_blocks)}")
        
        # Initialize liveness sets
        live_in = {}  # instruction -> set of live registers
        live_out = {}  # instruction -> set of live registers
        
        # SIMD register universe (XMM0-XMM31, YMM0-YMM31, ZMM0-ZMM31)
        simd_regs = set()
        for i in range(32):
            simd_regs.add(f'xmm{i}')
            simd_regs.add(f'ymm{i}')
            simd_regs.add(f'zmm{i}')
        
        # Initialize all instructions with empty live sets
        for insn in simd_instructions:
            insn_addr = insn['address'] + base_offset  # Normalize address
            live_in[insn_addr] = set()
            live_out[insn_addr] = set()
        
        print(f"Initialized liveness sets for {len(simd_instructions)} instructions")
        
        # Build instruction-to-basic-block mapping
        insn_to_block = {}
        block_to_insns = {}
        
        print(f"\n=== DEBUG: Building CFG Mappings ===")
        blocks_with_simd = 0
        
        # Debug basic block address ranges
        print(f"First 5 basic block address ranges:")
        for i, block in enumerate(basic_blocks[:5]):
            block_addr = block['address']
            block_size = block['size']
            block_end = block_addr + block_size
            print(f"  {i}: 0x{block_addr:08x} - 0x{block_end:08x}")
        
        # Debug SIMD instruction addresses (normalized)
        print(f"\nFirst 5 SIMD instruction addresses (normalized):")
        for i, insn in enumerate(simd_instructions[:5]):
            print(f"  {i}: 0x{insn['address']:08x}")
        
        for block in basic_blocks:
            block_addr = block['address']
            block_size = block['size']
            block_end = block_addr + block_size
            
            block_insns = []
            for insn in simd_instructions:
                insn_addr = insn['address'] + base_offset  # Normalize address
                if block_addr <= insn_addr < block_end:
                    insn_to_block[insn_addr] = block_addr
                    block_insns.append(insn)
            
            # Sort instructions within block by address
            block_insns.sort(key=lambda x: x['address'])
            block_to_insns[block_addr] = block_insns
            
            if block_insns:
                blocks_with_simd += 1
                print(f"  Block 0x{block_addr:x}: {len(block_insns)} SIMD instructions")
        
        print(f"Blocks with SIMD instructions: {blocks_with_simd}/{len(basic_blocks)}")
        
        # Build CFG edges mapping
        block_edges = {}
        total_edges = 0
        for block in basic_blocks:
            block_addr = block['address']
            successors = block.get('successors', [])
            block_edges[block_addr] = successors
            total_edges += len(successors)
        
        print(f"Total CFG edges: {total_edges}")
        
        # Detect function calls and model them
        function_calls = self._detect_function_calls(simd_instructions, basic_blocks)
        
        # Detect function arguments (SIMD registers used without being loaded first)
        function_args = self._detect_function_arguments(simd_instructions, basic_blocks)
        
        # Perform CFG-based backward data-flow analysis with function call handling
        changed = True
        iteration = 0
        max_iterations = 100  # Prevent infinite loops
        
        print(f"\n=== DEBUG: Starting Liveness Iteration ===")
        
        while changed and iteration < max_iterations:
            changed = False
            iteration += 1
            
            if iteration <= 3:  # Only show debug for first few iterations
                print(f"\n--- Iteration {iteration} ---")
            
            instructions_changed = 0
            
            # Process basic blocks in reverse order
            for block_addr in reversed(sorted(block_to_insns.keys())):
                block_insns = block_to_insns[block_addr]
                if not block_insns:
                    continue
                
                # Process instructions within block in reverse order
                for insn in reversed(block_insns):
                    insn_addr = insn['address'] + base_offset  # Normalize address
                    
                    # Get registers read and written by this instruction
                    regs_read = set(insn.get('regs_read', []))
                    regs_write = set(insn.get('regs_write', []))
                    
                    # Filter to only SIMD registers
                    simd_regs_read = regs_read.intersection(simd_regs)
                    simd_regs_write = regs_write.intersection(simd_regs)
                    
                    # Handle function calls specially
                    if insn_addr in function_calls:
                        call_info = function_calls[insn_addr]
                        # Function calls read argument registers and write return registers
                        simd_regs_read.update(call_info.get('args', set()))
                        simd_regs_write.update(call_info.get('returns', set()))
                    
                    # Handle function arguments (registers used without being loaded first)
                    if insn_addr in function_args:
                        func_args = function_args[insn_addr]
                        # These registers are live coming into the function
                        simd_regs_read.update(func_args)
                    
                    # Live-out: union of live-in sets of successors
                    old_live_out = live_out[insn_addr].copy()
                    live_out[insn_addr] = set()
                    
                    # Find successors of this instruction
                    successors = self._get_instruction_successors(insn_addr, block_insns, block_edges, block_to_insns, insn_to_block, base_offset)
                    
                    for succ_addr in successors:
                        if succ_addr in live_in:
                            live_out[insn_addr].update(live_in[succ_addr])
                    
                    # Live-in: (live-out - written) ∪ read
                    old_live_in = live_in[insn_addr].copy()
                    live_in[insn_addr] = (live_out[insn_addr] - simd_regs_write).union(simd_regs_read)
                    
                    # Check if anything changed
                    if live_in[insn_addr] != old_live_in or live_out[insn_addr] != old_live_out:
                        changed = True
                        instructions_changed += 1
                        
                        if iteration <= 3 and instructions_changed <= 5:  # Show first few changes
                            print(f"  Changed: 0x{insn_addr:x} {insn['mnemonic']} {insn['operands']}")
                            print(f"    Live-in: {old_live_in} -> {live_in[insn_addr]}")
                            print(f"    Live-out: {old_live_out} -> {live_out[insn_addr]}")
                            print(f"    Read: {simd_regs_read}, Write: {simd_regs_write}")
            
            if iteration <= 3:
                print(f"  Instructions changed: {instructions_changed}")
        
        print(f"\n=== DEBUG: Liveness Analysis Complete ===")
        print(f"Total iterations: {iteration}")
        print(f"Converged: {not changed}")
        
        # Show final liveness for first few instructions
        print(f"\nFinal liveness for first 5 instructions:")
        for i, insn in enumerate(simd_instructions[:5]):
            insn_addr = insn['address'] + base_offset  # Normalize address
            print(f"  0x{insn_addr:x} {insn['mnemonic']} {insn['operands']}")
            print(f"    Live-in: {live_in[insn_addr]}")
            print(f"    Live-out: {live_out[insn_addr]}")
        
        return {
            'live_in': live_in,
            'live_out': live_out,
            'simd_regs': simd_regs,
            'insn_to_block': insn_to_block,
            'block_to_insns': block_to_insns,
            'function_calls': function_calls,
            'function_args': function_args
        }
    
    def _detect_function_calls(self, simd_instructions: List[Dict], basic_blocks: List[Dict]) -> Dict:
        """Detect function call instructions and model their SIMD register effects."""
        function_calls = {}
        
        # Get all instructions (not just SIMD ones) to find call instructions
        all_instructions = []
        
        # Read the entire .text section to find all instructions
        try:
            code_section = self.elf_file.get_section_by_name('.text')
            if not code_section:
                return function_calls
            
            code = code_section.data()
            
            # Disassemble the entire .text section
            for insn in self.cs.disasm(code, 0x401000):  # Start at typical static binary base
                all_instructions.append({
                    'address': insn.address,
                    'mnemonic': insn.mnemonic,
                    'operands': insn.op_str,
                    'regs_read': [self.cs.reg_name(reg) for reg in insn.regs_read] if insn.regs_read else [],
                    'regs_write': [self.cs.reg_name(reg) for reg in insn.regs_write] if insn.regs_write else []
                })
        except Exception as e:
            print(f"Warning: Could not disassemble .text section: {e}")
            return function_calls
        
        # Find call instructions
        for insn in all_instructions:
            if insn['mnemonic'] == 'call':
                call_addr = insn['address']
                
                # Model function call effects on SIMD registers
                # For now, we'll use conservative assumptions:
                # - XMM0-XMM7 can be used for arguments (SysV ABI)
                # - XMM0 can be used for return values
                # - All XMM registers are caller-saved (can be clobbered)
                
                # This is a simplified model - in practice, we'd need to analyze
                # the called function to determine exact argument/return usage
                function_calls[call_addr] = {
                    'args': set(),  # Will be filled by argument detection
                    'returns': {'xmm0'},  # Conservative: assume XMM0 might be returned
                    'clobbered': set()  # All XMM registers are caller-saved
                }
        
        return function_calls
    
    def _detect_function_arguments(self, simd_instructions: List[Dict], basic_blocks: List[Dict]) -> Dict:
        """Detect SIMD registers used as function arguments (used without being loaded first)."""
        function_args = {}
        
        # Build a mapping of all instructions in each basic block
        block_instructions = {}
        for block in basic_blocks:
            block_addr = block['address']
            block_size = block['size']
            block_end = block_addr + block_size
            
            block_insns = []
            for insn in simd_instructions:
                insn_addr = insn['address']
                if block_addr <= insn_addr < block_end:
                    block_insns.append(insn)
            
            # Sort by address
            block_insns.sort(key=lambda x: x['address'])
            block_instructions[block_addr] = block_insns
        
        # For each basic block, analyze SIMD register usage patterns
        for block_addr, block_insns in block_instructions.items():
            if not block_insns:
                continue
            
            # Track which SIMD registers have been loaded in this block
            loaded_regs = set()
            
            for insn in block_insns:
                insn_addr = insn['address']
                regs_read = set(insn.get('regs_read', []))
                regs_write = set(insn.get('regs_write', []))
                
                # Filter to SIMD registers
                simd_regs_read = regs_read.intersection({f'xmm{i}' for i in range(32)})
                simd_regs_write = regs_write.intersection({f'xmm{i}' for i in range(32)})
                
                # Check for registers used without being loaded first
                unloaded_reads = simd_regs_read - loaded_regs
                
                if unloaded_reads:
                    # These registers are likely function arguments
                    function_args[insn_addr] = unloaded_reads
                
                # Update loaded registers
                loaded_regs.update(simd_regs_write)
        
        return function_args
    
    def _get_instruction_successors(self, insn_addr: int, block_insns: List[Dict], 
                                  block_edges: Dict, block_to_insns: Dict, 
                                  insn_to_block: Dict, base_offset: int) -> List[int]:
        """Get the successors of an instruction based on CFG edges."""
        successors = []
        
        # Find the position of this instruction in the block
        insn_index = -1
        for i, insn in enumerate(block_insns):
            if insn['address'] + base_offset == insn_addr:  # Compare normalized addresses
                insn_index = i
                break
        
        if insn_index == -1:
            return successors
        
        # If this is not the last instruction in the block, next instruction is successor
        if insn_index < len(block_insns) - 1:
            next_insn = block_insns[insn_index + 1]
            successors.append(next_insn['address'] + base_offset)  # Return normalized address
        
        # If this is the last instruction in the block, check CFG edges
        elif insn_index == len(block_insns) - 1:
            # This is the last instruction in the block
            block_addr = insn_to_block.get(insn_addr)
            if block_addr and block_addr in block_edges:
                # Get successors of this block
                block_successors = block_edges[block_addr]
                for succ_block_addr in block_successors:
                    if succ_block_addr in block_to_insns:
                        succ_block_insns = block_to_insns[succ_block_addr]
                        if succ_block_insns:
                            # First instruction of successor block
                            successors.append(succ_block_insns[0]['address'] + base_offset)
        
        return successors
    
    def _identify_session_boundaries(self, simd_instructions: List[Dict], liveness_info: Dict, base_offset: int) -> List[Dict]:
        """Identify AVX session start and end boundaries with function call handling."""
        print(f"\n=== DEBUG: Identifying Session Boundaries ===")
        print(f"SIMD instructions: {len(simd_instructions)}")
        
        sessions = []
        live_in = liveness_info['live_in']
        live_out = liveness_info['live_out']
        function_calls = liveness_info.get('function_calls', {})
        function_args = liveness_info.get('function_args', {})
        
        print(f"Live-in entries: {len(live_in)}")
        print(f"Live-out entries: {len(live_out)}")
        print(f"Function calls: {len(function_calls)}")
        print(f"Function args: {len(function_args)}")
        
        # Show first few live-in/live-out entries
        print(f"\nFirst 5 live-in entries:")
        for i, (addr, live_regs) in enumerate(list(live_in.items())[:5]):
            print(f"  {i}: 0x{addr:x} -> {live_regs}")
        
        print(f"\nFirst 5 live-out entries:")
        for i, (addr, live_regs) in enumerate(list(live_out.items())[:5]):
            print(f"  {i}: 0x{addr:x} -> {live_regs}")
        
        # Create a combined list of SIMD instructions and function calls
        all_instructions = []
        
        # Add all SIMD instructions
        for insn in simd_instructions:
            all_instructions.append({
                'address': insn['address'],
                'mnemonic': insn['mnemonic'],
                'operands': insn['operands'],
                'is_simd': True,
                'instruction': insn
            })
        
        # Add function calls as special instructions
        for call_addr, call_info in function_calls.items():
            all_instructions.append({
                'address': call_addr,
                'mnemonic': 'call',
                'operands': f'0x{call_addr:x}',
                'is_simd': False,
                'call_info': call_info
            })
        
        # Sort all instructions by address
        all_instructions.sort(key=lambda x: x['address'])
        
        print(f"\nProcessing {len(all_instructions)} instructions for session detection...")
        
        current_session = None
        
        for i, insn in enumerate(all_instructions):
            insn_addr = insn['address'] + base_offset  # Normalize address
            
            # Debug session start detection for first few instructions
            if i < 5:
                live_in_regs = live_in.get(insn_addr, set())
                live_out_regs = live_out.get(insn_addr, set())
                is_function_arg = insn_addr in function_args
                should_start = current_session is None and (live_in_regs or live_out_regs or is_function_arg)
                print(f"  Instruction {i}: 0x{insn_addr:x} {insn['mnemonic']} {insn['operands']}")
                print(f"    Live-in: {live_in_regs}")
                print(f"    Live-out: {live_out_regs}")
                print(f"    Function arg: {is_function_arg}")
                print(f"    Current session: {current_session is not None}")
                print(f"    Should start session: {should_start}")
            
            # Check if we're starting a new session
            # Session starts when:
            # 1. We have live registers coming in (live_in is non-empty), OR
            # 2. We create live registers (live_out is non-empty but live_in is empty), OR
            # 3. We detect function arguments (registers used without being loaded first)
            if current_session is None and (live_in.get(insn_addr, set()) or live_out.get(insn_addr, set()) or insn_addr in function_args):
                # Determine which registers are live for this session
                live_registers = live_in.get(insn_addr, set()) if live_in.get(insn_addr, set()) else live_out.get(insn_addr, set())
                
                # Add function arguments to live registers
                if insn_addr in function_args:
                    live_registers.update(function_args[insn_addr])
                
                # Session start: first instruction with live SIMD registers
                current_session = {
                    'start_address': insn_addr,
                    'start_instruction': insn['instruction'] if insn['is_simd'] else {
                        'address': insn_addr,
                        'mnemonic': insn['mnemonic'],
                        'operands': insn['operands']
                    },
                    'end_address': None,
                    'end_instruction': None,
                    'live_registers': list(live_registers),
                    'instructions': [insn['instruction'] if insn['is_simd'] else {
                        'address': insn_addr,
                        'mnemonic': insn['mnemonic'],
                        'operands': insn['operands']
                    }]
                }
            
            # If we're in a session, add this instruction
            elif current_session is not None:
                # Add instruction to session
                if insn['is_simd']:
                    current_session['instructions'].append(insn['instruction'])
                else:
                    # Add function call as a special instruction
                    current_session['instructions'].append({
                        'address': insn_addr,
                        'mnemonic': insn['mnemonic'],
                        'operands': insn['operands']
                    })
                
                # Update live registers if function arguments are detected
                if insn_addr in function_args:
                    current_session['live_registers'].extend(function_args[insn_addr])
                    # Remove duplicates
                    current_session['live_registers'] = list(set(current_session['live_registers']))
                
                # Check if session should end
                # Exception: if this is a function call, continue the session
                if not live_out.get(insn_addr, set()) and insn_addr not in function_calls:
                    # Session end: no live registers after this instruction
                    current_session['end_address'] = insn_addr
                    current_session['end_instruction'] = insn['instruction'] if insn['is_simd'] else {
                        'address': insn_addr,
                        'mnemonic': insn['mnemonic'],
                        'operands': insn['operands']
                    }
                    sessions.append(current_session)
                    current_session = None
        
        # Handle case where session extends to end of function
        if current_session is not None:
            current_session['end_address'] = all_instructions[-1]['address']
            current_session['end_instruction'] = all_instructions[-1]['instruction'] if all_instructions[-1]['is_simd'] else {
                'address': all_instructions[-1]['address'],
                'mnemonic': all_instructions[-1]['mnemonic'],
                'operands': all_instructions[-1]['operands']
            }
            sessions.append(current_session)

        print(f"\nSession detection complete: {len(sessions)} sessions found")
        for i, session in enumerate(sessions):
            print(f"  Session {i}: 0x{session['start_address']:x} - 0x{session['end_address']:x}")
            print(f"    Live registers: {session['live_registers']}")
            print(f"    Instructions: {len(session['instructions'])}")

        return sessions
    
    def generate_metadata(self) -> Dict:
        """Generate metadata containing only AVX session data."""
        metadata = {
            'avx_sessions': {},
            'analysis_info': {
                'binary_path': str(self.binary_path),
                'total_modules': len(self.libraries),
                'total_avx_sessions': sum(len(sessions) for sessions in self.avx_sessions.values()),
                'addressing_mode': 'relative',  # All addresses are relative to module base
                'note': 'All addresses are relative to module base. Runtime must add actual base addresses from /proc/pid/maps.'
            }
        }
        
        # Add AVX sessions for each module
        for module_path, sessions in self.avx_sessions.items():
            module_key = os.path.basename(module_path)
            metadata['avx_sessions'][module_key] = sessions
        
        return metadata
    
    def run_recall_test(self, module_name: str) -> Dict:
        """Run recall test to identify SIMD instructions not covered by AVX sessions."""
        print(f"\n=== Running Recall Test for {module_name} ===")
        
        # Get all SIMD instructions for this module
        # Find the correct key in simd_instructions (might be full path)
        module_key = None
        for key in self.simd_instructions.keys():
            if os.path.basename(key) == module_name:
                module_key = key
                break
        
        if module_key is None:
            print(f"Warning: Could not find SIMD instructions for module {module_name}")
            return {}
        
        all_simd_instructions = self.simd_instructions.get(module_key, [])
        avx_sessions = self.avx_sessions.get(module_key, [])
        
        print(f"Total SIMD instructions: {len(all_simd_instructions)}")
        print(f"Total AVX sessions: {len(avx_sessions)}")
        
        # Build maps for efficient lookup
        # Map: instruction_address -> instruction_info
        simd_instruction_map = {insn['address']: insn for insn in all_simd_instructions}
        
        # Map: session_address_range -> session_info
        session_ranges = []
        for session in avx_sessions:
            start_addr = session['start_address']
            end_addr = session['end_address']
            session_ranges.append((start_addr, end_addr, session))
        
        # Sort session ranges by start address for efficient lookup
        session_ranges.sort(key=lambda x: x[0])
        
        # Find uncovered SIMD instructions
        uncovered_instructions = []
        
        for insn_addr, insn_info in simd_instruction_map.items():
            # Check if this instruction is covered by any AVX session
            covered = False
            
            for start_addr, end_addr, session in session_ranges:
                if start_addr <= insn_addr <= end_addr:
                    # Check if this instruction is actually in the session's instruction list
                    session_insn_addrs = {insn['address'] for insn in session['instructions']}
                    if insn_addr in session_insn_addrs:
                        covered = True
                        break
            
            if not covered:
                uncovered_instructions.append(insn_info)
        
        print(f"Uncovered SIMD instructions: {len(uncovered_instructions)}")
        
        # Analyze uncovered instructions by function
        uncovered_by_function = {}
        for insn in uncovered_instructions:
            # Try to determine which function this instruction belongs to
            func_name = self._find_function_for_instruction(insn['address'], module_key)
            if func_name not in uncovered_by_function:
                uncovered_by_function[func_name] = []
            uncovered_by_function[func_name].append(insn)
        
        # Generate detailed analysis
        recall_results = {
            'module_name': module_name,
            'total_simd_instructions': len(all_simd_instructions),
            'total_avx_sessions': len(avx_sessions),
            'uncovered_instructions': len(uncovered_instructions),
            'coverage_percentage': ((len(all_simd_instructions) - len(uncovered_instructions)) / len(all_simd_instructions) * 100) if all_simd_instructions else 100,
            'uncovered_by_function': {}
        }
        
        # Detailed analysis of uncovered instructions
        for func_name, func_insns in uncovered_by_function.items():
            recall_results['uncovered_by_function'][func_name] = {
                'count': len(func_insns),
                'instructions': func_insns
            }
            
            print(f"\nFunction {func_name}: {len(func_insns)} uncovered instructions")
            for insn in func_insns[:5]:  # Show first 5
                print(f"  0x{insn['address']:08x} {insn['mnemonic']} {insn['operands']}")
            if len(func_insns) > 5:
                print(f"  ... and {len(func_insns) - 5} more")
        
        return recall_results
    
    def _find_function_for_instruction(self, insn_addr: int, module_name: str) -> str:
        """Find which function contains the given instruction address."""
        # Use CFG data to find the function
        cfg_data = self.cfg_data.get(module_name, {})
        functions = cfg_data.get('functions', [])
        
        for func in functions:
            if isinstance(func, dict):
                func_addr = func.get('address', 0)
                func_size = func.get('size', 0)
                if func_addr <= insn_addr < func_addr + func_size:
                    return func.get('name', f'func_0x{func_addr:x}')
            elif isinstance(func, int):
                # Handle case where functions is a list of addresses
                func_addr = func
                if func_addr <= insn_addr < func_addr + 0x1000:  # Assume 4KB function size
                    return f'func_0x{func_addr:x}'
        
        return f'unknown_func_0x{insn_addr:x}'
    
    def save_metadata(self, output_file: str = None) -> str:
        """Save metadata to a JSON file for runtime use."""
        import json
        
        if output_file is None:
            # Use just the filename to avoid permission issues
            output_file = f"{self.binary_path.name}.avxdump.json"
        
        metadata = self.generate_metadata()
        
        with open(output_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Metadata saved to: {output_file}")
        return output_file
    
    def print_summary(self):
        """Print a summary of discovered modules, SIMD instructions, and CFG data."""
        print("\n=== Analysis Summary ===")
        print(f"Total modules discovered: {len(self.libraries)}")
        
        total_simd = sum(len(instructions) for instructions in self.simd_instructions.values())
        print(f"Total SIMD instructions found: {total_simd}")
        
        total_functions = sum(len(cfg.get('functions', {})) for cfg in self.cfg_data.values())
        total_basic_blocks = sum(len(cfg.get('basic_blocks', {})) for cfg in self.cfg_data.values())
        print(f"Total functions analyzed: {total_functions}")
        print(f"Total basic blocks analyzed: {total_basic_blocks}")
        
        # Add simple mode information if available
        if hasattr(self, 'simple_mode_functions_with_simd') and self.simple_mode_functions_with_simd:
            total_functions_with_simd = sum(functions_with_simd for functions_with_simd in self.simple_mode_functions_with_simd.values())
            print(f"Functions identified as AVX sessions (simple mode): {total_functions_with_simd}")
        
        print("Note: All addresses are relative to module base for static analysis")
        print("Runtime reconstruction requires adding actual base addresses from /proc/pid/maps")
        print()
        
        for module_path, info in self.libraries.items():
            module_type = info['type']
            simd_count = len(self.simd_instructions.get(module_path, []))
            cfg_info = self.cfg_data.get(module_path, {})
            func_count = len(cfg_info.get('functions', {}))
            block_count = len(cfg_info.get('basic_blocks', {}))
            
            if module_type == 'main_binary':
                print(f"Main Binary: {module_path}")
                print(f"  Type: {info.get('binary_type', 'unknown')}")
                print(f"  Entry Point: 0x{info.get('entry_point', 0):x}")
            else:
                lib_name = info.get('name', 'unknown')
                print(f"Library: {lib_name}")
                print(f"  Type: {info['type']}")
                print(f"  Entry Point: 0x{info.get('entry_point', 0):x}")
            
            print(f"  Path: {info['path']}")
            print(f"  SIMD Instructions: {simd_count}")
            print(f"  Functions: {func_count}")
            print(f"  Basic Blocks: {block_count}")
            
            analysis_status = 'Success' if cfg_info.get('analysis_success', False) else 'Failed'
            analysis_method = cfg_info.get('analysis_method', 'unknown')
            print(f"  CFG Analysis: {analysis_status} ({analysis_method})")
            
            if cfg_info.get('error_details'):
                print(f"  Error: {cfg_info['error_details'][:100]}...")
            print()
    
    def run_analysis(self, save_metadata: bool = True, force: bool = False, binary_only: bool = False, simple_mode: bool = False) -> bool:
        """Run the complete analysis with enhanced workflow."""
        print(f"Starting AVX session analysis for: {self.binary_path}")
        
        # Determine target type
        target_type = self.get_target_type()
        print(f"Target type: {target_type}")
        
        # Check if metadata already exists
        if not force and self.metadata_exists():
            print(f"Metadata file {self.get_metadata_filename()} already exists.")
            print("Use -f/--force to overwrite existing metadata.")
            return True
        
        if not self.validate_binary():
            return False
        
        if not self.open_binary():
            return False
        
        if target_type == 'library':
            # Library-only analysis
            print("Performing library-only analysis...")
            return self._analyze_library_only(save_metadata, simple_mode)
        else:
            # Binary analysis with dependencies
            print("Performing binary analysis with dependencies...")
            return self._analyze_binary_with_deps(save_metadata, force, binary_only, simple_mode)
    
    def _analyze_library_only(self, save_metadata: bool, simple_mode: bool = False) -> bool:
        """Analyze a single library."""
        # Add the library itself to the libraries dict
        lib_info = self.get_library_info(str(self.binary_path))
        if lib_info:
            self.libraries[str(self.binary_path)] = {
                'path': str(self.binary_path),
                'type': 'library',
                'name': self.binary_path.name,
                'entry_point': lib_info['entry_point']
            }
        
        if not self.analyze_simd_instructions():
            print("Warning: No SIMD instructions found")
        
        # Always do CFG analysis - we need function boundaries for both modes
        if not self.analyze_cfg():
            print("Warning: CFG analysis failed")
        
        # Choose analysis method
        if simple_mode:
            if not self.analyze_simd_simple():
                print("Warning: Simple AVX session analysis failed")
        else:
            if not self.analyze_simd_liveness():
                print("Warning: Liveness analysis failed")
        
        self.print_summary()
        
        if save_metadata:
            self.save_metadata()
        
        return True
    
    def _analyze_binary_with_deps(self, save_metadata: bool, force: bool, binary_only: bool = False, simple_mode: bool = False) -> bool:
        """Analyze binary with dependencies, optionally skipping dependency analysis."""
        if not self.analyze_dependencies():
            print("Error: Failed to analyze dependencies")
            return False
        
        if binary_only:
            print("Binary-only mode: Skipping dependency analysis")
            # Remove all dependencies from analysis, keep only the main binary
            main_binary_path = str(self.binary_path)
            if main_binary_path in self.libraries:
                # Keep only the main binary
                main_binary_info = self.libraries[main_binary_path]
                self.libraries = {main_binary_path: main_binary_info}
                
                # Remove SIMD instructions and CFG data for dependencies
                if main_binary_path in self.simd_instructions:
                    main_simd = self.simd_instructions[main_binary_path]
                    self.simd_instructions = {main_binary_path: main_simd}
                else:
                    self.simd_instructions = {}
                
                if main_binary_path in self.cfg_data:
                    main_cfg = self.cfg_data[main_binary_path]
                    self.cfg_data = {main_binary_path: main_cfg}
                else:
                    self.cfg_data = {}
        
        if not self.analyze_simd_instructions():
            print("Warning: No SIMD instructions found")
        
        # Always do CFG analysis - we need function boundaries for both modes
        if not self.analyze_cfg():
            print("Warning: CFG analysis failed for some modules")
        
        # Choose analysis method
        if simple_mode:
            if not self.analyze_simd_simple():
                print("Warning: Simple AVX session analysis failed")
        else:
            if not self.analyze_simd_liveness():
                print("Warning: Liveness analysis failed")
        
        self.print_summary()
        
        if save_metadata:
            self.save_metadata()
        
        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AVX Session Analysis Tool - Steps 1-3: Binary Discovery, SIMD Analysis, and CFG Building",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool analyzes ELF binaries and libraries, performing the first three steps of AVX/SSE session analysis:
1. Discovers the target and its dependencies (for binaries)
2. Identifies SIMD instructions using Capstone disassembly  
3. Builds control flow graphs using angr CFGFast analysis

Workflow:
- For binaries: Analyzes the binary and all its dependencies
- For libraries: Analyzes only the library itself
- Skips analysis if metadata file already exists (use -f to force)
- Use -b to analyze only the main binary (skip dependencies)
- Use -s for simple function-based AVX session detection (faster, less precise)

Example usage:
  python3 avxdump.py /usr/bin/ls                    # Analyze binary with dependencies
  python3 avxdump.py /lib/x86_64-linux-gnu/libc.so.6  # Analyze library only
  python3 avxdump.py -f /usr/bin/ls                 # Force overwrite existing metadata
  python3 avxdump.py -b /usr/bin/cat                # Analyze only main binary (fast)
  python3 avxdump.py -s /usr/bin/ls                 # Use simple AVX session detection
        """
    )
    
    parser.add_argument('target_path', 
                       help='Path to the ELF binary or library to analyze')
    
    parser.add_argument('-f', '--force', action='store_true',
                       help='Force analysis even if metadata file already exists')
    
    parser.add_argument('-b', '--binary-only', action='store_true',
                       help='For binaries: analyze only the main binary, skip dependencies')
    
    parser.add_argument('-r', '--recall-test', action='store_true',
                       help='Run recall test to identify uncovered SIMD instructions')
    
    parser.add_argument('--no-metadata', action='store_true',
                       help='Skip saving metadata JSON file')
    
    parser.add_argument('-s', '--simple', action='store_true',
                       help='Use simple AVX session detection (function-based) instead of complex liveness analysis')
    
    args = parser.parse_args()
    
    # Create analyzer and run analysis
    analyzer = BinaryAnalyzer(args.target_path)
    
    success = analyzer.run_analysis(save_metadata=not args.no_metadata, force=args.force, binary_only=args.binary_only, simple_mode=args.simple)
    
    if success:
        print("Analysis completed successfully!")
        
        # Run recall test if requested
        if args.recall_test:
            print("\n" + "="*60)
            print("RUNNING RECALL TEST")
            print("="*60)
            
            # Run recall test for each analyzed module
            for module_path in analyzer.libraries.keys():
                module_name = os.path.basename(module_path)
                recall_results = analyzer.run_recall_test(module_name)
                
                # Save recall test results
                recall_file = f"{module_name}.recall_test.json"
                import json
                with open(recall_file, 'w') as f:
                    json.dump(recall_results, f, indent=2)
                print(f"Recall test results saved to: {recall_file}")
        
        return 0
    else:
        print("Analysis failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
