#!/usr/bin/env python3
"""
AVX Session Analysis Tool - Step 1: Binary and Library Discovery

This script implements the first step of static analysis for AVX/SSE usage sessions
in x86_64 ELF binaries. It discovers the main binary and all its dependencies,
gathering their load addresses for subsequent analysis.

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


class BinaryAnalyzer:
    """Analyzes ELF binaries and their dependencies."""
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.binary_file = None
        self.libraries = {}  # Dict[str, Dict] - library name -> info dict
        
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
            self.binary_file = ELFFile(open(self.binary_path, 'rb'))
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
            dynamic_section = self.binary_file.get_section_by_name('.dynamic')
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
            entry_point = self.binary_file.header.e_entry
            
            # Check if it's a PIE binary
            if self.binary_file.header.e_type == 'ET_DYN':
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
    
    def generate_metadata(self) -> Dict:
        """Generate metadata for runtime reconstruction of AVX sessions."""
        metadata = {
            'modules': {},
            'analysis_info': {
                'binary_path': str(self.binary_path),
                'total_modules': len(self.libraries),
                'addressing_mode': 'relative',  # All addresses are relative to module base
                'note': 'All addresses are relative to module base. Runtime must add actual base addresses from /proc/pid/maps.'
            }
        }
        
        for module_path, info in self.libraries.items():
            module_key = os.path.basename(module_path)
            module_info = {
                'path': info['path'],
                'type': info['type'],
                'name': info.get('name', module_key)
            }
            
            # Add binary-specific info
            if info['type'] == 'main_binary':
                module_info['binary_type'] = info.get('binary_type', 'unknown')
                module_info['entry_point'] = info.get('entry_point', 0)
            else:
                module_info['entry_point'] = info.get('entry_point', 0)
            
            metadata['modules'][module_key] = module_info
        
        return metadata
    
    def save_metadata(self, output_file: str = None) -> str:
        """Save metadata to a JSON file for runtime use."""
        import json
        
        if output_file is None:
            output_file = f"{self.binary_path}.avxdump.json"
        
        metadata = self.generate_metadata()
        
        with open(output_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Metadata saved to: {output_file}")
        return output_file
    
    def print_summary(self):
        """Print a summary of discovered modules."""
        print("\n=== Analysis Summary ===")
        print(f"Total modules discovered: {len(self.libraries)}")
        print("Note: All addresses are relative to module base for static analysis")
        print("Runtime reconstruction requires adding actual base addresses from /proc/pid/maps")
        print()
        
        for module_path, info in self.libraries.items():
            module_type = info['type']
            
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
            print()
    
    def run_analysis(self, save_metadata: bool = True) -> bool:
        """Run the complete analysis."""
        print(f"Starting AVX session analysis for: {self.binary_path}")
        
        if not self.validate_binary():
            return False
        
        if not self.open_binary():
            return False
        
        if not self.analyze_dependencies():
            print("Error: Failed to analyze dependencies")
            return False
        
        self.print_summary()
        
        if save_metadata:
            self.save_metadata()
        
        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AVX Session Analysis Tool - Step 1: Binary and Library Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool analyzes ELF binaries and discovers all their dependencies,
gathering load addresses for subsequent AVX/SSE session analysis.

Example usage:
  python3 avxdump.py /usr/bin/ls
  python3 avxdump.py ./my_program
        """
    )
    
    parser.add_argument('binary_path', 
                       help='Path to the ELF binary to analyze')
    
    parser.add_argument('--no-metadata', action='store_true',
                       help='Skip saving metadata JSON file')
    
    args = parser.parse_args()
    
    # Create analyzer and run analysis
    analyzer = BinaryAnalyzer(args.binary_path)
    
    success = analyzer.run_analysis(save_metadata=not args.no_metadata)
    
    if success:
        print("Analysis completed successfully!")
        return 0
    else:
        print("Analysis failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
