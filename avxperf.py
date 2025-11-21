#!/usr/bin/env python3

import argparse
import json
import sys
import csv
from collections import defaultdict

def parse_arguments():
    parser = argparse.ArgumentParser(description="Parse funcdump and perf script.")
    parser.add_argument("-f", "--funcdump", required=True, help="Path to funcdump.json file")
    parser.add_argument("-p", "--perf", required=True, help="Path to perf script file")
    parser.add_argument("-o", "--output", help="Path to output CSV file")
    return parser.parse_args()

def load_funcdump(filepath):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        # Create a mapping from function name to num_simd_insns
        func_map = {}
        if "functions" in data:
            for func in data["functions"]:
                name = func.get("name")
                simd_insns = func.get("num_simd_insns")
                if name:
                    func_map[name] = simd_insns
        return func_map
    except Exception as e:
        print(f"Error reading funcdump file: {e}", file=sys.stderr)
        sys.exit(1)

def parse_perf_script(filepath):
    func_counts = defaultdict(int)
    total_rows = 0
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    # Field 1: IP (index 0)
                    # Field 2: Function Name (index 1)
                    # Field 3: DSO Name (index 2 onwards?)
                    # The DSO name is wrapped in parenthesis, e.g., (/lib/...)
                    
                    # Note: Function names might arguably contain spaces in some perf outputs, 
                    # but user specified "three fields seperated by whitespace".
                    # We'll assume function name is the second token.
                    
                    func_name = parts[1]
                    func_counts[func_name] += 1
                    total_rows += 1
                    
        return func_counts, total_rows
    except Exception as e:
        print(f"Error reading perf script file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    args = parse_arguments()
    
    # 1. Parse funcdump.json
    func_simd_map = load_funcdump(args.funcdump)
    
    # 2. Parse perf script
    func_counts, total_rows = parse_perf_script(args.perf)
    
    if total_rows == 0:
        print("No data found in perf script.")
        return

    # 3. Cross reference and prepare data
    results = []
    zero_simd_occurrences = 0
    
    for func_name, count in func_counts.items():
        simd_insns = func_simd_map.get(func_name, "N/A")
        percentage = (count / total_rows) * 100
        
        results.append({
            "name": func_name,
            "occurrences": count,
            "percentage": percentage,
            "num_simd_insns": simd_insns
        })
        
        if simd_insns != "N/A" and simd_insns == 0:
            zero_simd_occurrences += count

    # 4. Sort by occurrences (descending)
    results.sort(key=lambda x: x["occurrences"], reverse=True)
    
    # 5. Print sorted list
    # Using a fixed width format for better readability
    # Name | Occurrences | Percentage | Num SIMD Insns
    print(f"{'Function Name':<60} {'Occur':<10} {'%':<10} {'SIMD Insns'}")
    print("-" * 95)
    
    for r in results:
        print(f"{r['name']:<60} {r['occurrences']:<10} {r['percentage']:.2f}%    {r['num_simd_insns']}")

    # 6. Print summary
    zero_simd_percentage = (zero_simd_occurrences / total_rows) * 100
    print("-" * 95)
    print(f"Total samples free of SIMD Insns: {zero_simd_occurrences} ({zero_simd_percentage:.2f}%)")

    # 7. Write to CSV if requested
    if args.output:
        try:
            with open(args.output, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Header
                writer.writerow(["Function Name", "Occurrences", "Percentage", "Num SIMD Insns"])
                
                # Data rows
                for r in results:
                    writer.writerow([r["name"], r["occurrences"], f"{r['percentage']:.2f}%", r["num_simd_insns"]])
                
                # Summary row
                # "convert the summary line to "num_simd_insns=0" with the sum occurrences and percentage"
                # append it as the last row
                writer.writerow(["num_simd_insns=0", zero_simd_occurrences, f"{zero_simd_percentage:.2f}%", 0])
                
            print(f"CSV output written to {args.output}")
        except Exception as e:
            print(f"Error writing CSV output: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
