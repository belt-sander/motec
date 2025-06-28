#!/usr/bin/env python3

import sys
import argparse
import re

def detect_file_type(filepath):
    """
    Detects the CAN log file format by inspecting the first few non-empty lines.
    Recognizes: 'trc', 'candump_asc', and 'vector_asc'.
    """
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            for _ in range(50):
                line = f.readline()
                if not line: break
                stripped_line = line.strip()
                if not stripped_line: continue

                # Order of checks is important
                if stripped_line.startswith(';'): return 'trc'
                if stripped_line.startswith('('): return 'candump_asc'

                # Check for Vector/MoTeC style: line starts with a float timestamp
                parts = stripped_line.split()
                if len(parts) >= 6:
                    try:
                        float(parts[0])
                        # If the first part is a float and it's not one of the other formats,
                        # it's very likely the Vector/MoTeC format.
                        return 'vector_asc'
                    except ValueError:
                        continue # Not a float, so it's a header line or other format
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error during file type detection: {e}", file=sys.stderr)
        return None


def calculate_frame_bits(dlc, is_extended_id):
    """Calculates the total bits for a CAN frame including worst-case bit stuffing."""
    if is_extended_id:
        overhead_bits = 64
        stuff_check_bits = 34 + (dlc * 8) + 15
    else:
        overhead_bits = 44
        stuff_check_bits = 12 + 6 + (dlc * 8) + 15
    data_bits = dlc * 8
    stuff_bits = stuff_check_bits // 4
    return overhead_bits + data_bits + stuff_bits


def analyze_can_log(filepath, file_type):
    """Parses a CAN log file to gather statistics on each CAN ID."""
    can_id_data = {}
    first_ts, last_ts = None, None
    line_number = 0

    try:
        with open(filepath, 'r', encoding='utf-8-sig') as file:
            for line in file:
                line_number += 1
                line = line.strip()
                if not line: continue

                try:
                    timestamp, can_id_hex, dlc = None, None, None
                    parts = line.split()

                    if file_type == 'trc':
                        if line.startswith(';'): continue
                        if len(parts) < 5 or not parts[0].endswith(')'): continue
                        timestamp = float(parts[1]) / 1000.0
                        can_id_hex = parts[3]
                        dlc = int(parts[4])

                    elif file_type == 'candump_asc':
                        if not line.startswith('(') or len(parts) < 3: continue
                        timestamp = float(parts[0].strip('()'))
                        can_id_hex = parts[2].split('#')[0]
                        if '#' in parts[2]: dlc = len(parts[2].split('#')[1]) // 2
                        elif len(parts) > 3 and parts[3].startswith('['): dlc = int(re.search(r'\[(\d+)\]', parts[3]).group(1))
                        else: dlc = 0
                    
                    elif file_type == 'vector_asc':
                        if len(parts) < 6: continue
                        # The first element must be a float timestamp, otherwise it's a header
                        try:
                            timestamp = float(parts[0])
                        except ValueError:
                            continue
                        can_id_hex = parts[2].rstrip('x') # Handle the 'x' for extended IDs
                        dlc = int(parts[5])

                    if timestamp is None: continue

                    can_id = int(can_id_hex, 16)
                    is_extended = can_id > 0x7FF or (file_type == 'vector_asc' and parts[2].endswith('x'))

                    if first_ts is None: first_ts = timestamp
                    last_ts = timestamp

                    frame_bits = calculate_frame_bits(dlc, is_extended)
                    
                    if can_id in can_id_data:
                        can_id_data[can_id]['count'] += 1
                        can_id_data[can_id]['total_bits'] += frame_bits
                        can_id_data[can_id]['last_timestamp'] = timestamp
                    else:
                        can_id_data[can_id] = {'count': 1, 'total_bits': frame_bits, 'first_timestamp': timestamp, 'last_timestamp': timestamp}

                except (ValueError, IndexError, TypeError) as e:
                    print(f"[Warning] Skipping malformed line {line_number}: '{line}'. Reason: {e}", file=sys.stderr)
                    continue
    except Exception as e:
        print(f"An unexpected error occurred while processing the file: {e}", file=sys.stderr)
        sys.exit(1)

    return can_id_data, first_ts, last_ts


def calculate_bus_load(total_bits, duration, bit_rate_mbps):
    if duration <= 0: return 0.0
    total_possible_bits = bit_rate_mbps * 1e6 * duration
    return (total_bits / total_possible_bits) * 100


def print_can_id_packets(filepath, file_type, target_can_id):
    """Prints all packets for a specific CAN ID from a log file."""
    try:
        target_id_int = int(target_can_id, 16)
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            for line in f:
                try:
                    parts = line.strip().split()
                    if not parts: continue
                    line_can_id_hex = None
                    if file_type == 'trc' and not line.strip().startswith(';') and len(parts) >= 4 and parts[0].endswith(')'):
                        line_can_id_hex = parts[3]
                    elif file_type == 'candump_asc' and line.strip().startswith('(') and len(parts) >= 3:
                        line_can_id_hex = parts[2].split('#')[0]
                    elif file_type == 'vector_asc' and len(parts) >= 6:
                        try:
                            float(parts[0]) # Is it a data line?
                            line_can_id_hex = parts[2].rstrip('x')
                        except ValueError:
                            continue

                    if line_can_id_hex and int(line_can_id_hex, 16) == target_id_int:
                        sys.stdout.write(line)
                except (ValueError, IndexError): continue
    except Exception as e:
        print(f"Could not filter for ID {target_can_id}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Process and analyze CAN bus data from .asc or .trc files.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('filepath', help='Path to the CAN bus data file (.asc or .trc)')
    parser.add_argument('-id', '--target_can_id', help='Optional: Target CANId (in hex) to filter and print')
    parser.add_argument('-b', '--bit_rate', type=float, default=1.0, help='CAN bus bit rate in Mbps (default: 1.0)')

    args = parser.parse_args()

    file_type = detect_file_type(args.filepath)
    if file_type is None:
        print(f"Error: Could not determine file type for '{args.filepath}'.", file=sys.stderr)
        print("Please ensure it is a valid candump, Vector/MoTeC (.asc), or PCAN-View (.trc) file.", file=sys.stderr)
        sys.exit(1)
    
    type_map = {
        'trc': 'PCAN-View (.trc)',
        'candump_asc': 'ASC (candump-style)',
        'vector_asc': 'ASC (Vector/MoTeC-style)'
    }
    print(f"\nDetected file type: {type_map.get(file_type, 'Unknown')}")

    can_id_data, first_ts, last_ts = analyze_can_log(args.filepath, file_type)

    if not can_id_data:
        print("\nNo valid CAN data was successfully parsed from the file.")
        print("Check for warnings above about malformed lines.")
        return

    print("\n--- Message Rate Analysis ---")
    for can_id in sorted(can_id_data.keys()):
        data = can_id_data[can_id]
        time_span = data['last_timestamp'] - data['first_timestamp']
        rate = (data['count'] - 1) / time_span if time_span > 0 and data['count'] > 1 else 0
        print(f"CAN ID 0x{can_id:08X}: Count={data['count']:<5} Avg Rate={rate:>7.2f} Hz")

    total_transmitted_bits = sum(d['total_bits'] for d in can_id_data.values())
    total_duration = 0 if first_ts is None else last_ts - first_ts

    bus_load = calculate_bus_load(total_transmitted_bits, total_duration, args.bit_rate)
    print(f"\n--- Bus Load Analysis ---")
    print(f"Log duration:       {total_duration:.3f} seconds")
    print(f"Total bits sent:    {total_transmitted_bits} bits")
    print(f"Bus bit rate:       {args.bit_rate} Mbps")
    print(f"Estimated Bus Load: {bus_load:.2f}%\n")

    if args.target_can_id:
        print(f"\n--- Data Packets for CAN ID {args.target_can_id} ---")
        print_can_id_packets(args.filepath, file_type, args.target_can_id)

if __name__ == '__main__':
    main()