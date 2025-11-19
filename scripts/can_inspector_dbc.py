#!/usr/bin/env python3

import sys
import argparse
import re
import binascii

# Try to import cantools for DBC decoding
try:
    import cantools
    CANTOOLS_AVAILABLE = True
except ImportError:
    CANTOOLS_AVAILABLE = False

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

                if stripped_line.startswith(';'): return 'trc'
                if stripped_line.startswith('('): return 'candump_asc'

                parts = stripped_line.split()
                if len(parts) >= 6:
                    try:
                        float(parts[0])
                        return 'vector_asc'
                    except ValueError:
                        continue
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
                        try:
                            timestamp = float(parts[0])
                        except ValueError:
                            continue
                        can_id_hex = parts[2].rstrip('x')
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
                    continue
    except Exception as e:
        print(f"An unexpected error occurred while processing the file: {e}", file=sys.stderr)
        sys.exit(1)

    return can_id_data, first_ts, last_ts

def calculate_bus_load(total_bits, duration, bit_rate_mbps):
    if duration <= 0: return 0.0
    total_possible_bits = bit_rate_mbps * 1e6 * duration
    return (total_bits / total_possible_bits) * 100

def extract_data_bytes(parts, file_type, line):
    """Helper to extract raw bytes from a log line."""
    data_bytes = bytearray()
    try:
        if file_type == 'trc':
            # Format: Num Time Type ID DLC D0 D1 ...
            # parts[5:] are usually the data bytes
            if len(parts) > 5:
                for b in parts[5:]:
                    data_bytes.append(int(b, 16))
                    
        elif file_type == 'candump_asc':
            # Format: (Timestamp) Interface ID#DATA
            payload_str = parts[2].split('#')[1]
            data_bytes = bytearray.fromhex(payload_str)
            
        elif file_type == 'vector_asc':
            # Format: Time Ch ID Rx/Tx d DLC D0 D1 ...
            # Usually parts[6] begins the data if parts[5] is DLC
            # Vector files can be variable, but data usually follows DLC
            dlc_index = 5
            if len(parts) > dlc_index + 1:
                for b in parts[dlc_index+1:]:
                    # Stop if we hit non-hex data (some files have strings at end)
                    try:
                        data_bytes.append(int(b, 16))
                    except ValueError:
                        break
    except Exception:
        return None
    return data_bytes

def print_decoded_line(db, can_id, data_bytes):
    """Decodes and prints signals using the DBC."""
    if not db: return
    
    try:
        decoded = db.decode_message(can_id, data_bytes)
        formatted_signals = ", ".join([f"{k}: {v}" for k, v in decoded.items()])
        print(f"    └─ Decoded: {formatted_signals}")
    except KeyError:
        print(f"    └─ Decoded: [ID 0x{can_id:X} not found in DBC]")
    except Exception as e:
        print(f"    └─ Decoded: [Error decoding: {e}]")

def print_can_id_packets(filepath, file_type, target_can_id, db=None):
    """Prints packets for a specific CAN ID, optionally decoding them."""
    try:
        target_id_int = int(target_can_id, 16)
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            for line in f:
                try:
                    parts = line.strip().split()
                    if not parts: continue
                    line_can_id_hex = None
                    
                    # Identification Logic
                    if file_type == 'trc' and not line.strip().startswith(';') and len(parts) >= 4 and parts[0].endswith(')'):
                        line_can_id_hex = parts[3]
                    elif file_type == 'candump_asc' and line.strip().startswith('(') and len(parts) >= 3:
                        line_can_id_hex = parts[2].split('#')[0]
                    elif file_type == 'vector_asc' and len(parts) >= 6:
                        try:
                            float(parts[0])
                            line_can_id_hex = parts[2].rstrip('x')
                        except ValueError:
                            continue

                    if line_can_id_hex and int(line_can_id_hex, 16) == target_id_int:
                        sys.stdout.write(line)
                        
                        # Perform Decoding if DBC is present
                        if db:
                            data = extract_data_bytes(parts, file_type, line)
                            if data:
                                print_decoded_line(db, target_id_int, data)
                            
                except (ValueError, IndexError): continue
    except Exception as e:
        print(f"Could not filter for ID {target_can_id}: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Process and analyze CAN bus data from .asc or .trc files.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('filepath', help='Path to the CAN bus data file (.asc or .trc)')
    parser.add_argument('-id', '--target_can_id', help='Optional: Target CANId (in hex) to filter and print (e.g., 1F4)')
    parser.add_argument('-b', '--bit_rate', type=float, default=1.0, help='CAN bus bit rate in Mbps (default: 1.0)')
    parser.add_argument('--dbc', help='Optional: Path to .dbc file for decoding signals')

    args = parser.parse_args()

    # Load DBC if requested
    db = None
    if args.dbc:
        if not CANTOOLS_AVAILABLE:
            print("Error: You specified a DBC file, but 'cantools' is not installed.", file=sys.stderr)
            print("Please install it using: pip install cantools", file=sys.stderr)
            sys.exit(1)
        try:
            print(f"Loading DBC file: {args.dbc} ...")
            db = cantools.database.load_file(args.dbc)
            print("DBC loaded successfully.")
        except Exception as e:
            print(f"Error loading DBC file: {e}", file=sys.stderr)
            sys.exit(1)

    file_type = detect_file_type(args.filepath)
    if file_type is None:
        print(f"Error: Could not determine file type for '{args.filepath}'.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Detected file type: {file_type}")

    # 1. Run Statistical Analysis
    can_id_data, first_ts, last_ts = analyze_can_log(args.filepath, file_type)

    if not can_id_data:
        print("\nNo valid CAN data parsed.")
        return

    print("\n--- Message Rate Analysis ---")
    for can_id in sorted(can_id_data.keys()):
        data = can_id_data[can_id]
        time_span = data['last_timestamp'] - data['first_timestamp']
        rate = (data['count'] - 1) / time_span if time_span > 0 and data['count'] > 1 else 0
        
        # Add DBC Name lookup to the summary if available
        msg_name = ""
        if db:
            try:
                msg_name = f" ({db.get_message_by_frame_id(can_id).name})"
            except:
                msg_name = ""

        print(f"CAN ID 0x{can_id:08X}{msg_name}: Count={data['count']:<5} Avg Rate={rate:>7.2f} Hz")

    # 2. Bus Load
    total_transmitted_bits = sum(d['total_bits'] for d in can_id_data.values())
    total_duration = 0 if first_ts is None else last_ts - first_ts
    bus_load = calculate_bus_load(total_transmitted_bits, total_duration, args.bit_rate)
    
    print(f"\n--- Bus Load Analysis ---")
    print(f"Estimated Bus Load: {bus_load:.2f}% (@ {args.bit_rate} Mbps)")

    # 3. Print Specific Packet Data (Decoded if DBC provided)
    if args.target_can_id:
        print(f"\n--- Data Packets for CAN ID {args.target_can_id} ---")
        print_can_id_packets(args.filepath, file_type, args.target_can_id, db)

if __name__ == '__main__':
    main()