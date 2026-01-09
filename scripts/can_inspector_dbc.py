#!/usr/bin/env python3

import sys
import argparse
import re
import math

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
                        
                        # FORMAT 1: PCAN-View v2.0 (DT column present)
                        if len(parts) >= 6 and parts[2] == 'DT':
                            timestamp = float(parts[1]) / 1000.0  # Convert ms to seconds
                            can_id_hex = parts[3]
                            dlc = int(parts[5])
                            
                        # FORMAT 2: Legacy TRC
                        elif len(parts) >= 5 and parts[0].endswith(')'):
                            timestamp = float(parts[1]) / 1000.0
                            can_id_hex = parts[3]
                            dlc = int(parts[4])
                        else:
                            continue

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

                    # ---------------------------------------------------------
                    # Data Accumulation Logic
                    # ---------------------------------------------------------
                    
                    if timestamp is not None and can_id_hex is not None:
                        current_id = int(can_id_hex, 16)
                        
                        # Global Time Tracking
                        if first_ts is None: first_ts = timestamp
                        last_ts = timestamp
                        
                        # Initialize ID entry if new
                        if current_id not in can_id_data:
                            can_id_data[current_id] = {
                                'count': 0, 
                                'total_bits': 0, 
                                'dlc': dlc,
                                'last_timestamp': timestamp,
                                'deltas': [] # List to store time intervals between packets
                            }
                        else:
                            # Calculate time delta from previous packet of same ID
                            prev_ts = can_id_data[current_id]['last_timestamp']
                            delta = timestamp - prev_ts
                            can_id_data[current_id]['deltas'].append(delta)
                            can_id_data[current_id]['last_timestamp'] = timestamp
                        
                        # Update ID Stats
                        can_id_data[current_id]['count'] += 1
                        
                        # Calculate Bits
                        is_extended = len(can_id_hex) > 3
                        frame_bits = calculate_frame_bits(dlc, is_extended)
                        can_id_data[current_id]['total_bits'] += frame_bits

                except Exception:
                    continue
                    
        return can_id_data, first_ts, last_ts

    except FileNotFoundError:
        print(f"Error: File not found {filepath}", file=sys.stderr)
        sys.exit(1)
        
def calculate_bus_load(total_bits, duration, bit_rate_mbps):
    if duration <= 0: return 0.0
    total_possible_bits = bit_rate_mbps * 1e6 * duration
    return (total_bits / total_possible_bits) * 100

def extract_data_bytes(parts, file_type, line):
    """Helper to extract raw bytes from a log line."""
    data_bytes = bytearray()
    try:
        if file_type == 'trc':
            # Check for PCAN v2.0 format (DT column present)
            if len(parts) > 6 and parts[2] == 'DT':
                # Data starts at index 6
                for b in parts[6:]:
                    data_bytes.append(int(b, 16))
            else:
                # Legacy Format
                if len(parts) > 5:
                    for b in parts[5:]:
                        data_bytes.append(int(b, 16))
                    
        elif file_type == 'candump_asc':
            payload_str = parts[2].split('#')[1]
            data_bytes = bytearray.fromhex(payload_str)
            
        elif file_type == 'vector_asc':
            dlc_index = 5
            if len(parts) > dlc_index + 1:
                for b in parts[dlc_index+1:]:
                    try:
                        data_bytes.append(int(b, 16))
                    except ValueError:
                        break
    except Exception:
        return None
    return data_bytes

def print_decoded_line(db, can_id, data_bytes):
    """Decodes and prints signals using the DBC in a column format."""
    if not db: return
    
    try:
        decoded = db.decode_message(can_id, data_bytes)
        print(f"    └─ Decoded:")
        for name, value in decoded.items():
            if isinstance(value, float):
                print(f"        • {name}: {value:.4f}")
            else:
                print(f"        • {name}: {value}")

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
                    
                    if file_type == 'trc' and not line.strip().startswith(';'):
                        if len(parts) >= 6 and parts[2] == 'DT':
                            line_can_id_hex = parts[3]
                        elif len(parts) >= 4 and parts[0].endswith(')'):
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

    print("\n--- Message Rate & Jitter Analysis ---")
    print(f"{'CAN ID':<15} {'Name':<20} {'Count':<8} {'Avg Rate (Hz)':<15} {'Std Dev (ms)':<15}")
    print("-" * 80)

    for can_id in sorted(can_id_data.keys()):
        data = can_id_data[can_id]
        
        # Calculate Average Rate
        # Note: We use the sum of deltas to get the exact span between first and last packet of this specific ID
        deltas = data['deltas']
        count = data['count']
        
        if count > 1 and deltas:
            duration = sum(deltas)
            avg_rate = (count - 1) / duration if duration > 0 else 0
            
            # Calculate Standard Deviation of the intervals
            avg_interval = duration / len(deltas)
            variance = sum((x - avg_interval) ** 2 for x in deltas) / (len(deltas) - 1)
            std_dev_s = math.sqrt(variance)
            std_dev_ms = std_dev_s * 1000.0
        else:
            avg_rate = 0.0
            std_dev_ms = 0.0
        
        # Get Name
        msg_name = ""
        if db:
            try:
                msg = db.get_message_by_frame_id(can_id)
                msg_name = msg.name[:19] # Truncate for display
            except:
                msg_name = "-"
        
        print(f"0x{can_id:04X}          {msg_name:<20} {count:<8} {avg_rate:<15.2f} {std_dev_ms:<15.4f}")

    # 2. Bus Load
    total_transmitted_bits = sum(d['total_bits'] for d in can_id_data.values())
    total_duration = 0 if first_ts is None else last_ts - first_ts
    bus_load = calculate_bus_load(total_transmitted_bits, total_duration, args.bit_rate)
    
    print(f"\n--- Bus Load Analysis ---")
    print(f"Estimated Bus Load: {bus_load:.2f}% (@ {args.bit_rate} Mbps)")

    # 3. Print Specific Packet Data
    if args.target_can_id:
        print(f"\n--- Data Packets for CAN ID {args.target_can_id} ---")
        print_can_id_packets(args.filepath, file_type, args.target_can_id, db)

if __name__ == '__main__':
    main()