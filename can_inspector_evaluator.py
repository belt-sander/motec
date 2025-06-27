#!/usr/bin/env python3

import sys
import argparse
import re

def calculate_frame_bits(dlc, is_extended_id):
    """
    Calculates the total number of bits for a single CAN frame, including a
    worst-case estimation for bit stuffing.

    Args:
        dlc (int): The Data Length Code (0-8 bytes).
        is_extended_id (bool): True if the frame uses a 29-bit extended ID,
                               False for a standard 11-bit ID.

    Returns:
        int: The estimated total bits in the CAN frame on the bus.
    """
    # Nominal bits without bit stuffing:
    # Standard Frame (11-bit ID) Overhead: SOF(1)+ID(11)+RTR(1)+IDE(1)+r0(1)+DLC(4)+CRC(15)+DEL(1)+ACK(1)+DEL(1)+EOF(7) = 44 bits
    # Extended Frame (29-bit ID) Overhead: SOF(1)+ID(11)+SRR(1)+IDE(1)+ID(18)+RTR(1)+r1,r0(2)+DLC(4)+CRC(15)+DEL(1)+ACK(1)+DEL(1)+EOF(7) = 64 bits
    if is_extended_id:
        overhead_bits = 64
        # For extended frames, the fields subject to bit stuffing are:
        # Arbitration(32) + Control(6) + Data + CRC(15)
        stuff_check_bits = 34 + (dlc * 8) + 15
    else:
        overhead_bits = 44
        # For standard frames, the fields subject to bit stuffing are:
        # Arbitration(12) + Control(6) + Data + CRC(15)
        stuff_check_bits = 12 + 6 + (dlc * 8) + 15

    data_bits = dlc * 8
    
    # Worst-case bit stuffing: one stuff bit is added for every 5 consecutive
    # bits of the same polarity. A common worst-case approximation is to
    # add (N-1)/4 stuff bits for a field of N bits. We simplify to N/4.
    stuff_bits = stuff_check_bits // 4

    return overhead_bits + data_bits + stuff_bits

def analyze_can_log(filepath):
    """
    Parses a CAN log file to gather statistics on each CAN ID.

    Args:
        filepath (str): The path to the CAN log file.

    Returns:
        A tuple containing:
        - dict: A dictionary with statistics for each CAN ID.
        - float: The timestamp of the first message.
        - float: The timestamp of the last message.
    """
    can_id_data = {}
    first_timestamp_overall = None
    last_timestamp_overall = None

    try:
        with open(filepath, 'r') as file:
            for line in file:
                parts = line.strip().split()
                if not parts or len(parts) < 3:
                    continue

                try:
                    # Extract timestamp and CAN ID
                    timestamp = float(parts[0].strip('()'))
                    can_id_hex = parts[2].split('#')[0]
                    can_id = int(can_id_hex, 16)
                    
                    # Determine if it's an 11-bit or 29-bit ID
                    # A simple heuristic: if the ID is larger than 0x7FF (2047), it's extended.
                    is_extended = can_id > 0x7FF

                    # Extract Data Length Code (DLC)
                    dlc = 0
                    if '#' in parts[2]: # Format: 123#<data>
                        data_part = parts[2].split('#')[1]
                        dlc = len(data_part) // 2
                    elif len(parts) > 3 and parts[3].startswith('['): # Format: [d]
                        dlc = int(re.search(r'\[(\d+)\]', parts[3]).group(1))
                    else:
                        # Assuming no data if DLC is not found, could be an error frame or RTR
                        dlc = 0
                    
                    # Update timestamps
                    if first_timestamp_overall is None:
                        first_timestamp_overall = timestamp
                    last_timestamp_overall = timestamp
                    
                    # Calculate bits for this specific frame
                    frame_bits = calculate_frame_bits(dlc, is_extended)

                    # Initialize or update the CAN ID data
                    if can_id in can_id_data:
                        can_id_data[can_id]['count'] += 1
                        can_id_data[can_id]['total_bits'] += frame_bits
                        can_id_data[can_id]['last_timestamp'] = timestamp
                    else:
                        can_id_data[can_id] = {
                            'count': 1,
                            'total_bits': frame_bits,
                            'first_timestamp': timestamp,
                            'last_timestamp': timestamp
                        }
                except (ValueError, IndexError):
                    # Skip malformed lines
                    continue

    except FileNotFoundError:
        print(f"Error: The file {filepath} was not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while processing the file: {e}", file=sys.stderr)
        sys.exit(1)
        
    return can_id_data, first_timestamp_overall, last_timestamp_overall

def calculate_bus_load(total_bits, duration, bit_rate_mbps):
    """
    Calculates the CAN bus load percentage.

    Args:
        total_bits (int): The total number of bits transmitted.
        duration (float): The total time duration in seconds.
        bit_rate_mbps (float): The bus speed in Megabits per second.

    Returns:
        float: The estimated bus load in percent.
    """
    if duration <= 0:
        return 0.0
        
    # Total bits that could have been transmitted in the given time
    total_possible_bits = bit_rate_mbps * 1e6 * duration
    
    # Bus load is the ratio of actual bits to possible bits
    bus_load_percentage = (total_bits / total_possible_bits) * 100
    
    return bus_load_percentage

def main():
    parser = argparse.ArgumentParser(description="Process and analyze CAN bus data from a file.")
    parser.add_argument('filepath', help='Path to the CAN bus data file')
    parser.add_argument('-id', '--target_can_id', help='Optional: Target CANId (in hex) to filter and print data packets')
    # User was asked to assume 1mbps, so we set that as the default.
    parser.add_argument('-b', '--bit_rate', type=float, default=1.0, help='CAN bus bit rate in Mbps (default: 1.0 for 1mbps)')

    args = parser.parse_args()

    # Analyze the log file
    can_id_data, first_ts, last_ts = analyze_can_log(args.filepath)

    if not can_id_data:
        print("No valid CAN data found in the file.")
        return

    # --- Calculate and Print Rates ---
    print("--- Message Rate Analysis ---")
    for can_id in sorted(can_id_data.keys()):
        data = can_id_data[can_id]
        time_span = data['last_timestamp'] - data['first_timestamp']
        rate = (data['count'] - 1) / time_span if time_span > 0 and data['count'] > 1 else 0
        print(f"CAN ID 0x{can_id:08X}: Count={data['count']:<5} Avg Rate={rate:>7.2f} Hz")

    # --- Calculate and Print Bus Load ---
    total_transmitted_bits = sum(d['total_bits'] for d in can_id_data.values())
    total_duration = last_ts - first_ts
    
    bus_load = calculate_bus_load(total_transmitted_bits, total_duration, args.bit_rate)
    print(f"\n--- Bus Load Analysis ---")
    print(f"Log duration:       {total_duration:.3f} seconds")
    print(f"Total bits sent:    {total_transmitted_bits} bits")
    print(f"Bus bit rate:       {args.bit_rate} Mbps")
    print(f"Estimated Bus Load: {bus_load:.2f}%")

    # --- Print packets for a specific ID if requested ---
    if args.target_can_id:
        print(f"\n--- Data Packets for CAN ID {args.target_can_id} ---")
        try:
            target_id_int = int(args.target_can_id, 16)
            with open(args.filepath, 'r') as f:
                for line in f:
                    try:
                        line_can_id = int(line.strip().split()[2].split('#')[0], 16)
                        if line_can_id == target_id_int:
                            sys.stdout.write(line)
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            print(f"Could not filter for ID {args.target_can_id}: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()