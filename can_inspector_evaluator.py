#!/usr/bin/env python3

import sys
import argparse

def count_and_rate_can_ids(filepath):
    # Dictionary to store the counts and timestamps of each CANId
    can_id_data = {}

    try:
        with open(filepath, 'r') as file:
            # Skip the first 7 rows
            for _ in range(7):
                next(file)

            for line in file:
                # Split the line into components based on whitespace
                parts = line.strip().split()

                # Skip lines that do not contain the expected number of elements (avoiding header lines)
                if len(parts) < 7:
                    continue

                # Extract the timestamp and CANId
                timestamp = float(parts[0])

                # Parse CAN ID as a 29-bit value, assuming it is in hexadecimal format
                can_id = int(parts[2], 16)

                # Initialize or update the CANId data
                if can_id in can_id_data:
                    can_id_data[can_id]['count'] += 1
                    can_id_data[can_id]['last_timestamp'] = timestamp
                else:
                    can_id_data[can_id] = {
                        'count': 1,
                        'first_timestamp': timestamp,
                        'last_timestamp': timestamp
                    }

    except FileNotFoundError:
        print(f"The file {filepath} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    # Calculate rates
    can_id_rates = {}
    for can_id, data in can_id_data.items():
        time_span = data['last_timestamp'] - data['first_timestamp']
        if time_span > 0:  # To avoid division by zero
            rate = data['count'] / time_span
        else:
            rate = 0  # or assume instantaneous rate if time_span is zero
        can_id_rates[can_id] = rate

    return can_id_rates, can_id_data

def calculate_bus_load(can_id_data, bit_rate):
    # Assume standard CAN frame sizes (arbitration, control, data, CRC, etc.)
    # Standard frame overhead: 47 bits; data size: 8 bytes max (64 bits)
    bits_per_frame = 47 + 64

    total_bits = 0
    for data in can_id_data.values():
        total_bits += data['count'] * bits_per_frame

    # Estimate the bus load
    bus_load = (total_bits / (bit_rate * 1e6)) * 100  # Bit rate in Mbps
    return bus_load

def print_can_id_packets(filepath, target_can_id):
    try:
        with open(filepath, 'r') as file:
            # Skip the first 7 rows
            for _ in range(7):
                next(file)

            for line in file:
                # Split the line into components based on whitespace
                parts = line.strip().split()

                # Skip lines that do not contain the expected number of elements (avoiding header lines)
                if len(parts) < 7:
                    continue

                # Extract the CANId and compare it to the target, ensuring both are handled as 29-bit IDs
                can_id = int(parts[2], 16)

                if can_id == int(target_can_id, 16):
                    sys.stdout.write(line)

    except FileNotFoundError:
        print(f"The file {filepath} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Process and analyze CAN bus data from a file.")
    parser.add_argument('-f', '--filepath', help='Path to the CAN bus data file')
    parser.add_argument('-id', '--target_can_id', help='Target CANId (in hexadecimal) to filter and print data packets')
    parser.add_argument('-b', '--bit_rate', type=float, default=1000.0, help='CAN bus bit rate in Mbps (default: 500 Mbps)')

    args = parser.parse_args()

    # Process the file
    can_id_rates, can_id_data = count_and_rate_can_ids(args.filepath)

    # Printing the average rates for each CANId in numerical order
    print("Average rates for each CANId:")
    for can_id in sorted(can_id_rates.keys()):
        print(f"Average rate of CANId 0x{can_id:08X} is {can_id_rates[can_id]:.2f} messages per second.")

    # Calculate and print CAN bus load
    bus_load = calculate_bus_load(can_id_data, args.bit_rate)
    print(f"\nEstimated CAN bus load: {bus_load:.2f}%")

    # Print all packets for the specified target CANId
    print(f"\nData packets for CANId {args.target_can_id}:")
    print_can_id_packets(args.filepath, args.target_can_id)

if __name__ == '__main__':
    main()
