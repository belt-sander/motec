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
                can_id = parts[2]

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

    return can_id_rates

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

                # Extract the CANId
                can_id = parts[2]

                # Print the line if the CANId matches the target CANId
                if can_id == target_can_id:
                    sys.stdout.write(line)

    except FileNotFoundError:
        print(f"The file {filepath} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Process and analyze CAN bus data from a file.")
    parser.add_argument('filepath', help='Path to the CAN bus data file')
    parser.add_argument('target_can_id', help='Target CANId to filter and print data packets')
    
    args = parser.parse_args()
    
    # Process the file
    can_id_rates = count_and_rate_can_ids(args.filepath)
    
    # Printing the average rates for each CANId in numerical order
    print("Average rates for each CANId:")
    for can_id in sorted(can_id_rates.keys(), key=lambda x: int(x, 16)):
        print(f"Average rate of CANId {can_id} is {can_id_rates[can_id]:.2f} messages per second.")
    
    # Print all packets for the specified target CANId
    print(f"\nData packets for CANId {args.target_can_id}:")
    print_can_id_packets(args.filepath, args.target_can_id)

if __name__ == '__main__':
    main()
