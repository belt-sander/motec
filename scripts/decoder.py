import argparse
import base64
import xml.etree.ElementTree as ET
import os
import re

def process_m1mod_file(file_path):
    """
    Parses a .m1mod XML file to find and decode all Base64 encoded blocks.

    Args:
        file_path (str): The path to the .m1mod file.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return
    except ET.ParseError as e:
        print(f"Error parsing XML file '{file_path}': {e}")
        return

    # Create an output directory relative to the input file
    output_dir = os.path.join(os.path.dirname(os.path.abspath(file_path)), "decoded_output")
    os.makedirs(output_dir, exist_ok=True)
    print(f"Saving decoded files to: {output_dir}")

    file_count = 0

    # 1. Find and decode all <Code Encoding="base64"> elements
    # Iterate through each module to create a descriptive name
    for module in root.findall('.//Module'):
        module_name = module.get('Name', f'UnnamedModule_{file_count}')
        for component in module.findall('.//Component'):
            code_element = component.find('Code[@Encoding="base64"]')
            if code_element is not None and code_element.text:
                component_name = component.get('Name', f'UnnamedComponent_{file_count}')

                # Sanitize names to create a valid filename
                safe_module_name = re.sub(r'[^\w.-]', '_', module_name)
                safe_comp_name = re.sub(r'[^\w.-]', '_', component_name)
                
                # The decoded scripts appear to be Lua, so use the .lua extension
                filename = f"{safe_module_name}_{safe_comp_name}.lua"
                output_path = os.path.join(output_dir, filename)

                # Extract, decode, and write the data
                encoded_data = code_element.text.strip()
                try:
                    decoded_data = base64.b64decode(encoded_data)
                    with open(output_path, 'wb') as f_out:
                        f_out.write(decoded_data)
                    print(f"  - Created script: {filename}")
                    file_count += 1
                except (base64.binascii.Error, TypeError) as e:
                    print(f"  - ERROR: Could not decode Base64 for '{filename}': {e}")

    # 2. Find and decode the <img> src attribute
    for module in root.findall('.//Module'):
        module_name = module.get('Name', f'UnnamedModule_{file_count}')
        for component in module.findall('.//Component'):
            # The image is located within a <Comment> tag
            img_element = component.find('Comment/img')
            if img_element is not None and 'src' in img_element.attrib:
                src_data = img_element.get('src')
                prefix = 'data:image/png;base64,'
                if src_data.startswith(prefix):
                    component_name = component.get('Name', f'UnnamedComponent_{file_count}')
                    
                    safe_module_name = re.sub(r'[^\w.-]', '_', module_name)
                    safe_comp_name = re.sub(r'[^\w.-]', '_', component_name)

                    filename = f"{safe_module_name}_{safe_comp_name}_Comment.png"
                    output_path = os.path.join(output_dir, filename)

                    # Extract the Base64 data part, decode, and write to a file
                    encoded_data = src_data[len(prefix):]
                    try:
                        decoded_data = base64.b64decode(encoded_data)
                        with open(output_path, 'wb') as f_out:
                            f_out.write(decoded_data)
                        print(f"  - Created image: {filename}")
                        file_count += 1
                    except (base64.binascii.Error, TypeError) as e:
                        print(f"  - ERROR: Could not decode image for '{filename}': {e}")
    
    print(f"\nProcessing complete. Total files created: {file_count}")

def main():
    """
    Main function to set up command-line argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="Decode Base64 blocks from a MoTeC M1 .m1mod XML file and save each to a separate output file."
    )
    parser.add_argument(
        '-f', '--file',
        required=True,
        help="Path to the input .m1mod file."
    )
    args = parser.parse_args()
    process_m1mod_file(args.file)

if __name__ == "__main__":
    main()