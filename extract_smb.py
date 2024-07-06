import os
import json
from scapy.all import rdpcap

def extract_smb_data(pcap_file):
    # Create a folder for extracted files
    output_folder = "C:\\Users\\wondo\\Downloads\\smb_extractor\\extracted_original_files"
    os.makedirs(output_folder, exist_ok=True)

    # Initialize metadata list
    metadata = []

    # Read the pcap file
    packets = rdpcap(pcap_file)

    for packet in packets:
        if packet.haslayer('SMB'):
            smb_layer = packet.getlayer('SMB')
            command = smb_layer.fields.get('Command')
            if command in (8, 12):  # SMB Write Request/Response
                # Debugging: Print packet summary
                print(packet.summary())
                print(smb_layer.fields)

                # Extract relevant information
                file_name = smb_layer.fields.get('FileName', 'unknown_file')
                file_size = smb_layer.fields.get('DataLength', 0)
                src_ip = packet['IP'].src
                src_port = packet['TCP'].sport
                dst_ip = packet['IP'].dst
                dst_port = packet['TCP'].dport
                timestamp = packet.time

                # Debugging: Print extracted information
                print(f"File Name: {file_name}")
                print(f"File Size: {file_size}")
                print(f"Source IP: {src_ip}")
                print(f"Source Port: {src_port}")
                print(f"Destination IP: {dst_ip}")
                print(f"Destination Port: {dst_port}")
                print(f"Timestamp: {timestamp}")

                # Save attachment (customize this part)
                attachment_data = smb_layer.fields.get('Data', b'')
                if attachment_data:  # Check if there is data to save
                    attachment_path = os.path.join(output_folder, file_name)
                    with open(attachment_path, "wb") as attachment_file:
                        attachment_file.write(attachment_data)

                # Add metadata to the list
                metadata.append({
                    "file_name": file_name,
                    "file_size": file_size,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "timestamp": timestamp,
                })

    # Save metadata to a JSON file
    metadata_file = "C:\\Users\\wondo\\Downloads\\smb_extractor\\metadata_of_extracted_file.json"
    with open(metadata_file, "w") as json_file:
        json.dump(metadata, json_file, indent=4)

    print(f"Attachments saved in {output_folder}")
    print(f"Metadata saved in {metadata_file}")

if __name__ == "__main__":
    pcap_file_path = "C:\\Users\\wondo\\Downloads\\smb_extractor\\smb.pcap"
    extract_smb_data(pcap_file_path)
