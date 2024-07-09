import os
import json
from scapy.all import rdpcap

def create_directory(folder_name):
  """Creates a directory with error handling.
  Args:
      folder_name (str): The name of the directory to create.
  Returns:
      str: The full path to the created directory, or None on error.
  """

  try:
    dir_path = os.path.join(os.getcwd(), folder_name)
    os.makedirs(dir_path, exist_ok=True)
    print(f"Directory '{dir_path}' created successfully.")
    return dir_path
  except PermissionError:
    print(f"Permission denied: Unable to create directory '{folder_name}'.")
  except Exception as e:
    print(f"An error occurred: {e}")
  return None

def get_file_path(file_path):
  """Checks if a file exists and returns its path if valid.
  Args:
      file_path (str): The path to the file.
  Returns:
      str: The full path to the file if it exists, or None otherwise.
  """

  if os.path.isfile(file_path):
    print(f"File found: {file_path}")
    return file_path
  else:
    print("Invalid file path. Please try again.")
    return None

def extract_smb_data(pcap_file):
  """Extracts SMB data from a PCAP file, saves extracted files, and creates metadata.
  Args:
      pcap_file (str): The path to the PCAP file.
  """
  # Create a folder for extracted files
  folder_name = input("Please enter the output folder name: ").strip()
  output_folder = create_directory(folder_name)
  if not output_folder:
    return

  # Initialize metadata list
  metadata = []

  # Read the PCAP file
  packets = rdpcap(pcap_file)

  for packet in packets:
    if packet.haslayer('SMB'):
      smb_layer = packet.getlayer('SMB')
      command = smb_layer.fields.get('Command', 'Unknown')

      if command in (0x0A, 0x0B):  # SMB Write Request/Response

        # Extract relevant information
        file_name = smb_layer.fields.get('FileName', 'unknown_file')
        file_size = smb_layer.fields.get('DataLength', 0)
        src_ip = packet['IP'].src
        src_port = packet['TCP'].sport
        dst_ip = packet['IP'].dst
        dst_port = packet['TCP'].dport
        timestamp = packet.time

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
  metadata_file = input("Please enter the path to save the metadata: ").strip()
  with open(metadata_file, "w") as json_file:
    json.dump(metadata, json_file, indent=4)
  print(f"Metadata saved in {metadata_file}")

if __name__ == "__main__":
  file_path = input("Please enter the SMB file path: ").strip()
  pcap_file_path = get_file_path(file_path)
  if pcap_file_path:
    extract_smb_data(pcap_file_path)
