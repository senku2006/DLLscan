import os
import requests
import hashlib
from tabulate import tabulate
import colorama
from colorama import Fore, Style
from tqdm import tqdm
import pyfiglet
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

colorama.init(autoreset=True)

# Function to check and install missing libraries
def install_missing_libraries():
    required_libraries = ["requests", "tabulate", "tqdm", "pyfiglet", "concurrent.futures"]
    for lib in required_libraries:
        try:
            __import__(lib)
        except ImportError:
            print(f"{Fore.RED}Library '{lib}' not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib, "--break-system-packages"])

# Function to prompt the user for the API key (only once)
def get_api_key():
    print(f"{Fore.YELLOW}Please enter your VirusTotal API key:")
    return input(f"{Fore.CYAN}API Key: ")

# Function to get the file hash (SHA-256) to query VirusTotal
def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to get DLL file description from VirusTotal
def get_virustotal_description(file_hash, api_key):
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            description = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return f"Detected by {description.get('malicious', 0)} antivirus engines."
        else:
            return "No description found in VirusTotal or file not found."
    except Exception as e:
        return f"Error fetching description: {str(e)}"

# Function to check file details
def check_file_permissions(file_path):
    try:
        attributes = os.stat(file_path)
        permissions = {
            "readable": os.access(file_path, os.R_OK),
            "writable": os.access(file_path, os.W_OK),
            "executable": os.access(file_path, os.X_OK)
        }
        return {"size": attributes.st_size, "permissions": permissions}
    except Exception as e:
        return {"error": str(e)}

# Function to analyze file risk
def assess_risk(file_info):
    risk_level = "Low"
    if file_info["permissions"]["writable"] and file_info["permissions"]["executable"]:
        risk_level = "High"
    elif file_info["permissions"]["writable"]:
        risk_level = "Medium"
    return risk_level

# Function to process a single file
def process_file(file_path, api_key):
    file_info = check_file_permissions(file_path)
    if "error" in file_info:
        return {"path": file_path, "error": file_info["error"]}

    file_hash = get_file_hash(file_path)
    file_info.update({
        "path": file_path,
        "risk_level": assess_risk(file_info),
        "virustotal_description": get_virustotal_description(file_hash, api_key)
    })
    return file_info

# Function to scan directory for files
def scan_directory(directory, api_key, scan_dll_only=True):
    files_to_scan = []
    for root, _, files in os.walk(directory):
        for file in files:
            if scan_dll_only and not file.lower().endswith(".dll"):
                continue
            files_to_scan.append(os.path.join(root, file))

    results = []
    with tqdm(total=len(files_to_scan), desc="Scanning files", ncols=100, unit="file") as pbar:
        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(process_file, file_path, api_key)
                for file_path in files_to_scan
            ]
            for future in futures:
                results.append(future.result())
                pbar.update(1)

    return results

# Function to display results
def display_results(results):
    table = []
    headers = ["File Path", "Size (Bytes)", "Readable", "Writable", "Executable", "Risk Level", "VirusTotal"]
    for result in results:
        if "error" in result:
            table.append([result["path"], "N/A", "N/A", "N/A", "N/A", f"{Fore.RED}Error", "N/A"])
        else:
            table.append([
                result["path"],
                result["size"],
                result["permissions"]["readable"],
                result["permissions"]["writable"],
                result["permissions"]["executable"],
                f"{Fore.GREEN if result['risk_level'] == 'Low' else Fore.YELLOW if result['risk_level'] == 'Medium' else Fore.RED}{result['risk_level']}",
                result["virustotal_description"]
            ])
    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

# Main menu
if __name__ == "__main__":
    install_missing_libraries()  # Install missing libraries
    ascii_banner = pyfiglet.figlet_format("CyberSenku")
    print(Fore.CYAN + ascii_banner)

    api_key = get_api_key()  # Ask for API key once

    while True:
        print(f"{Fore.CYAN}\n=== File Scanner ===")
        print("1. Scan a specific folder for DLL files")
        print("2. Scan a specific folder for all files")
        print("3. Exit")

        choice = input(f"{Fore.YELLOW}Enter your choice: ")
        if choice == "1":
            folder = input(f"{Fore.YELLOW}Enter the folder path to scan for DLL files: ")
            if os.path.exists(folder) and os.path.isdir(folder):
                print(f"{Fore.GREEN}\nScanning folder: {folder}...")
                results = scan_directory(folder, api_key, scan_dll_only=True)
                display_results(results)
            else:
                print(f"{Fore.RED}Invalid folder path.")
        elif choice == "2":
            folder = input(f"{Fore.YELLOW}Enter the folder path to scan for all files: ")
            if os.path.exists(folder) and os.path.isdir(folder):
                print(f"{Fore.GREEN}\nScanning folder: {folder}...")
                results = scan_directory(folder, api_key, scan_dll_only=False)
                display_results(results)
        elif choice == "3":
            print(f"{Fore.GREEN}Exiting. Goodbye!")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please select a valid option.")

