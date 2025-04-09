## **Dllscan - Powerful File Scanner 🔍**

---

### **What is CyberSenku?**  
**CyberSenku** is a lightweight, fast, and intelligent file scanning tool designed to detect potential security risks in your system files (including `.dll` files and all other types of files). It combines **local system analysis** with **online threat intelligence services** (like VirusTotal) to identify vulnerabilities, permissions risks, and malicious behaviors.

---

### **Key Features 🚀**  

1. **Multi-File Scanning**:
   - Scan **specific folders** or perform a **full system scan** for DLL files or all file types.  
   - Analyze file permissions (readable, writable, executable) to identify misconfigurations.

2. **VirusTotal Integration 🛡️**:
   - Automatically fetch **file threat assessments** and descriptions using VirusTotal's API.  
   - Detect how many antivirus engines mark a file as malicious.

3. **Parallel Execution for Faster Scans ⚡**:
   - Uses multi-threading to perform scans in parallel, ensuring lightning-fast performance even for large folders.

4. **Automated Dependency Management 🛠️**:
   - No need to worry about missing libraries! CyberSenku checks for all dependencies and installs them **automatically** before running.

5. **User-Friendly CLI with Real-Time Updates 📊**:
   - Displays real-time progress using a **loading bar** for better user experience.  
   - Results are shown in a clean, tabular format with color-coded risk levels:
     - 🟢 **Low Risk**  
     - 🟡 **Medium Risk**  
     - 🔴 **High Risk**  

6. **Customization Options 🎯**:
   - Scan **only DLL files** or **all files** based on your preference.  
   - Enter your VirusTotal API key once, and the tool remembers it during the session.

7. **CyberSenku Branding**:  
   - Professional and stylish startup banner powered by **ASCII art** to welcome users to the tool.

---

### **Why Use Dllscan? 🔥**

- **Security First**: Quickly identify potential security threats in your files.  
- **Fast and Efficient**: Thanks to multi-threading, even huge directories are scanned in record time.  
- **Easy to Use**: Just run it in your terminal—no complicated setup required.  
- **Automatic Fixes**: Missing libraries? CyberSenku will install them seamlessly.  

---

### **How to Use It? 🖥️**

1. Clone the Repository:
   ```bash
   git clone https://github.com/senku2006/DLLscan.git
   cd DLLscan
   cd python
   ```

2. Run the Tool:
   ```bash
   python3 dll_scanner9.py
   ```

3. Enter Your VirusTotal API Key:  
   The tool will prompt you to enter your API key once during execution.

4. Choose Scan Options:
   - **1**: Scan a specific folder for `.dll` files only.  
   - **2**: Scan all files in a folder for potential risks.  
   - **3**: Exit the program.  

---

### **Example Output 📝**  

```text
CyberSenku
================================
Scanning folder: /media/user/Documents...

╒══════════════════════════════════╤═══════════╤══════════╤═════════╤════════════╤══════════════╤═════════════════════╕
│ File Path                        │ Size (KB) │ Readable │ Writable│ Executable │ Risk Level   │ VirusTotal          │
╞══════════════════════════════════╪═══════════╪══════════╪═════════╪════════════╪══════════════╪═════════════════════╡
│ /media/.../example.dll           │ 320       │ True     │ False   │ True       │ Low          │ Clean by 70 engines │
│ /media/.../dangerous.dll         │ 540       │ True     │ True    │ True       │ High         │ Detected by 5 AVs   │
╘══════════════════════════════════╧═══════════╧══════════╧═════════╧════════════╧══════════════╧═════════════════════╛
```

---

### **Dependencies 📦**

CyberSenku automatically installs the following Python libraries if missing:  
- `requests`  
- `tabulate`  
- `tqdm`  
- `pyfiglet`  

---

### **License 📄**

This project is licensed under the **MIT License**. Feel free to fork, contribute, or share!

---

### **Contribute 💡**

Pull requests and feature suggestions are welcome. If you encounter bugs, please open an issue in the repository.

---

**CyberSenku** — **Scan, Detect, and Secure Your Files!** 🛡️  
