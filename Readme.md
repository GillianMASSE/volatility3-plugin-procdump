# ProcdumpCustom Plugin for Volatility 3

This repository contains a custom Volatility 3 plugin, `ProcdumpCustom`, designed to extract process memory regions containing executable code (PE binaries) from a Windows memory dump. This work was completed as part of a digital forensics project at EURECOM.

## 📁 Repository Structure

```
├── procdump_custom.py         # The plugin file to be copied into the Volatility 3 plugin directory
├── README.md                  # This file
├── Procdump_Report.pdf        # Full technical report describing the project and development process
```

## 📦 Requirements

* Python 3.8 or newer
* pip / virtualenv
* Git

## 🧪 Tested On

* **Ubuntu 22.04**
* **Windows 7 x64 memory image (OtterCTF.vmem)**

## 🛠️ Installation Instructions

### 1. Clone Volatility 3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
```

### 2. Set Up a Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Place the Plugin

Copy the `procdump_custom.py` file from this repo into the Volatility 3 plugin folder:

```bash
cp /path/to/procdump_custom.py volatility3/plugins/windows/
```

### 4. Download the PDB Symbol Files (Optional but Recommended)

You can pre-download or let Volatility fetch them when running a plugin. Ensure you have internet access for that step.

### 5. Run the Plugin

Assuming your memory dump is in the root folder:

```bash
python3 vol.py -f OtterCTF.vmem windows.procdump_custom.ProcdumpCustom --dump-dir ./dumps
```

To restrict to a specific PID:

```bash
python3 vol.py -f OtterCTF.vmem windows.procdump_custom.ProcdumpCustom --dump-dir ./dumps --pid 1234
```

## 📂 Output

* The plugin will save `.dmp` files into the `--dump-dir` folder you specify.
* Each file corresponds to a VAD region of a process, labeled by its name, PID, and memory range.

## 🔍 Verifying Extracted Files

You can inspect the dumps using:

```bash
file ./dumps/*.dmp
strings ./dumps/explorer.exe_*.dmp | less
```

This allows validation of dumped executable format (e.g., PE32+) and discovery of human-readable content.

## 🧠 About This Project

This plugin was developed as part of a digital forensics course project. The full methodology, implementation steps, and evaluations are available in the provided `Procdump_Report.pdf`.

## 📄 License

This project is provided for educational and research purposes only.
