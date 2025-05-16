# 🛡️ PacketSentry

**PacketSentry** is a flow-based intrusion detection tool that processes PCAP files to extract statistical features from network flows and classify them as **benign** or **malicious** using a trained machine learning model. It supports both **offline analysis** and **live packet capture**, and outputs detailed flow-level CSV reports and a visual HTML chart of prediction probabilities.

## 🚀 Features

- 🔍 Flow extraction from PCAP files
- 📊 Extracts **14 statistical features** per flow
- 🤖 ML-based classification (Benign vs Malicious)
- 📁 CSV export with:
  - Flow features
  - Prediction probability
  - Predicted label
- 📈 HTML chart visualization of flow probabilities
- 🔌 Supports both:
  - **Offline PCAP analysis**
  - **Live capture mode** (`-live=true`)

## Prerequisite

- **Go**: Version 1.18 or higher
- **Python**: Version 3.6 or higher (for training and converting the model)
- **PCAP files**: For offline analysis
- **Linux**: Recommended for live capture mode (requires `sudo`)
- **Python Libraries**: `scikit-learn`, `numpy`, etc. (for training and converting the model)

## ⚙️ Setup Instructions

**Clone the Repository**
```bash
git clone https://github.com/your-username/PacketSentry.git
cd PacketSentry
```

**Create a Virtual Environment (for Python tools)**  
⚠️ Only needed if you're training or converting the model  
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r scripts/requirements.txt
```
This installs Python dependencies like `scikit-learn`, `joblib`, etc., used for preprocessing and model training.

## 🏗️ Build & Run

**Run in Offline Mode (PCAP)**

```bash
go run cmd/main.go -live=false -fname=test/redline -max=10000
```
parameters:

- `-live=false`: Run in offline mode
- `-fname=test/redline`: Path to the .pcap file (without extension)
- `-max`: (Optional) Max packet limit (default is unlimited)


**Run in Live Mode (Sniffing Interface)**

```bash
sudo go run cmd/main.go -live=true -interface=eth0 -max=10000
```
parameters:

- `-live=true`: Run in live capture mode
- `-max`: (Optional) Max packet limit (default is unlimited)
- `-interface=eth0`: Name of the network interface to sniff  
Run as sudo for live packet capture

## 📤 Output

After execution, you will get the following:

- **Processed Features** - `data/processed/<filename>_features.csv`
   
    Contains the 14 statistical features extracted per flow.
  
- **Prediction Results** - `data/results/<filename>.csv`
    
    Each row includes:
    - 14 features
    - 5-tuple metadata (src IP, dst IP, src port, dst port, protocol)
    - Probability (0–1)
    - Label (benign or malicious)

- **Flow Probability Chart** - `data/results/<filename>_chart.html`
   
    Opens in browser and shows the predicted malicious probabilities per flow.
