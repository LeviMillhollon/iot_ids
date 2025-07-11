📡 IoT IDS Toolkit
This is a lightweight, Plug-N-Play modular Intrusion Detection System (IDS) for monitoring and analyzing IoT network traffic, built with Python and Streamlit on aRaspberry PI 4.

FLash sd-card with Raspberry lite OS

- CONFIGURE RP4        -
- user:admin, pass:     -
- timezone             -


🔧 Installation
Check python version
$ python --version
Make sure you have Python 3.8+ installed.

Install nmap
$ sudo apt install nmap

Install the required dependencies:
****  may need to activate VENV ****
$ pip install scapy streamlit pandas requests netifaces

Clone or download this repository - 
$ sudo git clone https://github.com/LeviMillhollon/iot_ids.git

Open a terminal in the directory where the files are located.

"python -m streamlit run dashboard.py --server.port 8501 --browser.serverAddress localhost"

Streamlit will open the dashboard in your browser at http://localhost:8501. 
You may view the dashboard from other devices on the network with http://{host device IP}:8501

start scanning with "python ./packet_scanner.py"
