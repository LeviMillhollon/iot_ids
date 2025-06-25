📡 IoT IDS Toolkit
This is a lightweight, modular Intrusion Detection System (IDS) for monitoring and analyzing IoT network traffic, built with Python and Streamlit.


🔧 Installation
Make sure you have Python 3.8+ installed.

Install the required dependencies:

pip install scapy streamlit


▶️ How to Run
Clone or download this repository - git clone https://github.com/LeviMillhollon/iot_ids.git

Open a terminal in the directory where the files are located.

Run the dashboard:
"python -m streamlit run dashboard.py --server.port 8501 --browser.serverAddress localhost"

Streamlit will open the dashboard in your browser at http://localhost:8501. 
You may view the dashboard from other devices on the network with http://{host device IP}:8501
