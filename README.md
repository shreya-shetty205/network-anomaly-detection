# Network Anomaly Detection Using Machine Learning

This project implements a machine learning–based Network Anomaly Detection System to identify malicious or abnormal network traffic.  
It integrates ML models with a Flask web application and a Gemini-powered chatbot for explanations and security guidance.

---

## Features
- Network anomaly detection using ML models (KNN, RNN, LSTM)
- Real-time and input-based traffic analysis
- Web-based interface using Flask
- Gemini AI chatbot for attack explanation and prevention tips
- Secure handling of API keys using environment variables

---

## Project Structure
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
├── static/
├── training/
├── models/
└── data/ # Not included in GitHub



## Dataset
Datasets are not included in this repository due to GitHub file size limits.

Download datasets from:
- NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- CICIDS 2017: https://www.unb.ca/cic/datasets/ids-2017.html

After downloading, place all dataset files inside the `data/` folder.

---

## Setup Instructions

1. Clone the repository:
git clone https://github.com/USERNAME/REPO_NAME.git



2. Install dependencies:
pip install -r requirements.txt



3. Create a `.env` file in the project root (local only):
MAIL_USERNAME=your_email
MAIL_PASSWORD=your_email_password



## Run the Application
python app.py

Open your browser and go to:
http://127.0.0.1:5011



