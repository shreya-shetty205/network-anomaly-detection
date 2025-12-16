from flask import Flask,render_template,request,session,redirect,jsonify,flash, url_for
import mysql.connector
from hashlib import sha256
import joblib
import ast
import os
import numpy as np
import google.generativeai as genai

import pandas as pd
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder, StandardScaler
from werkzeug.security import generate_password_hash, check_password_hash
import random
from flask_mail import Mail, Message
import pyshark
import asyncio
from dotenv import load_dotenv
load_dotenv()



app=Flask(__name__)


model_dir = 'models'


app.secret_key = 'zambdbdb'

db_config = {
    'host': 'localhost',
    'user': 'root',           # Replace with your MySQL username
    'password': '',       # Replace with your MySQL password
    'database': 'network',        # Replace with your MySQL database name
}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # from .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # from .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)


genai.configure(api_key="GOOGLE_API_KEY")   # ✅ Replace with your key
genmodel = genai.GenerativeModel('gemini-2.0-flash')


def get_db_connection():
    return mysql.connector.connect(**db_config)


def hash_password(password):
    return sha256(password.encode()).hexdigest()



loaded_models = {
    'KNN': joblib.load(os.path.join(model_dir, 'knn_model.pkl')),
    # 'MLP': tf.keras.models.load_model(os.path.join(model_dir, 'mlp_model.h5')),
    'RNN': tf.keras.models.load_model(os.path.join(model_dir, 'rnn_model.h5')),
    'LSTM': tf.keras.models.load_model(os.path.join(model_dir, 'lstm_model.h5'))
}

loaded_encoders = joblib.load(os.path.join(model_dir, 'label_encoders.pkl'))
loaded_scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))

feature_columns_for_prediction = ['0', 'tcp', 'ftp_data', 'SF', '491', '0.1', '0.2', '0.3', '0.4', '0.5',
    '0.6', '0.7', '0.8', '0.9', '0.10', '0.11', '0.12', '0.13', '0.14',
    '0.15', '0.16', '0.18', '2', '2.1', '0.00', '0.00.1', '0.00.2',
    '0.00.3', '1.00', '0.00.4', '0.00.5', '150', '25', '0.17', '0.03',
    '0.17.1', '0.00.6', '0.00.7', '0.00.8', '0.05', '0.00.9', '20']

categorical_indices = [1, 2, 3]  # 'tcp', 'ftp_data', 'SF'



def predict_realtime(data_point, models, encoders, scaler, feature_columns, rnn_lstm_reshape=True):
    data_series = pd.Series(data_point, index=feature_columns)

    # Apply label encoding to categorical features
    for col in ['tcp', 'ftp_data', 'SF']:
        if col in encoders:
            try:
                data_series[col] = encoders[col].transform([data_series[col]])[0]
            except ValueError:
                data_series[col] = -1  # Assign a default for unseen category

    # Scale data
    data_scaled = scaler.transform([data_series.values])
    predictions = {}

    # Predict with each model
    for model_name, model in models.items():
        try:
            if model_name in ['RNN', 'LSTM'] and rnn_lstm_reshape:
                reshaped = data_scaled.reshape(data_scaled.shape[0], 1, data_scaled.shape[1])
                pred_proba = model.predict(reshaped)
                predicted_class_index = np.argmax(pred_proba, axis=1)[0]
            else:
                if hasattr(model, 'predict_proba'):
                    pred_proba = model.predict_proba(data_scaled)
                    predicted_class_index = np.argmax(pred_proba, axis=1)[0]
                else:
                    predicted_class_index = model.predict(data_scaled)[0]

            predicted_label = encoders['label'].inverse_transform([predicted_class_index])[0]
            predictions[model_name] = predicted_label

        except Exception as e:
            predictions[model_name] = f"Error: {e}"

    return predictions


attack_info = {
    "DoS": {
        "info": (
            "A Denial-of-Service (DoS) attack targets the availability of a system by overloading "
            "it with massive traffic or resource-intensive requests. The goal is to exhaust CPU, RAM, "
            "bandwidth, or application threads so that legitimate users cannot access the service. "
            "Attackers may use SYN floods, UDP floods, ICMP floods, or malformed packets. Large-scale "
            "attacks performed using hundreds of infected devices are called Distributed DoS (DDoS)."
        ),
        "tips": [
            "Use firewalls, traffic filtering, and rate-limiting rules to block malicious spikes.",
            "Deploy DDoS protection tools such as Cloudflare, AWS Shield, or Akamai.",
            "Use load balancers to distribute traffic and reduce overload impact.",
            "Enable SYN cookies to protect against SYN flood attacks.",
            "Monitor network traffic for unusual spikes or repeated requests from a single IP.",
            "Isolate critical services behind reverse proxies and CDNs.",
            "Keep servers patched to avoid protocol-based DoS vulnerabilities.",
            "Maintain an incident response plan for emergency traffic mitigation."
        ]
    },

    "Probe": {
        "info": (
            "Probe attacks (reconnaissance attacks) are early-stage intrusion attempts where attackers "
            "scan a network to discover open ports, running services, OS versions, software details, "
            "and potential vulnerabilities. Tools like Nmap, Nessus, and Masscan are commonly used. "
            "Probing is often a precursor to more serious attacks like exploitation or penetration."
        ),
        "tips": [
            "Disable unused ports and shutdown unnecessary services.",
            "Use Intrusion Detection Systems (IDS) such as Snort or Suricata to detect scanning attempts.",
            "Enable firewall rules that restrict access to internal or sensitive ports.",
            "Run periodic security scans to find vulnerabilities before attackers do.",
            "Use network segmentation to limit what information probes can gather.",
            "Monitor logs for repeated port hits or scanning patterns.",
            "Enable stealth mode on routers and disable ICMP replies where appropriate.",
            "Regularly update firmware, OS, and services to eliminate known weaknesses."
        ]
    },

    "R2L": {
        "info": (
            "Remote-to-Local (R2L) attacks occur when an attacker with no local account attempts to "
            "gain access to a machine remotely. These attacks exploit weak credentials, open remote "
            "ports, social engineering, phishing, insecure services (FTP, Telnet), or unpatched "
            "vulnerabilities. Once inside, attackers may steal data or escalate privileges."
        ),
        "tips": [
            "Use strong passwords, password rotation, and multi-factor authentication (MFA).",
            "Limit remote access to trusted IP ranges (IP whitelisting).",
            "Disable insecure remote protocols like Telnet and enable SSH instead.",
            "Regularly review remote login logs for unusual access attempts.",
            "Enforce account lockout policies after repeated failed login attempts.",
            "Educate employees to recognize phishing emails and malicious attachments.",
            "Implement endpoint security (EDR) and continuous threat monitoring.",
            "Use VPN access with strong encryption for remote employees."
        ]
    },

    "U2R": {
        "info": (
            "User-to-Root (U2R) attacks involve privilege escalation, where an attacker with normal "
            "user access exploits system vulnerabilities to gain administrative or root-level control. "
            "Common methods include abusing SUID programs, kernel exploits, buffer overflows, or "
            "misconfigured access controls. U2R attacks can completely compromise the system."
        ),
        "tips": [
            "Follow the principle of least privilege for all user accounts.",
            "Patch the OS and all software regularly to remove privilege escalation exploits.",
            "Restrict execution of SUID/SGID binaries and monitor changes to them.",
            "Use SELinux, AppArmor, or RBAC to restrict permissions and system-level access.",
            "Enable logging and alerting for suspicious privilege elevation attempts.",
            "Use containerization or sandboxing to isolate applications.",
            "Audit system file permissions frequently to detect misconfigurations.",
            "Disable root login where possible and use sudo with strict permissions."
        ]
    },

    "Normal": {
        "info": (
            "The network behavior appears normal. No suspicious patterns, anomaly signatures, or "
            "malicious traffic types were detected. Existing traffic matches typical usage patterns, "
            "and the system is operating within expected thresholds."
        ),
        "tips": [
            "Continue regular monitoring of system and network activity.",
            "Maintain updated firewall rules and intrusion detection configurations.",
            "Perform scheduled vulnerability scans and system audits.",
            "Keep backups updated and stored securely offline.",
            "Educate users about security best practices and emerging threats.",
            "Regularly review logs and analytics to detect early warning signs.",
            "Ensure antivirus and endpoint protection systems stay updated.",
            "Periodically test incident response plans for preparedness."
        ]
    }
}


def ensure_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)



def get_interface():
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()

    for iface in interfaces:
        if "loopback" in iface.lower():
            continue
        try:
            cap = pyshark.LiveCapture(interface=iface)
            packets = cap.sniff(timeout=1)
            if packets:
                return iface
        except:
            pass

    raise Exception("No active interface found.")


# -------------------------------------------------------
# LIVE PACKET CAPTURE USING PYSHARK
# -------------------------------------------------------
# def capture_live_packet_pyshark():
#     interface_name = get_interface() 

#     capture = pyshark.LiveCapture(interface=interface_name)

#     packets = capture.sniff(timeout=2)  # capture 1–2 seconds of traffic

#     print(packets,"dfdf")

#     if len(packets) == 0:
#         raise Exception("No packet captured. Try again or change interface name.")

#     packet = packets[0]

#     extracted = {col: 0 for col in feature_columns_for_prediction}

#     # Basic fields
#     if hasattr(packet, "length"):
#         extracted['0'] = int(packet.length)

#     proto = packet.highest_layer.lower()
#     extracted['tcp'] = 'tcp' if 'tcp' in proto else ('udp' if 'udp' in proto else 'other')

#     if hasattr(packet, 'tcp'):
#         extracted['ftp_data'] = 'ftp_data' if int(packet.tcp.dstport) == 20 else 'other'
#         extracted['SF'] = "SF" if packet.tcp.flags == "0x002" else "S0"
#     else:
#         extracted['ftp_data'] = "other"
#         extracted['SF'] = "SF"

#     if hasattr(packet, "ip"):
#         extracted['491'] = int(packet.ip.ttl)
#         extracted['2'] = int(packet.ip.len)

#     extracted['20'] = float(packet.sniff_timestamp)

#     ordered_values = [extracted[c] for c in feature_columns_for_prediction]
#     return ordered_values




from scapy.all import sniff, IP, TCP, UDP

def capture_live_packet_scapy():
    # Capture 1 packet from ANY interface
    packet = sniff(count=1, timeout=3)[0]

    extracted = {col: 0 for col in feature_columns_for_prediction}

    # Packet length
    extracted['0'] = len(packet)

    # Protocol
    if packet.haslayer(TCP):
        extracted['tcp'] = "tcp"
    elif packet.haslayer(UDP):
        extracted['tcp'] = "udp"
    else:
        extracted['tcp'] = "other"

    # ftp_data (port 20)
    if packet.haslayer(TCP):
        extracted['ftp_data'] = "ftp_data" if packet[TCP].dport == 20 else "other"
        extracted['SF'] = "SF" if packet[TCP].flags == "S" else "S0"
    else:
        extracted['ftp_data'] = "other"
        extracted['SF'] = "SF"

    # TTL
    if packet.haslayer(IP):
        extracted['491'] = packet[IP].ttl
        extracted['2'] = packet[IP].len

    # timestamp
    extracted['20'] = packet.time

    # output ordered features
    return [extracted[c] for c in feature_columns_for_prediction]

@app.route("/")
def index():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template("index.html")





@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if hash_password(password) == user['password']:
                session['user_id'] = user['u_id']
                session['username'] = user['uname']
                session['uemail'] = user['email']

                flash("✅ Login successful!", "success")
                return redirect(url_for('index'))     # <-- GOOD
            else:
                flash("❌ Invalid email or password.", "danger")
        else:
            flash("❌ Invalid email or password.", "danger")

        # ❗ ALWAYS redirect on POST (even when invalid)
        return redirect(url_for('login'))

    return render_template('login.html')



# ---------------- REGISTER ----------------
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("⚠️ Email already exists. Try another one.", "warning")
            connection.close()
            return redirect(url_for('register'))     # <-- redirect after POST

        hashed_password = hash_password(password)
        cursor.execute(
            "INSERT INTO user (uname, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        connection.commit()
        connection.close()

        flash("✅ Registration successful! Please log in.", "success")
        return redirect(url_for('login'))            # <-- redirect after POST

    return render_template('register.html')



@app.route("/logout")
def logout():
    session.clear()  # clears all session data
    flash("Logout successful!", "success")  # Flash message that shows only once
    return redirect(url_for("login"))  # Redirect instead of rendering directly


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash("❌ No account found with that email.", "danger")
            return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))

        # Store OTP in session (not database)
        session['reset_email'] = email
        session['reset_otp'] = otp

        msg = Message(
            subject='Password Reset Code',
            recipients=[email]
        )
        msg.body = f"""
Hello {email},

Your OTP for resetting password is: {otp}

If you did not request this, ignore the email.

– NetSecureAI
"""
        mail.send(msg)

        flash("✅ OTP sent to your email.", "success")
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')



# --------------------------
# Reset Password Route
# --------------------------
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['password']

        saved_otp = session.get('reset_otp')
        email = session.get('reset_email')

        if otp != saved_otp:
            flash("❌ Invalid or expired OTP.", "danger")
            return redirect(url_for('reset_password'))

        conn = get_db_connection()
        cursor = conn.cursor()

        hashed_pass = hash_password(new_password)   # <-- FIXED HERE

        cursor.execute("UPDATE user SET password = %s WHERE email = %s",
                       (hashed_pass, email))
        conn.commit()
        conn.close()

        session.pop('reset_otp', None)
        session.pop('reset_email', None)

        flash("✅ Password reset successful!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')






@app.route('/predict', methods=['POST','GET'])
def predict():
    if request.method == 'GET':
        return render_template('detection.html')  

    data = request.get_json() or {}
    if 'input_string' not in data:
        return jsonify({"error": "Missing 'input_string' in request"}), 400

    input_values_raw = data['input_string'].split(',')
    input_feature_values = input_values_raw[:42]

    if len(input_feature_values) != len(feature_columns_for_prediction):
        return jsonify({
            "error": f"Input values count ({len(input_feature_values)}) does not match expected feature count ({len(feature_columns_for_prediction)})."
        }), 400

    processed_input_values = []
    for i, value in enumerate(input_feature_values):
        if i in categorical_indices:
            processed_input_values.append(value)
        else:
            try:
                processed_input_values.append(float(value) if '.' in value else int(value))
            except ValueError:
                processed_input_values.append(value)

    predictions = predict_realtime(
        processed_input_values,
        loaded_models,
        loaded_encoders,
        loaded_scaler,
        feature_columns_for_prediction
    )

    # Attack info and prevention tips
    

    # Find the most common prediction among models
    most_common_prediction = max(set(predictions.values()), key=list(predictions.values()).count)

    # Normalize to match keys in attack_info
    key_map = {
        "normal": "Normal",
        "dos": "DoS",
        "probe": "Probe",
        "r2l": "R2L",
        "u2r": "U2R"
    }
    key = key_map.get(most_common_prediction.lower(), None)

    info = attack_info.get(key, {
        "info": "Unknown attack type.",
        "tips": ["No specific prevention tips available."]
    })

    # ✅ Calculate confidence score
    total_models = len(predictions)
    prediction_counts = {pred: list(predictions.values()).count(pred) for pred in set(predictions.values())}
    confidence_scores = {model: f"{(prediction_counts[pred]/total_models)*100:.2f}%" 
                         for model, pred in predictions.items()}

    return jsonify({
        "predictions": predictions,
        "confidence": confidence_scores,
        "attack_info": info["info"],
        "prevention_tips": info["tips"]
    })


@app.route('/live-detect', methods=['GET'])
def live_detect():
    try:
        ensure_event_loop()

        live_features = capture_live_packet_scapy()

        predictions = predict_realtime(
            live_features,
            loaded_models,
            loaded_encoders,
            loaded_scaler,
            feature_columns_for_prediction
        )

        majority = max(set(predictions.values()), key=list(predictions.values()).count)

        key_map = {"normal": "Normal", "dos": "DoS", "probe": "Probe", "r2l": "R2L", "u2r": "U2R"}
        key = key_map.get(majority.lower(), "Normal")

        total = len(predictions)
        counts = {p: list(predictions.values()).count(p) for p in set(predictions.values())}
        confidence = {m: f"{(counts[p] / total) * 100:.2f}%" for m, p in predictions.items()}

        return jsonify({
            "predictions": predictions,
            "confidence": confidence,
            "attack_info": attack_info[key]["info"],
            "prevention_tips": attack_info[key]["tips"],
            "live_packet_data": dict(zip(feature_columns_for_prediction, live_features))
   
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/methodology")
def methodology():
    return render_template("methodology.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route('/chatbot', methods=['POST'])
def chatbot():
    """
    Chatbot for explaining attacks, network data, and ML predictions.
    Uses your attack_info + Gemini model for detailed responses.
    """

    user_msg = request.json.get("message", "").strip()

    if not user_msg:
        return jsonify({"reply": "⚠️ Please enter a message."})

    # ----------------------------
    # 1. Include your attack_info
    # ----------------------------
    attack_info_block = ""
    for key, data in attack_info.items():
        attack_info_block += f"\n\n### {key} Attack\nDescription: {data['info']}\nTips: {', '.join(data['tips'])}\n"

    # ----------------------------
    # 2. Build Context for Model
    # ----------------------------
    system_context = f"""
You are NetSecureAI — a assistant integrated into an Intrusion Detection System.

You can explain:
- Network attack types (DoS, Probe, R2L, U2R, Normal)
- Sub-attacks and their mapping
- Live network packet analysis
- NSL-KDD features
- Predictions from ML models (KNN, RNN, LSTM)
- Prevention tips
- Real-time threat interpretation

Here is the attack classification knowledge base:

{attack_info_block}

Always answer clearly, professionally and relate answers to network security.
"""

    # ----------------------------
    # 3. Get AI Response
    # ----------------------------
    try:
        response = genmodel.generate_content(
            system_context + "\nUser Query: " + user_msg
        )

        bot_reply = response.text

    except Exception as e:
        bot_reply = f"Error generating response: {e}"

    return jsonify({"reply": bot_reply})




if __name__=='__main__':
    app.run(debug=True,port=5011)