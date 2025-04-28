from flask import Flask, jsonify, render_template
import subprocess
import time
import pandas as pd
import joblib
import warnings
import datetime
from collections import defaultdict, deque
warnings.filterwarnings('ignore')

app = Flask(__name__, template_folder="templates")


latest_prediction = {
    "status": "Starting...",
    "latest_label": "N/A",
    "total_malicious": 0,
    "total_packets": 0,
    "logs": []
}


alert_history = deque(maxlen=100)  
prediction_counts = defaultdict(int) 
prediction_history = defaultdict(lambda: deque(maxlen=20)) 

def initialize_data():
    prediction_counts["Benign"] = 0
    prediction_counts["DoS"] = 0
    prediction_counts["Port Scan"] = 0
    

    for i in range(10):
        timestamp = (datetime.datetime.now() - datetime.timedelta(minutes=i)).strftime("%H:%M:%S")
        alert_history.appendleft({
            "timestamp": timestamp,
            "benign_count": 0,
            "malicious_count": 0,
            "total_count": 0
        })

def start_packet_capture(interface="ens33", host="192.168.202.128", port="5000", capture_duration=15):
    print("Starting packet capture...")
    capture_command = [
        "sudo", "tshark",
        "-i", interface,
        "-f", f"host {host} and port {port}",
        "-w", "/tmp/test.pcap"
    ]
    capture_process = subprocess.Popen(capture_command)
    time.sleep(capture_duration)
    capture_process.terminate()
    print("Packet capture completed.")

def extract_features_from_pcap():
    print("Extracting features...")
    extract_command = [
        "tshark", 
        "-r", "/tmp/test.pcap",
        "-T", "fields", 
        "-E", "header=y", 
        "-E", "separator=,", 
        "-E", "quote=d", 
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.len", "-e", "ip.flags.df", "-e", "ip.flags.mf", 
        "-e", "ip.fragment", "-e", "ip.fragment.count", "-e", "ip.fragments", "-e", "ip.ttl", "-e", "ip.proto",
        "-e", "tcp.window_size", "-e", "tcp.ack", "-e", "tcp.seq", "-e", "tcp.len", "-e", "tcp.stream", 
        "-e", "tcp.urgent_pointer", "-e", "tcp.flags", "-e", "tcp.analysis.ack_rtt", "-e", "tcp.segments", 
        "-e", "tcp.reassembled.length", "-e", "http.request", "-e", "udp.port", "-e", "frame.time_relative", 
        "-e", "frame.time_delta", "-e", "tcp.time_relative", "-e", "tcp.time_delta"
    ]
    
    with open("test.csv", "w") as f:
        try:
            subprocess.run(extract_command, stdout=f, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running tshark: {e}")
            f.write("ip.src,ip.dst,ip.len,ip.flags.df\n")
            f.write("0,0,0,0\n")
            
    print("Feature extraction completed. Data saved to test.csv.")

def process_data_for_prediction(file_path="test.csv"):
    df = pd.read_csv(file_path)
    df.fillna(0, inplace=True)
    
    df['ip.flags.df'].fillna(0, inplace=True)
    
    df['ip.src'] = df['ip.src'].apply(lambda x: int(str(x).replace('.', '')) if pd.notnull(x) else 0)
    df['ip.dst'] = df['ip.dst'].apply(lambda x: int(str(x).replace('.', '')) if pd.notnull(x) else 0)
    
    df['ip.len'] = df['ip.len'].astype('Int64')
    df['ip.flags.df'] = df['ip.flags.df'].astype('Int64')
    df['ip.flags.mf'] = df['ip.flags.mf'].astype('Int64')
    df['ip.fragment'] = df['ip.fragment'].astype('int64')
    df['ip.fragment.count'] = df['ip.fragment.count'].astype('int64')
    df['ip.fragments'] = df['ip.fragments'].astype('int64')
    df['ip.ttl'] = df['ip.ttl'].astype('Int64')
    df['ip.proto'] = df['ip.proto'].astype('Int64')
    df['tcp.window_size'] = df['tcp.window_size'].astype('float64')
    df['tcp.ack'] = df['tcp.ack'].astype('float64')
    df['tcp.seq'] = df['tcp.seq'].astype('float64')
    df['tcp.len'] = df['tcp.len'].astype('float64')
    df['tcp.stream'] = df['tcp.stream'].astype('float64')
    df['tcp.urgent_pointer'] = df['tcp.urgent_pointer'].astype('float64')
    df['tcp.flags'] = df['tcp.flags'].apply(lambda x: float(int(x, 16)) if isinstance(x, str) and x.startswith('0x') else float(x))
    df['tcp.analysis.ack_rtt'] = df['tcp.analysis.ack_rtt'].astype('float64')
    df['tcp.segments'] = df['tcp.segments'].astype('int64')
    df['tcp.reassembled.length'] = df['tcp.reassembled.length'].astype('int64')
    df['http.request'] = df['http.request'].astype('int64')
    df['udp.port'] = pd.to_numeric(df['udp.port'], errors='coerce')  
    df['frame.time_relative'] = df['frame.time_relative'].astype('float64')
    df['frame.time_delta'] = df['frame.time_delta'].astype('float64')
    df['tcp.time_relative'] = df['tcp.time_relative'].astype('float64')
    df['tcp.time_delta'] = df['tcp.time_delta'].astype('float64')
    
    return df

def predict_and_update_dashboard(df, model, label_encoder):
    predictions = model.predict(df)
    results = label_encoder.inverse_transform(predictions)

    print("Predictions:", results)

    labels_series = pd.Series(results)
    most_repeated_label = labels_series.mode()[0]

    for label in results:
        prediction_counts[label] += 1

    benign_count = sum(1 for label in results if label.lower() == 'benign')
    malicious_count = len(results) - benign_count

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    alert_history.append({
        "timestamp": timestamp,
        "benign_count": benign_count,
        "malicious_count": malicious_count,
        "total_count": len(results)
    })

    total_malicious = sum(label.lower() != 'benign' for label in results)
    total_packets = len(results)
    logs = []
    data = pd.read_csv("test.csv")

    num_packets = min(1000, len(results))

    for i in range(num_packets):
        logs.append({
            "timestamp": str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "ip_src": str(data.iloc[i]["ip.src"]) if "ip.src" in data.columns else "N/A",
            #"src_port": str(data.iloc[i]["tcp.srcport"]) if "tcp.srcport" in data.columns else (str(data.iloc[i]["udp.port"]) if "udp.port" in data.columns else ""),
            "ip_dst": str(data.iloc[i]["ip.dst"]) if "ip.dst" in data.columns else "N/A",
            #"dst_port": str(data.iloc[i]["tcp.dstport"]) if "tcp.dstport" in data.columns else "",
            "protocol": str(data.iloc[i]["ip.proto"]) if "ip.proto" in data.columns else "",
            "length": str(data.iloc[i]["ip.len"]) if "ip.len" in data.columns else "",
            "prediction": results[i],
            "severity": "High" if results[i].lower() != "benign" else "Low",
            "action": "Alert" if results[i].lower() != "benign" else "Allow",
            "color_class": "benign" if results[i].lower() == 'benign' else "malicious"
        })

    latest_prediction.update({
        "status": "Completed",
        "latest_label": most_repeated_label,
        "total_malicious": total_malicious,
        "total_packets": total_packets,
        "logs": logs
    })

def run_ids_once():
    model = joblib.load("idsrandomforest.pkl")
    label_encoder = joblib.load("idslabel_encoder.pkl")

    latest_prediction["status"] = "Capturing packets..."

    try:
        start_packet_capture()
        extract_features_from_pcap()
        df = process_data_for_prediction()
        predict_and_update_dashboard(df, model, label_encoder)
    except Exception as e:
        latest_prediction["status"] = f"Error: {str(e)}"
        print(f"Error in IDS process: {e}")

@app.route("/", methods=["GET"])
def index():
    return render_template("dashboard.html")

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify(latest_prediction)


@app.route("/api/chart/prediction-distribution", methods=["GET"])
def prediction_distribution():

    filtered = [(label, count) for label, count in prediction_counts.items() if count > 0]
    if not filtered:
        filtered = [("No data", 1)]
        background_colors = ["#444"]
    else:
        colors = {
            "benign": "#34a853",
            "ddos": "#ea4335",
            "port scan": "#fbbc05",
            "bruteforce": "#4285f4",
            "sql injection": "#7f5af0",
            "xss": "#f15bb5",
        }
        background_colors = [colors.get(label.lower(), "#7f5af0") for label, _ in filtered]

    labels = [label for label, _ in filtered]
    values = [count for _, count in filtered]

    return jsonify({
        "labels": labels,
        "datasets": [{
            "data": values,
            "backgroundColor": background_colors,
            "hoverOffset": 4,
            "borderWidth": 0
        }]
    })


@app.route("/api/chart/detection-history", methods=["GET"])
def detection_history():
    """Returns data for line chart showing detection trends over time"""
    timestamps = [entry["timestamp"] for entry in alert_history]
    malicious_counts = [entry["malicious_count"] for entry in alert_history]
    benign_counts = [entry["benign_count"] for entry in alert_history]
    
    return jsonify({
        "labels": timestamps,
        "datasets": [
            {
                "label": "Malicious Traffic",
                "data": malicious_counts,
                "borderColor": "#ef4444",
                "backgroundColor": "rgba(239, 68, 68, 0.2)",
                "tension": 0.4,
                "fill": True
            },
            {
                "label": "Benign Traffic",
                "data": benign_counts,
                "borderColor": "#10b981",
                "backgroundColor": "rgba(16, 185, 129, 0.1)",
                "tension": 0.4,
                "fill": True
            }
        ]
    })

@app.route("/api/start-capture", methods=["POST"])
def start_capture():
    latest_prediction["status"] = "Capturing packets..."
    run_ids_once()
    return jsonify({"message": "Capture completed successfully!"})

@app.route("/api/repeat-capture", methods=["GET"])
def repeat_capture():
    run_ids_once()
    return jsonify(latest_prediction)
@app.route("/api/chart/traffic-volume", methods=["GET"])
def traffic_volume():
    """Returns data for network traffic volume over time"""
    timestamps = [entry["timestamp"] for entry in alert_history]
    total_counts = [entry["total_count"] for entry in alert_history]
    return jsonify({
        "labels": timestamps,
        "datasets": [
            {
                "label": "Network Traffic Volume",
                "data": total_counts,
                "borderColor": "#4285f4",
                "backgroundColor": "rgba(66,133,244,0.2)",
                "tension": 0.4,
                "fill": True
            }
        ]
    })



if __name__ == "__main__":
    initialize_data()
    run_ids_once()
    app.run(host="0.0.0.0", port=8000, debug=False)
