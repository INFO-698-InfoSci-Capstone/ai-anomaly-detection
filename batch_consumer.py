import json
import time
import sqlite3
import requests
import pandas as pd  # Added for NaN handling
from azure.eventhub import EventHubConsumerClient
from azure.eventhub import EventData
from slack_sdk import WebClient

# Azure Event Hubs connection details
connection_str = "******"
eventhub_name = "stream1"
consumer_group = "consumer_test"

# Slack configuration
SLACK_TOKEN = "***"
SLACK_CHANNEL = "**"
slack_client = WebClient(token=SLACK_TOKEN)

# SQLite database setup
conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

# Batch processing configuration
BATCH_SIZE = 5
BATCH_TIMEOUT = 3.0  # seconds

# Function to send Slack notification
def send_slack_notification(message):
    try:
        response = slack_client.chat_postMessage(channel=SLACK_CHANNEL, text=message)
        if not response["ok"]:
            print(f"[ERROR] Slack notification failed: {response['error']}")
    except Exception as e:
        print(f"[ERROR] Slack notification failed: {str(e)}")

# Callback for processing event batches
def on_event_batch(partition_context, events):
    if not events:
        print(f"No events received. Waiting {BATCH_TIMEOUT} seconds before processing the next batch...")
        return

    for event in events:
        try:
            # Parse event data
            event_str = event.body_as_str()
            # Replace various forms of NaN with '0.0' to make it JSON-compliant
            event_str = event_str.replace('nan', '0.0').replace('NaN', '0.0').replace('NAN', '0.0')
            log = json.loads(event_str)
            # Convert to DataFrame to handle any remaining NaN values
            df = pd.DataFrame([log])
            df = df.fillna(0.0)  # Replace NaN with 0.0
            log = df.to_dict('records')[0]  # Convert back to dictionary
            log['log_id'] = f"{log.get('Timestamp')}_{log.get('Source_IP_Address')}_{log.get('Destination_IP_Address')}"
        except Exception as e:
            print(f"[SKIP] Malformed log: {str(e)}")
            continue

        # Check for duplicates
        cursor.execute("SELECT log_id FROM logs WHERE log_id = ?", (log['log_id'],))
        if cursor.fetchone():
            print(f"[SKIP] Duplicate log: {log['log_id']}")
            continue

        # Make prediction request
        api_url = "http://localhost:8001/predict"  # Updated to port 8001
        headers = {"x-api-key": "streaminglogfastapi"}
        start_time = time.time()
        response = requests.post(api_url, json=log, headers=headers)
        api_time = time.time() - start_time

        if response.status_code == 200:
            prediction = response.json()
            pred_cleaned = prediction.get("Predicted_Traffic_Type", "Unknown").strip("[']").strip("']")
            anomaly_score = float(prediction.get("Anomaly_Score", 0.0))
            risk = prediction.get("Risk_Flag", "LOW")
            confidence = float(prediction.get("Confidence_Score", 0.0))  # Extract confidence score
        else:
            print(f"[ERROR] API request failed with status {response.status_code}: {response.text}")
            pred_cleaned = "Unknown"
            anomaly_score = 0.0
            risk = "LOW"
            confidence = 0.0  # Default to 0.0 if API fails

        # Prepare risk display
        risk_display = (
            f"\033[92mRisk: {risk:<9}\033[0m | Time: {log.get('Timestamp')} | "
            f"Proto: {log.get('Protocol'):<5} | Src IP: {log.get('Source_IP_Address'):<15} | "
            f"Dst IP: {log.get('Destination_IP_Address'):<15} | Anomaly: {anomaly_score:.3f} | "
            f"Prediction: {pred_cleaned:<20} | API Time: {api_time:.3f}s"
        )
        print(risk_display)

        # Insert into database
        try:
            cursor.execute("""
                INSERT INTO logs (timestamp, source_ip, destination_ip, protocol, anomaly_score, predicted_traffic_type, risk_flag, confidence_score, log_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log.get('Timestamp'),
                log.get('Source_IP_Address'),
                log.get('Destination_IP_Address'),
                log.get('Protocol'),
                anomaly_score,
                pred_cleaned,
                risk,
                confidence,  # Add confidence score
                log['log_id']
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            print(f"[SKIP] Duplicate log: {log['log_id']}")
            continue

        # Send Slack notification for high-risk anomalies
        if risk in ["HIGH", "CRITICAL"]:
            alert_message = (
                f"⚠️ High-Risk Anomaly Detected!\n"
                f"Timestamp: {log.get('Timestamp')}\n"
                f"Source IP: {log.get('Source_IP_Address')}\n"
                f"Destination IP: {log.get('Destination_IP_Address')}\n"
                f"Protocol: {log.get('Protocol')}\n"
                f"Anomaly Score: {anomaly_score:.3f}\n"
                f"Predicted Traffic Type: {pred_cleaned}\n"
                f"Risk Flag: {risk}"
            )
            send_slack_notification(alert_message)

    print(f"Processed batch of {len(events)} logs. Waiting {BATCH_TIMEOUT} seconds before processing the next batch...")

    # Commenting out checkpoint update to avoid PermissionError
    # if events:
    #     partition_context.update_checkpoint(events[-1])

# Callback for handling errors
def on_error(partition_context, error):
    print(f"[ERROR] Consumer error: {str(error)}")

# Main consumer logic
if __name__ == "__main__":
    print("Listening in batch mode using consumer group")
    client = EventHubConsumerClient.from_connection_string(
        conn_str=connection_str,
        consumer_group=consumer_group,
        eventhub_name=eventhub_name
    )

    try:
        with client:
            client.receive_batch(
                on_event_batch=on_event_batch,
                on_error=on_error,
                max_batch_size=BATCH_SIZE,
                starting_position="@latest"
            )
    except KeyboardInterrupt:
        print("Consumer stopped by user")
    finally:
        conn.close()
        print("Database connection closed")