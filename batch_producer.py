import pandas as pd
import json
import time
from azure.eventhub import EventHubProducerClient, EventData

# Load data
df_stream = pd.read_csv("pca_merged_logs.csv")
logs_list = df_stream.to_dict(orient='records')

# Azure Event Hub configuration
connection_str = "********************1"
eventhub_name = "stream1"

# Create Event Hub producer
producer = EventHubProducerClient.from_connection_string(
    conn_str=connection_str,
    eventhub_name=eventhub_name
)

# Define batch size
BATCH_SIZE = 10

# Stream logs in batches
with producer:
    for i in range(0, len(logs_list), BATCH_SIZE):
        batch_logs = logs_list[i:i+BATCH_SIZE]
        batch = [EventData(json.dumps(log, separators=(",", ":"))) for log in batch_logs]
        producer.send_batch(batch)

        print(f" Sent batch {i//BATCH_SIZE + 1} | Logs {i+1}–{i+len(batch)}")
        time.sleep(1.0)  # Delay between batches