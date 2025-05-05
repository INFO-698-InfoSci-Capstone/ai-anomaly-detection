from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import pandas as pd
from catboost import CatBoostClassifier

# Initialize FastAPI app
app = FastAPI()

# Define the API key (you can change this to a secure value)
API_KEY = "streaminglogfastapi"

# Dependency to check the API key
async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key

# Load the CatBoost model
model = CatBoostClassifier()
model.load_model("catboost_threat_model.cbm")

# Define the features
features = [
    "Protocol", "Packet_Type", "Device_Information", "Network_Segment",
    "Geo_location_Data", "Proxy_Information", "Log_Source",
    "Packet_Length", "Packet_Count", "Flow_Duration", "Payload_Entropy",
    "pca_anomaly_score"
]

# Define the input model for FastAPI
class LogInput(BaseModel):
    Protocol: str
    Packet_Type: str
    Device_Information: str
    Network_Segment: str
    Geo_location_Data: str
    Proxy_Information: str
    Log_Source: str
    Packet_Length: float
    Packet_Count: float
    Flow_Duration: float
    Payload_Entropy: float
    pca_anomaly_score: float

# Prediction endpoint with API key authentication
@app.post("/predict", dependencies=[Depends(verify_api_key)])
async def predict(log: LogInput):
    try:
        # Convert input to DataFrame
        df = pd.DataFrame([log.dict()], columns=features)

        # Perform prediction with CatBoost
        prediction = model.predict(df)[0]
        prediction_cleaned = str(prediction).strip("[']").strip("']")  # Remove [' and '] from the prediction
        probabilities = model.predict_proba(df)[0]  # Get probabilities for each class
        confidence = float(max(probabilities))  # Use the highest probability as the confidence score

        # Calculate risk flag
        anomaly_score = log.pca_anomaly_score
        risk = (
            "CRITICAL" if prediction_cleaned != "Normal" and anomaly_score > 0.05
            else "HIGH" if prediction_cleaned != "Normal"
            else "MEDIUM" if anomaly_score > 0.05
            else "LOW"
        )

        # Return the result
        return {
            "Predicted_Traffic_Type": prediction_cleaned,  # Use the cleaned prediction
            "Anomaly_Score": anomaly_score,
            "Risk_Flag": risk,
            "Confidence_Score": confidence  # Add confidence score to response
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)  # Running on port 8001