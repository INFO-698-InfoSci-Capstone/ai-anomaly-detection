pip install catboost

from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from collections import Counter

# Load your PCA-merged dataset (if not already loaded)
df = pd.read_csv("pca_merged_logs.csv")

# Define target and feature columns
target = "Traffic_Type"
categorical_features = [
    "Protocol", "Packet_Type", "Device_Information", "Network_Segment",
    "Geo_location_Data", "Proxy_Information", "Log_Source"
]
numerical_features = [
    "Packet_Length", "Packet_Count", "Flow_Duration", "Payload_Entropy",
    "pca_anomaly_score"
]
features = categorical_features + numerical_features

# Drop rows with missing target
df = df.dropna(subset=[target])

# Split data
X = df[features]
y = df[target]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# Calculate inverse class weights
class_counts = Counter(y_train)
class_weights = {cls: 1/count for cls, count in class_counts.items()}

# Train CatBoost with class weights
model = CatBoostClassifier(
    verbose=0,
    random_seed=42,
    cat_features=categorical_features,
    class_weights=class_weights
)
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred, labels=model.classes_)
plt.figure(figsize=(10, 6))
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
            xticklabels=model.classes_, yticklabels=model.classes_)
plt.title(" Confusion Matrix: CatBoost with Class Weights")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

model.save_model("catboost_threat_model.cbm")