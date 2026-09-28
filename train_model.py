import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Load dataset
data = pd.read_csv("dataset.csv")

# Features
X = data[
    [
        "url_length",
        "has_https",
        "num_dots",
        "num_special_chars",
        "has_suspicious_keyword"
    ]
]

# Target
y = data["is_phishing"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Train model
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("Random Forest Model Training Complete!")
print("Accuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "phishguard_model.pkl")

print("\nModel saved as phishguard_model.pkl")