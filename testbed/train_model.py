#!/usr/bin/env python3
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

def main():
    dataset_path = "dataset.csv"
    model_dir = "../data/models"
    model_path = os.path.join(model_dir, "esp_traffic_classifier.pkl")
    
    if not os.path.exists(dataset_path):
        print(f"Error: {dataset_path} not found. Did you run extract_features.py?")
        return
        
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    if df.empty:
        print("Error: Dataset is empty.")
        return
        
    print(f"Dataset loaded. Total flows: {len(df)}")
    print(f"Traffic distribution:\n{df['label'].value_counts()}\n")
    
    # Feature Selection: We ignore spi, src_ip, dst_ip as they are not behavioral characteristics
    features = ['packet_count', 'total_bytes', 'mean_packet_size', 'std_packet_size', 'mean_iat', 'std_iat']
    X = df[features]
    y = df['label']
    
    # In a real scenario with massive data, we'd split into train/test. 
    # With a small testbed dataset, we can still do a small split to evaluate.
    # If the dataset is too small, train_test_split might complain, so we check size.
    if len(df) > 20:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    else:
        print("Dataset very small, training and testing on the same set for demonstration.")
        X_train, X_test, y_train, y_test = X, X, y, y
        
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    clf.fit(X_train, y_train)
    
    print("Evaluating Model...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n--- AI Classification Results ---")
    print(f"Overall Accuracy: {accuracy * 100:.2f}%\n")
    
    # Display some sample predictions with AI Confidence Score
    print("Sample Predictions vs Ground Truth:")
    for i in range(min(5, len(y_test))):
        true_label = y_test.iloc[i]
        predicted_label = y_pred[i]
        # Get confidence for the predicted class
        class_idx = list(clf.classes_).index(predicted_label)
        confidence = y_prob[i][class_idx] * 100
        print(f"  Flow {i+1}: True=[{true_label:<4}] | Predicted=[{predicted_label:<4}] | AI Confidence: {confidence:.1f}%")
        
    # Save the model
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"\nModel saved successfully to: {model_path}")
    print("This model can now be loaded by the main API dashboard!")

if __name__ == "__main__":
    main()
