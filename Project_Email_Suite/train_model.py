# train_model.py
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import time

def plot_confusion_matrix(cm, labels, model_name, output_path):
    """Plots and saves the confusion matrix."""
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=labels, yticklabels=labels, cmap="Blues")
    plt.title(f"Confusion Matrix - {model_name}")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Saved confusion matrix to {output_path}")

def main():
    """Trains, evaluates, and saves multiple ML models."""
    os.makedirs("models", exist_ok=True)
    os.makedirs("results", exist_ok=True)

    # Load dataset
    csv_path = "data/dataset.csv"
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["text", "label"])

    X = df['text'].astype(str)
    y = df['label'].astype(str)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples.")

    # Define model pipelines
    pipelines = {
        "Naive_Bayes": Pipeline([
            ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ('clf', MultinomialNB())
        ]),
        "Linear_SVC": Pipeline([
            ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ('clf', LinearSVC(random_state=42))
        ])
    }

    # Train and evaluate each model
    for name, pipeline in pipelines.items():
        print(f"\n--- Training {name} model ---")
        start_time = time.time()
        pipeline.fit(X_train, y_train)
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds.")

        # Evaluate
        y_pred = pipeline.predict(X_test)
        
        # Save classification report
        report = classification_report(y_test, y_pred, output_dict=True)
        report_df = pd.DataFrame(report).transpose()
        report_path = f"results/report_{name}.csv"
        report_df.to_csv(report_path)
        print(f"Saved classification report to {report_path}")
        print(report_df)

        # Save confusion matrix
        labels = sorted(y.unique())
        cm = confusion_matrix(y_test, y_pred, labels=labels)
        cm_path = f"results/confmat_{name}.png"
        plot_confusion_matrix(cm, labels, name, cm_path)

        # Save model pipeline using joblib
        model_path = f"models/email_classifier_{name}.pkl"
        joblib.dump(pipeline, model_path)
        print(f"Saved trained model to {model_path}")

if __name__ == "__main__":
    main()
    