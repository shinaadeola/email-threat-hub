# Email Threat Analysis Tool
**Final Year Undergraduate Cybersecurity Project**

## Overview
This project is an advanced cybersecurity application that leverages the Unsupervised **Isolation Forest** machine learning algorithm to detect email-based threats, such as Spam and Phishing attempts. 

Unlike traditional semantic filters that rely on keyword dictionaries (which can be easily evaded by attackers), this system evaluates the **Structural Metadata** of an email. 

## How It Works
The system evaluates plain text input and extracts 8 key structural features:
1. Total Character Length
2. Hidden HTML Tags (e.g., `<script>`, `<b>`)
3. Clickable URLs/Links
4. Exclamation Mark Frequency
5. Dollar Sign Frequency
6. ALL CAPS Ratio
7. Urgent Keyword Count ("urgent", "immediate", "action required")
8. Account Keyword Count ("account", "suspend", "verify")

These vectors are passed into the `IsolationForest` model (trained with a Contamination threshold of 0.1). The model calculates an Anomaly Score. Negative scores indicate statistically significant structural anomalies characteristic of malicious payloads.

## Tech Stack
- **Backend:** Flask (Python)
- **Machine Learning Engine:** scikit-learn (Isolation Forest)
- **Feature Processing:** regex, NumPy, pandas
- **Frontend UI:** HTML, CSS

## Running Locally
1. Clone the repository.
2. Ensure you are using Python 3.8+. 
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the Flask server:
   ```bash
   flask run
   ```
5. Navigate to `http://localhost:5000` in your web browser.

## Repository Structure
- `app.py`: The Main Flask API and Server instance.
- `train.py`: The data-ingestion pipeline used to originally train the model.
- `models/`: Contains the serialized `isoforest.pkl` model and `scaler.pkl`.
- `templates/`: Clean, academic HTML interfaces for the Web Application.
- `static/`: Styling assets.

*Powered by Isolation Forest Anomaly Detection.*
