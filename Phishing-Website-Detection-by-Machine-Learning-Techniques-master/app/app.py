from flask import Flask, request, render_template
import pickle
import pandas as pd
from URLFeatureExtraction import featureExtraction

# Initialize Flask app
app = Flask(__name__)

# Load the XGBoost trained model
model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

# Define the expected feature order
feature_columns = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 
    'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame', 
    'Mouse_Over', 'Right_Click', 'Web_Forwards'
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        try:
            # Get the URL from the form
            url = request.form['url']
            
            # Extract features from the URL
            features = featureExtraction(url)
            
            # Convert features into a DataFrame with the expected column order
            features_df = pd.DataFrame([features], columns=feature_columns)
            
            # Predict using the XGBoost model
            prediction = model.predict(features_df)[0]
            
            # Determine the result
            result = "Phishing" if prediction == 0 else "Legitimate"
        
        except Exception as e:
            # Log the error to the console
            print(f"Error occurred: {str(e)}")
            
            # Set the result as a generic error message
            result = "An error occurred during prediction. Please try again later."
        
        return render_template('index.html', url=url, result=result)

if __name__ == "__main__":
    app.run(debug=True)
