import joblib

from flask import Flask, request

from helpers import convert_json_to_dataframe, make_prediction


app = Flask(__name__)


@app.route("/", methods=["POST", "GET"])
def home():
    """
    Home route that will confirm if the app is healthy
    """
    return "app is healthy"


@app.route("/health", methods=["POST", "GET"])
def health():
    """
    Health check endpoint that wil confirm if the app is healthy
    """
    return "app is healthy"


@app.route("/predict", methods=["POST"])
def predict():
    """
    Endpoint to make predictions
    """
    model = joblib.load('modeling/model.pkl')
    input_data = request.json
    input_df = convert_json_to_dataframe(input_data)
    prediction = make_prediction(input_df, model)
    return {
        'prediction': prediction
    }
