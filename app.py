from flask import Flask, request, jsonify
from flask_cors import CORS # pip install flask-cors
from verfierv2 import EmailVerifier

app = Flask(__name__)
CORS(app) # Enable CORS for all routes
verifier = EmailVerifier()

@app.route('/verify', methods=['POST'])
def verify_single():
    data = request.json
    result = verifier.verify_email(data['email'])
    return jsonify(result)

@app.route('/verify-bulk', methods=['POST'])
def verify_bulk():
    data = request.json
    results = verifier.verify_bulk(data['emails'])
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)