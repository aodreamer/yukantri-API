# my_simple_flask_app/app/routes.py
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    if request.method == 'GET':
        return jsonify(message='GET request successful')
    elif request.method == 'POST':
        return jsonify(message='POST request successful')

if __name__ == '__main__':
    app.run(debug=True)
