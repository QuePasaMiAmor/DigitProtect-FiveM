import os
from flask import Flask, request, jsonify
from flask_restful import Api
import requests
import json

app = Flask(__name__)
api = Api(app)

tokensList = {}

@app.route('/client', methods=['POST'])
def index1():
    requestForm = request.form
    method = requestForm.get("method")

    if method == "getEndpoints":
        token = requestForm.get("token")
        
        if token is not None and token != "":
            doesExist = False
            try: 
                tokenData = tokensList[token]
                doesExist = True
            except:
                doesExist = False

            if doesExist:
                return "what are you trying to do? get endpoints again? just chill and give up calmly."
            else:
                r = requests.post("http://" + request.headers.get('backendurl') + "/client", 
                 headers=request.headers,
                 data = request.form
                )

                response = "false"

                try: 
                    response = jsonify(r.text)
                except Exception as e:
                    print(e)
                    response = "false"

                print(f"Status Code: {r.status_code}, Content: {response}")
                tokensList[token] = True

                print(response)
                return r.text
            
            return "nbb"
        return "ntm"
    else: 
        r = requests.post("http://" + request.headers.get('backendurl') + "/client", 
            headers=request.headers,
            data = request.form
        )
        
        return r.text


    return "bb"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=61012,debug=True)