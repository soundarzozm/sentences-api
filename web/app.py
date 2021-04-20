from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")

db = client.SentencesDatabase
users = db["Users"]

def countTokens(username):

    num_tokens = users.find({
        "username": username
    })[0]["tokens"]

    return num_tokens

def verifyPassword(username, password):
    
    hashed_pw = users.find({
        "username": username
    })[0]["password"]

    if bcrypt.checkpw(hashed_pw, password):
        return True    
    
    return False

class Register(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

        users.insert({
            "username": username,
            "password": hashed_pw,
            "tokens": 10,
            "sentence": ""
        })

        retJson = {
            "status": 200,
            "msg": "success"
        }

        return jsonify(retJson)

class Store(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        sentence = postedData["sentence"]
        
        num_tokens = countTokens(username)

        if verifyPassword(username, password) != False:
            retJson = {
                "status": 302,
                "msg": "incorrect password"
            }
            return jsonify(retJson)

        if num_tokens < 1:
            retJson = {
                "status": 301,
                "msg": "not enough tokens"
            }
            return jsonify(retJson)

        users.update({
            "username": username
        },{
            "$set": {
                "sentence": sentence,
                "tokens": num_tokens - 1
            }
        }
        )

        retJson = {
            "status": 200,
            "msg": "success"
        }

        return jsonify(retJson)

class Retrieve(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        num_tokens = countTokens(username)

        if verifyPassword(username, password) == False:
            retJson = {
                "status": 302,
                "msg": "incorrect password"
            }
            return jsonify(retJson)

        if num_tokens < 1:
            retJson = {
                "status": 301,
                "msg": "not enough tokens"
            }
            return jsonify(retJson)

        sentence = users.find({
            "username": username
        })[0]["sentence"]

        users.update({
            "username": username
        },{
            "$set": {
                "tokens": num_tokens - 1
            }
        }
        )

        retJson = {
            "status": 200,
            "sentence": sentence
        }

        return jsonify(retJson)

api.add_resource(Register, "/register")
api.add_resource(Store, "/store")
api.add_resource(Retrieve, "/retrieve")

if __name__ == "__main__":
    app.run(host="0.0.0.0")