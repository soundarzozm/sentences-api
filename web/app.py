from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")

db = client.SentencesDatabase
users = db["Users"]

class Register(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())

        users.insert({
            "username": username,
            "password": hashed_pw
        })

if __name__ == "__main__":
    app.run(host="0.0.0.0")