import jwt
import base64
import json
import urllib.parse
import hashlib
import uuid

def encode_jwt(secret, payload):
    return jwt.encode(secret, json.loads(payload), algorithm='HS256')

def decode_jwt(secret, payload):
    return jwt.decode(secret, payload, algorithms=['HS256'])

def encode_base64(input):
    return base64.b64encode(input.encode('ascii'))

def decode_base64(input):
    return base64.b64decode(input).decode('ascii')

def format_json(input):
    return json.dumps(json.loads(input), indent=2)

def encode_url(input):
    return urllib.parse.quote(input)

def decode_url(input):
    return urllib.parse.unquote(input)

def encode_hex(input):
    return input.encode('utf-8').hex()

def decode_hex(input):
    return bytes.fromhex(input).decode('utf-8')

def hash_string(input, hashing_algorithm):
    hash_algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    return hash_algorithms[hashing_algorithm](input.encode('utf-8')).hexdigest()

def generate_uuid():
    return str(uuid.uuid4())