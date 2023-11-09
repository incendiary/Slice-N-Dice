import uuid
from flask import Flask, send_file, abort, render_template
import configparser
import os
from werkzeug.utils import secure_filename
import hashlib
import base64
import re

app = Flask(__name__)

# Read the configuration
config = configparser.ConfigParser()
config.read('../config.ini')
server_hostname = config['DEFAULT']['ServerHostname']
num_files = int(config['DEFAULT']['NumberOfFiles'])
key = config['DEFAULT']['EncryptionKey']
download_name = config['DEFAULT']['DownloadName']
downloads_path = 'Downloads/parts'  # Assuming the parts folder is in the Downloads directory

# Generate a unique FileGUID when the server starts
file_guid = str(uuid.uuid4())

encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')

def compute_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()
    

@app.after_request
def add_header(response):
    # Add headers to both force latest IE rendering engine or Chrome Frame,
    # and also to cache the rendered page for 10 minutes.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/')
def index():
    # Scan the directory and create a dictionary with file names and their hashes
    file_parts = {part: compute_hash(os.path.join(downloads_path, part)) for part in os.listdir(downloads_path)}
    sorted_file_parts = dict(sorted(file_parts.items(), key=lambda item: int(re.search(r'part(\d+)', item[0]).group(1))))

    return render_template('sideloadme.html', server_hostname=server_hostname, file_parts=sorted_file_parts,
                           file_guid=file_guid, encoded_key=encoded_key, download_name=download_name)

@app.route('/<uid>/<path:filename>')
def serve_file_part(uid, filename):
    if uid != file_guid:
        abort(404)
    # Secure the filename to avoid any directory traversal attack
    secure_filename_path = secure_filename(filename)
    # Build the complete file path
    file_path = os.path.join(downloads_path, secure_filename_path)

    print(file_path)

    # Check if file exists
    if os.path.isfile(file_path):
        return send_file(file_path, mimetype='application/octet-stream')
    else:
        abort(404)  # If the file doesn't exist, return a 404 not found error.

# Serve the IV and Salt files, with added directory traversal protection
@app.route('/<uid>/iv')
def get_iv(uid):
    if uid != file_guid:
        abort(404)
    # Assuming the iv.bin is directly under the Downloads directory
    iv_path = os.path.join('Downloads', 'iv.bin')
    return send_file(iv_path, mimetype='application/octet-stream')

@app.route('/<uid>/salt')
def get_salt(uid):
    if uid != file_guid:
        abort(404)
    # Assuming the salt.bin is directly under the Downloads directory
    salt_path = os.path.join('Downloads', 'salt.bin')
    return send_file(salt_path, mimetype='application/octet-stream')

# Print all the routes for the Flask app
def print_routes(app):
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule}")

if __name__ == '__main__':
    print("GID Generated is: " + file_guid)
    print("Key Info - Value: %s, Encoded Value:%s" % (key, encoded_key))
    print_routes(app)  # This will print all routes
    app.run(port=int(config['SERVER']['Port']), debug=config['SERVER'].getboolean('DebugMode'))
