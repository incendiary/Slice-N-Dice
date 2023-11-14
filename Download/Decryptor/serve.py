"""
This module contains a Flask application for serving Split and Encrypted files.
"""

import uuid
import configparser
import os
import hashlib
import base64
import re
from werkzeug.utils import secure_filename
from flask import Flask, send_file, abort, render_template

app = Flask(__name__)

# Read the configuration
config = configparser.ConfigParser()
config.read('../config.ini')
server_hostname = config['DEFAULT']['ServerHostname']
num_files = int(config['DEFAULT']['NumberOfFiles'])
key = config['DEFAULT']['EncryptionKey']
download_name = config['DEFAULT']['DownloadName']
DOWNLOADS_PATH = 'Downloads/parts'  # Assuming the parts folder is in the Downloads directory

# Generate a unique FileGUID when the server starts
FILE_GUID = str(uuid.uuid4())

encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')


def compute_hash(file_path):
    """
    Compute the SHA-256 hash of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The computed SHA-256 hash.
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


@app.after_request
def add_header(response):
    """
    Add headers to the response to control caching.

    Args:
        response: The Flask response object.

    Returns:
        response: The modified Flask response object.
    """
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route('/')
def index():
    """
    Render the index page with file information.

    Returns:
        str: The rendered HTML page.
    """
    # Scan the directory and create a dictionary with file names and their hashes
    file_parts = {part: compute_hash(os.path.join(
        DOWNLOADS_PATH, part)) for part in os.listdir(DOWNLOADS_PATH)}
    sorted_file_parts = dict(sorted(file_parts.items(),
                                    key=lambda item: int(re.search(r'part(\d+)',
                                                                   item[0]).group(1)
                                                         )
                                    )
                             )

    return render_template('SideLoadMe.html',
                           server_hostname=server_hostname,
                           file_parts=sorted_file_parts,
                           file_guid=FILE_GUID,
                           encoded_key=encoded_key,
                           download_name=download_name)


@app.route('/<uid>/<path:filename>')
def serve_file_part(uid, filename):
    """
    Serve a specific file part.

    Args:
        uid (str): The UID associated with the request.
        filename (str): The filename to serve.

    Returns:
        file: The requested file part.
    """
    if uid != FILE_GUID:
        abort(404)
    # Secure the filename to avoid any directory traversal attack
    secure_filename_path = secure_filename(filename)
    # Build the complete file path
    file_path = os.path.join(DOWNLOADS_PATH, secure_filename_path)

    print(file_path)

    # Check if file exists
    if os.path.isfile(file_path):
        return send_file(file_path, mimetype='application/octet-stream')
    return None


# Serve the IV and Salt files, with added directory traversal protection
@app.route('/<uid>/iv')
def get_iv(uid):
    """
    Serve the IV file.

    Args:
        uid (str): The UID associated with the request.

    Returns:
        file: The IV file.
    """
    if uid != FILE_GUID:
        abort(404)
    # Assuming the iv.bin is directly under the Downloads directory
    iv_path = os.path.join('Downloads', 'iv.bin')
    return send_file(iv_path, mimetype='application/octet-stream')


@app.route('/<uid>/salt')
def get_salt(uid):
    """
    Serve the Salt file.

    Args:
        uid (str): The UID associated with the request.

    Returns:
        file: The Salt file.
    """
    if uid != FILE_GUID:
        abort(404)
    # Assuming the salt.bin is directly under the Downloads directory
    salt_path = os.path.join('Downloads', 'salt.bin')
    return send_file(salt_path, mimetype='application/octet-stream')


# Print all the routes for the Flask flask_app
def print_routes(flask_app):
    """
    Print all registered routes in the Flask flask_app.

    Args:
        flask_app: The Flask flask_app.
    """
    print("Registered routes:")
    for rule in flask_app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule}")


if __name__ == '__main__':
    print("GID Generated is: " + FILE_GUID)
    print(f"Key Info - Value: {key}, Encoded Value:{encoded_key}")
    print_routes(app)  # This will print all routes
    app.run(port=int(config['SERVER']['Port']), debug=config['SERVER'].getboolean('DebugMode'))
