"""
This module contains a Flask application for receiving Split and Encrypted files.
"""
import base64
import configparser
import os
import uuid

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from flask import Flask, render_template, request, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
# flask_app.secret_key = 'your_secret_key'  # Needed for session management and flash messaging
app.secret_key = str(uuid.uuid4())

# Read the configuration
config = configparser.ConfigParser()
config.read('config.ini')
server_hostname = config['DEFAULT']['ServerHostname']
key = config['DEFAULT']['EncryptionKey']
UPLOAD_DIRECTORY = config['DEFAULT']['UploadDirectory']
NUMBEROFFILES = int(config['DEFAULT']['NumberOfFiles'])
# Generate a unique FileGUID when the server starts
RUN_GUID = str(uuid.uuid4())

encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_DIRECTORY, RUN_GUID), exist_ok=True)


def decrypt_file_part(file_path, decrypting_key, iv):
    """
        Decrypt a specific part of a file.

        Args:
            file_path (str): The path to the encrypted file part.
            decrypting_key (bytes): The encryption key used for decryption.
            iv (bytes): The initialization vector for AES decryption.

        Returns:
            bytes: The decrypted data of the file part.
        """
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
        cipher = AES.new(decrypting_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data


# Print all the routes for the Flask flask_app
def print_routes(flask_app):
    """
    Print all registered routes in the Flask application.

    Args:
        flask_app (Flask): The Flask application instance.

    This function iterates over all the routes registered in the Flask
    application and prints them.
    """
    print("Registered routes:")
    for rule in flask_app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule}")


def derive_key(salt, password="exampleKey", iterations=100000, dk_len=16):
    """
    Derive a cryptographic derived_key using PBKDF2
    (Password-Based Key Derivation Function 2).

    Args:
        salt (bytes): The salt value to use in derived_key derivation.
        password (str, optional): The password to derive the derived_key from.
            Defaults to "exampleKey".
        iterations (int, optional): Number of iterations for derived_key derivation.
            Defaults to 100000.
        dk_len (int, optional): The desired byte-length of the derived derived_key.
            Defaults to 16.

    Returns:
        bytes: The derived cryptographic derived_key.
    """
    password_bytes = password.encode('utf-8')
    derived_key = PBKDF2(password_bytes, salt, dkLen=dk_len,
                         count=iterations, hmac_hash_module=SHA256)
    return derived_key


def extract_original_name_and_part(filename):
    """
        Extract the original file name and part number from a given filename.

        Args:
            filename (str): The filename from which to extract information.

        Returns:
            tuple: A tuple containing the original filename and the part number as an integer.
    """
    parts = filename.split('_part_')
    original_name = parts[0]
    part_number = int(parts[1].split('.')[0])
    return original_name, part_number


def all_parts_uploaded(original_file_name, total_parts):
    """
        Check if all parts of a file have been uploaded.

        Args:
            original_file_name (str): The original name of the file.
            total_parts (int): The total number of parts expected for the file.

        Returns:
            bool: True if all parts are uploaded, False otherwise.
    """
    for i in range(total_parts):
        part_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, f"{original_file_name}_part_{i}")

        print(f"looking for {part_path}")
        if not os.path.exists(part_path):
            return False
    return True


def recombine_file(original_file_name, total_parts):
    """
        Combine all uploaded parts of a file into a single file.

        Args:
            original_file_name (str): The original name of the file.
            total_parts (int): The total number of parts to combine.

        This function reads each part of the file and writes it to a combined file.
    """
    with open(os.path.join(UPLOAD_DIRECTORY, RUN_GUID, original_file_name), 'wb') as output_file:
        for i in range(total_parts):
            part_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, f"{original_file_name}_part_{i}")
            with open(part_path, 'rb') as part_file:
                output_file.write(part_file.read())
            # Optionally, delete the part file after combining
            # os.remove(part_path)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
        Handle the file upload via the '/upload' route.

        Supports both GET and POST requests. For GET requests, it renders the
        upload page. For POST requests, it handles the uploading of file parts.

        Returns:
            str: A success message if a file part is uploaded successfully,
                 otherwise, it renders the upload HTML template.
    """
    if request.method == 'POST':
        # Check if the post request has the file part
        file = request.files['file']
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, filename)
        file.save(file_path)

        if "_part_0" in filename:
            print(f"Here: filename is {filename}")

            iv = request.files['iv']
            salt = request.files['salt']

            base_filename = filename[:-7]

            iv_filename = secure_filename(base_filename + '_iv')
            salt_filename = secure_filename(base_filename + '_salt')

            iv_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, iv_filename)
            salt_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, salt_filename)

            iv.save(iv_path)
            salt.save(salt_path)

        print(f"Uploaded: {filename}")
        original_file_name, part_number = extract_original_name_and_part(filename)
        print(f"Original Filename: {original_file_name}, Part Number: {part_number}")

        return 'File part uploaded successfully', 200

    upload_url = url_for('upload_file')
    return render_template('upload.html', number_of_files=NUMBEROFFILES,
                           server_hostname=server_hostname, upload_url=upload_url, key=key)


@app.route('/upload/complete')
def complete_upload():
    """
    Handle the completion of file upload via the '/upload/complete' route.

    Checks if all parts of a file have been uploaded and, if so,
    initiates the recombination and decryption process.

    Returns:
        str: A status message indicating the outcome of the operation.
    """
    filename = request.args.get('filename')
    if not filename:
        return 'Filename is missing', 400

    original_file_name, _ = extract_original_name_and_part(filename + "_part_0")
    if not all_parts_uploaded(original_file_name, NUMBEROFFILES):
        return 'Not all parts are uploaded yet', 400

    decrypted_parts = process_file_parts(original_file_name)
    output_file_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, f"decrypted_{original_file_name}")
    with open(output_file_path, 'wb') as output_file:
        for part_data in decrypted_parts:
            output_file.write(part_data)

    return 'File recombination complete', 200


def process_file_parts(original_file_name):
    """
    Process each part of the file for decryption.

    Args:
        original_file_name (str): The original name of the file.

    Returns:
        list: A list containing decrypted data for each file part.
    """
    decrypted_parts = []
    for i in range(NUMBEROFFILES):
        part_path, iv_path, salt_path = get_file_paths(original_file_name, i)
        iv, salt = read_iv_and_salt(iv_path, salt_path)
        derived_key = derive_key(salt)
        decrypted_data = decrypt_file_part(part_path, derived_key, iv)
        decrypted_parts.append(decrypted_data)
    return decrypted_parts


def get_file_paths(original_file_name, part_index):
    """
    Generate file paths for the part file, iv file, and salt file.

    Args:
        original_file_name (str): The original name of the file.
        part_index (int): The index of the part file.

    Returns:
        tuple: A tuple containing paths for the part file, iv file, and salt file.
    """
    part_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, f"{original_file_name}_part_{part_index}")
    iv_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, f"{original_file_name}_iv")
    salt_path = os.path.join(UPLOAD_DIRECTORY, RUN_GUID, f"{original_file_name}_salt")
    return part_path, iv_path, salt_path


def read_iv_and_salt(iv_path, salt_path):
    """
    Read the initialization vector and salt from their respective files.

    Args:
        iv_path (str): Path to the IV file.
        salt_path (str): Path to the salt file.

    Returns:
        tuple: A tuple containing the IV and salt.
    """
    with open(iv_path, 'rb') as iv_file, open(salt_path, 'rb') as salt_file:
        iv = iv_file.read()
        salt = salt_file.read()
    return iv, salt


@app.route('/')
def index():
    """
    Render the index page of the application.

    This route renders the main page of the application, displaying file
    information and upload instructions.

    Returns:
        str: The rendered HTML for the index page.
    """
    return render_template('index.html', server_hostname=server_hostname,
                           file_guid=RUN_GUID, encoded_key=encoded_key,
                           number_of_files=NUMBEROFFILES)


if __name__ == '__main__':
    print("GID Generated is: " + RUN_GUID)
    print(f"Key Info - Value: {key}, Encoded Value:{encoded_key}")
    print_routes(app)  # This will print all routes
    app.run(port=int(config['SERVER']['Port']), debug=config['SERVER'].getboolean('DebugMode'))
