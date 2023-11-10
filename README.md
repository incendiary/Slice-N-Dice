 **Slice-N-Dice**

A toolkit for secure file encryption, slicing, and transfer for red team like operations, making the task of blue teams more complex by splitting data streams.

## Repository Structure

```plaintext
.
├── Decryptor
│   ├── Downloads
│   │   └── parts
│   ├── Serve.py
│   ├── requirements.txt
│   └── templates
│       └── SideLoadMe.html
├── Encryptors
│   └── python
│       ├── Slice.py
│       └── requirements.txt
└── config.ini

```

**Prerequisites**

- Python 3.x
- virtualenv for creating isolated Python environments. (suggested)

**Setup**

Cloning the Repository

```
git clone https://github.com/incendiary/Slice-N-Dice.git
cd Slice-N-Dice
```

Using virtualenv

```pip install virtualenv
pip install virtualenv
```

For Decryptor

```
cd Decryptor
virtualenv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
deactivate  # To deactivate the virtual environment
```

For Encryptor

```
cd ../Encryptors/python
virtualenv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
deactivate  # To deactivate the virtual environment
```

Usage

## Encrypting and Slicing Files

Activate the virtual environment in Encryptors/python.
Use Slice.py to encrypt and slice your file:

```
python Slice.py <file_to_encrypt>
```

**Serving Files**

```Activate the virtual environment in Decryptor.
Activate the virtual environment in Decryptor.
Start the server with Serve.py:
```

**Decrypting and Downloading**

After starting the server, browse to the default page for the decryption and download process.
