from flask import Flask, send_file, render_template, make_response

app = Flask(__name__)

@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/')
def index():
    # Serve your 'SideLoadMe.html' as the default page
    return render_template('SideLoadMe.html')

@app.route('/iv')
def get_iv():
    # Serve the 'iv.bin' file
    response = make_response(send_file('iv.bin', mimetype='application/octet-stream'))
    return response

@app.route('/salt')
def get_salt():
    # Serve the 'salt.bin' file
    response = make_response(send_file('salt.bin', mimetype='application/octet-stream'))
    return response

@app.route('/file_part0')
def get_part0():
    # Serve the 'file_part0' file
    response = make_response(send_file('file_part0', mimetype='application/octet-stream'))
    return response

@app.route('/file_part1')
def get_part1():
    # Serve the 'file_part1' file
    response = make_response(send_file('file_part1', mimetype='application/octet-stream'))
    return response

if __name__ == '__main__':
    app.run(port=80)
