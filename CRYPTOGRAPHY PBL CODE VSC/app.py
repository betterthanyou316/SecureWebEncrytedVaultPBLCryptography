import os
from flask import (
    Flask, render_template, request, redirect, url_for, 
    send_file, flash, session
)
from werkzeug.utils import secure_filename
from io import BytesIO
#Cryptography Imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#App Configuration
app = Flask(__name__)
# Create an 'uploads' folder if it doesn't exist
if not os.path.exists('uploads'):
    os.makedirs('uploads')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB file limit (optional)
# A secret key is required for flash messages and for the session
app.secret_key = os.urandom(24) 
#Cryptographic Helper Functions
def encrypt_data(data, password):
    """Encrypts data using AES-GCM with a key derived from the password."""
    salt = os.urandom(16) # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32-byte (256-bit) key
        salt=salt,
        iterations=100000, # A good number of iterations
        backend=default_backend()
    )
    key = kdf.derive(password.encode()) # Derive the key
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # 12-byte nonce 
    encrypted_data = aesgcm.encrypt(nonce, data, None) # Encrypt
    # Prepend salt and nonce to the encrypted data for storage
    return salt + nonce + encrypted_data
def decrypt_data(encrypted_full_blob, password):
    """Decrypts AES-GCM encrypted data using a key derived from the password."""
    try:
        # Extract the salt, nonce, and ciphertext from the blob
        salt = encrypted_full_blob[:16]
        nonce = encrypted_full_blob[16:16+12]
        encrypted_data_with_tag = encrypted_full_blob[16+12:]
        # Derive the key *exactly* as we did in encryption
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key) 
        # Decrypt. This will raise InvalidTag if the password is wrong
        # or the data has been tampered with.
        plaintext_data = aesgcm.decrypt(nonce, encrypted_data_with_tag, None)
        return plaintext_data
    except Exception as e:
        print(f"Decryption failed: {e}")
        # Raise a specific error to be caught by the route
        raise ValueError("Decryption failed. Incorrect password or tampered data.")
#Flask Routes
@app.route('/')
def index():
    """Renders the homepage."""
    return render_template('index.html')
@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles multiple file uploads and encryption."""
    files = request.files.getlist('file') # Get a list of files
    password = request.form['password']
    if not files or files[0].filename == '':
        flash("No selected files", 'error')
        return redirect(url_for('index'))
    if not password:
        flash("Password missing", 'error')
        return redirect(url_for('index'))
    if len(files) > 10:
        flash("You can only upload a maximum of 10 files at a time.", 'error')
        return redirect(url_for('index'))
    uploaded_filenames = [] # To list successful uploads
    for file in files:
        if file and file.filename != '':
            filename = secure_filename(file.filename) # Sanitize filename
            plaintext_data = file.read() # Read file content
            try:
                encrypted_full_blob = encrypt_data(plaintext_data, password)                
                encrypted_filename = filename + ".enc"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)               
                with open(file_path, 'wb') as f:
                    f.write(encrypted_full_blob)                
                uploaded_filenames.append(encrypted_filename)               
            except Exception as e:
                flash(f"Error encrypting {filename}: {e}", 'error')
    if not uploaded_filenames:
        flash("No files were successfully uploaded.", 'error')
        return redirect(url_for('index'))
    # Store the list of successful uploads in the user's session
    session['uploaded_files'] = uploaded_filenames
    # Redirect to our new 'upload_success' page
    return redirect(url_for('upload_success'))
@app.route('/upload_success')
def upload_success():
    """Shows a page with clickable links to the download pages."""
    # Get the list of filenames from the session
    # .pop() retrieves the list AND clears it (so it's clean for next time)
    file_ids = session.pop('uploaded_files', []) # Default to an empty list
    if not file_ids:
        # If someone just visits this page directly, send them home
        return redirect(url_for('index'))
    # Pass the list of file IDs to the new template
    return render_template('upload_success.html', file_ids=file_ids)
@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    """Handles the download page and file decryption.""" 
    safe_file_id = secure_filename(file_id) # Sanitize the file ID
    encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_file_id)
    if not os.path.exists(encrypted_filepath):
        flash("File not found on server.", 'error')
        return redirect(url_for('index'))
    if request.method == 'GET':
        # Show the password page
        return render_template('download.html', file_id=safe_file_id)
    elif request.method == 'POST':
        # User submitted password
        password = request.form['password']
        if not password:
            flash("Password missing", 'error')
            return render_template('download.html', file_id=safe_file_id)
        try:
            # Read the encrypted file from disk
            with open(encrypted_filepath, 'rb') as f:
                encrypted_full_blob = f.read()
            # Attempt to decrypt
            plaintext_data = decrypt_data(encrypted_full_blob, password)
            # Determine original filename (remove '.enc')
            original_filename = safe_file_id[:-4] if safe_file_id.endswith('.enc') else safe_file_id
            # Send the decrypted data from memory
            return send_file(
                BytesIO(plaintext_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=original_filename
            )
        except ValueError as e: # Catches our custom decryption error
            flash(str(e), 'error')
            return render_template('download.html', file_id=safe_file_id)
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'error')
            return render_template('download.html', file_id=safe_file_id)
# --- Run the App ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')