from django.shortcuts import render, redirect
from django.conf import settings
from .models import EncryptedFile
from .forms import FileUploadForm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(password, file_path):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    return encrypted_file_path

def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save()

            # Encrypt the file
            file_path = uploaded_file.file.path
            password = settings.ENCRYPTION_PASSWORD  # Get password from settings
            encrypted_file_path = encrypt_file(password, file_path)

            # Save encrypted file to the model
            uploaded_file.encrypted_file.name = os.path.relpath(encrypted_file_path, settings.MEDIA_ROOT)
            uploaded_file.save()

            return redirect('file_list')
    else:
        form = FileUploadForm()
    return render(request, 'upload.html', {'form': form})

def file_list(request):
    files = EncryptedFile.objects.all()
    return render(request, 'file_list.html', {'files': files})
