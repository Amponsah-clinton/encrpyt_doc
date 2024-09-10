from django.db import models

class EncryptedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    encrypted_file = models.FileField(upload_to='encrypted/', blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
