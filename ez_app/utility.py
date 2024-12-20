import os
from rest_framework.validators import ValidationError

def validate_file_extension(value):
    valid_extensions = ['.pptx', '.docx', '.xlsx']
    ext = os.path.splitext(value.name)[1]
    if ext.lower() not in valid_extensions:
        raise ValidationError('File type not supported. Only pptx, docx, and xlsx are allowed.')
