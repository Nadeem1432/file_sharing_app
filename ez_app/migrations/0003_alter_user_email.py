# Generated by Django 5.0 on 2024-12-19 19:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ez_app', '0002_alter_user_user_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
