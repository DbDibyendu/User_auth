# Generated by Django 3.0.5 on 2021-05-29 09:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='otp_time',
            field=models.DateTimeField(auto_now=True),
        ),
    ]