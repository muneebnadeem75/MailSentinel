

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gmail', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ThreatLog',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_email', models.CharField(max_length=255)),
                ('email_id', models.CharField(max_length=255)),
                ('subject', models.CharField(blank=True, max_length=500)),
                ('sender', models.CharField(blank=True, max_length=500)),
                ('risk', models.CharField(max_length=20)),
                ('risk_score', models.IntegerField(default=0)),
                ('action', models.CharField(default='detected', max_length=50)),
                ('logged_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-logged_at'],
            },
        ),
        migrations.CreateModel(
            name='EmailScanCache',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_email', models.CharField(max_length=255)),
                ('email_id', models.CharField(max_length=255)),
                ('subject', models.CharField(blank=True, max_length=500)),
                ('sender', models.CharField(blank=True, max_length=500)),
                ('date', models.CharField(blank=True, max_length=100)),
                ('snippet', models.TextField(blank=True)),
                ('risk', models.CharField(default='pending', max_length=20)),
                ('risk_score', models.IntegerField(default=0)),
                ('security_checks', models.JSONField(default=list)),
                ('scanned_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['-scanned_at'],
                'unique_together': {('user_email', 'email_id')},
            },
        ),
    ]
