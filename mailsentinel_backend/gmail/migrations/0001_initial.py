

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='FlaggedEmail',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_email', models.CharField(max_length=255)),
                ('email_id', models.CharField(max_length=255)),
                ('flagged_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-flagged_at'],
                'unique_together': {('user_email', 'email_id')},
            },
        ),
    ]
