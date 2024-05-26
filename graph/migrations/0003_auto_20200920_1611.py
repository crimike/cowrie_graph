# Generated by Django 3.0.8 on 2020-09-20 16:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('graph', '0002_auto_20200729_1516'),
    ]

    operations = [
        migrations.AddField(
            model_name='ipenrichments',
            name='latitude',
            field=models.FloatField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='ipenrichments',
            name='longitude',
            field=models.FloatField(default=0),
            preserve_default=False,
        ),
    ]
