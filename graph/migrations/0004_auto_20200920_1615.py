# Generated by Django 3.0.8 on 2020-09-20 16:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('graph', '0003_auto_20200920_1611'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ipenrichments',
            name='latitude',
            field=models.FloatField(default=0),
        ),
        migrations.AlterField(
            model_name='ipenrichments',
            name='longitude',
            field=models.FloatField(default=0),
        ),
    ]
