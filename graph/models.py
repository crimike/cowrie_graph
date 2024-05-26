# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models
import django_tables2 as tables




class CowrieAuth(models.Model):
    session = models.CharField(max_length=32)
    success = models.IntegerField()
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    timestamp = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'auth'


class Clients(models.Model):
    version = models.CharField(max_length=50)

    class Meta:
        managed = False
        db_table = 'clients'


class Downloads(models.Model):
    session = models.CharField(max_length=32)
    timestamp = models.DateTimeField()
    url = models.TextField()
    outfile = models.TextField(blank=True, null=True)
    shasum = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'downloads'


class Input(models.Model):
    session = models.CharField(max_length=32)
    timestamp = models.DateTimeField()
    realm = models.CharField(max_length=50, blank=True, null=True)
    success = models.IntegerField(blank=True, null=True)
    input = models.TextField()

    class Meta:
        managed = False
        db_table = 'input'


class Ipforwards(models.Model):
    session = models.ForeignKey('Sessions', models.DO_NOTHING, db_column='session')
    timestamp = models.DateTimeField()
    dst_ip = models.CharField(max_length=255)
    dst_port = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'ipforwards'


class Ipforwardsdata(models.Model):
    session = models.ForeignKey('Sessions', models.DO_NOTHING, db_column='session')
    timestamp = models.DateTimeField()
    dst_ip = models.CharField(max_length=255)
    dst_port = models.IntegerField()
    data = models.TextField()

    class Meta:
        managed = False
        db_table = 'ipforwardsdata'


class Keyfingerprints(models.Model):
    session = models.CharField(max_length=32)
    username = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'keyfingerprints'


class Params(models.Model):
    session = models.CharField(max_length=32)
    arch = models.CharField(max_length=32)

    class Meta:
        managed = False
        db_table = 'params'


class Sensors(models.Model):
    ip = models.CharField(max_length=255)

    class Meta:
        managed = False
        db_table = 'sensors'


class Sessions(models.Model):
    id = models.CharField(primary_key=True, max_length=32)
    starttime = models.DateTimeField()
    endtime = models.DateTimeField(blank=True, null=True)
    sensor = models.IntegerField()
    ip = models.CharField(max_length=15)
    termsize = models.CharField(max_length=7, blank=True, null=True)
    client = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'sessions'


class Ttylog(models.Model):
    session = models.CharField(max_length=32)
    ttylog = models.CharField(max_length=100)
    size = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'ttylog'

# class SimpleTable(tables.Table):
#     class Meta:
#         model = Sessions

class Ipenrichments(models.Model):
    ip = models.CharField(max_length=15)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    is_anonymous = models.BooleanField()
    is_known_attacker = models.BooleanField()
    is_known_abuser = models.BooleanField()
    is_threat = models.BooleanField()
    latitude = models.FloatField(default=0)
    longitude = models.FloatField(default=0)

    class Meta:
        db_table = 'ip_enrichments'
        verbose_name = 'enrichment'


