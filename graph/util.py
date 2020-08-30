import socket
import requests
from .models import Ipenrichments

api_key = '<ipdata_API_key>'

def reverse_ip_search(ip):
    try:
        return socket.gethostbyaddr(ip)
    except:
        return [""]

def enrich_ip(ip):
    try:
        data = requests.get(f'https://api.ipdata.co/{ip}?api-key={api_key}').json()
        city = data['city'] if data['city'] else get_city_geoip(ip)
        p = Ipenrichments(ip=ip, 
                city=city, 
                country=data['country_name'], 
                is_anonymous=data['threat']['is_anonymous'], 
                is_known_attacker=data['threat']['is_known_attacker'], 
                is_known_abuser=data['threat']['is_known_abuser'], 
                is_threat=data['threat']['is_threat'])
        p.save()
    except:
        p = Ipenrichments(ip=ip,
                city = 'None',
                country = 'None',
                is_anonymous = False,
                is_known_attacker = False,
                is_known_abuser = False,
                is_threat = False)
        # log the exception
    return p

def get_city_geoip(ip):
    try:
        data = requests.get(f'http://www.geoplugin.net/json.gp?ip={ip}').json()
        return data['geoplugin_city']
    except:
        # log exception
        return ''