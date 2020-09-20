from django.shortcuts import *
from django.template import loader
from django.db.models import Count
from django.http import HttpResponse
from .models import *
from django_tables2 import RequestConfig
from .util import *
import collections

class IP:
    ip_address = '0.0.0.0'
    nr_sessions = 0
    city = None
    country= None
    is_anonymous = False
    is_known_attacker = False
    is_known_abuser = False
    is_threat = False

    def __init__(self, ip, sessions_number, city = None, country = None ,isanon = False, isattack = False,isabuse = False,isthreat = False):
        self.ip_address = ip
        self.nr_sessions = sessions_number
        self.city = city
        self.country = country
        self.is_anonymous = isanon
        self.is_known_attacker = isattack
        self.is_known_abuser = isabuse
        self.is_threat = isthreat


def get_top_count(cls, value, count):
    topx = cls.objects.values(value).annotate(xcount=Count(value))
    dict_top = {}
    for x in topx:
        dict_top[x[value]] = x['xcount']

    return sorted(dict_top.items(), key=lambda item: item[1], reverse=True)[:count]    
    

def index(request):
    sessions = Sessions.objects.values('client').annotate(ccount=Count('client'))
    auths_combo = CowrieAuth.objects.values('username', 'password').annotate(combo_count=Count('username'))
    daily_authentications = CowrieAuth.objects.extra(select={'day': 'date( timestamp )'}).values('day').annotate(xcount=Count('timestamp'))
    weekly_authentications = list(collections.Counter(list(CowrieAuth.objects.dates('timestamp', 'week'))).items())
    logins_count = CowrieAuth.objects.all().count()
    sessions_count = Sessions.objects.all().count()
    downloads_count = Downloads.objects.all().count()
    inputs_count = Input.objects.all().count()
    unique_ip_count = Sessions.objects.values("ip").distinct().count()
    active_sessions = Input.objects.values('session').distinct().count()

    combos = {}
    for combo in auths_combo:
        combos[combo['username'] + ":" + combo['password']] = combo['combo_count']
        
    clients = {}
    for session in sessions:
        try:
            client_version = Clients.objects.filter(pk=session["client"])[0].version[2:-1]
            clients[client_version] = session["ccount"]
        except:
            #handle list index out of range
            pass

    top10combos = sorted(combos.items(),key=lambda item:item[1], reverse=True)[:10]
    top10clients = sorted(clients.items(), key=lambda item:item[1], reverse=True)[:10]

    top10pass = get_top_count(CowrieAuth, 'password', 10)
    top10users = get_top_count(CowrieAuth, 'username', 10)
    top10inputs = get_top_count(Input, 'input', 10)
    top10countries = get_top_count(Ipenrichments, 'country', 15)
    top10ips = get_top_count(Sessions, 'ip', 15)


    context = {
        'passwords': top10pass,
        'users': top10users,
        'combos': top10combos,
        'inputs': top10inputs,
        'clients': top10clients,
        'countries': top10countries,
        'ips': top10ips,
        'days': daily_authentications,
        'weeks': weekly_authentications,
        'logins_count': logins_count,
        'sessions_count': sessions_count,
        'downloads_count': downloads_count,
        'inputs_count': inputs_count,
        'unique_ip_count': unique_ip_count,
        'active_sessions': active_sessions
    }
    return render(request, 'dashboard.html', context)

def top50(request):
    sessions = Sessions.objects.values('client').annotate(ccount=Count('client'))
    auths_combo = CowrieAuth.objects.values('username', 'password').annotate(combo_count=Count('username'))

    combos = {}
    for combo in auths_combo:
        combos[combo['username'] + ":" + combo['password']] = combo['combo_count']
        
    clients = {}
    for session in sessions:
        try:
            client_version = Clients.objects.filter(pk=session["client"])[0].version[2:-1]
            clients[client_version] = session["ccount"]
        except:
            #handle list index out of range
            pass

    top_combos = sorted(combos.items(),key=lambda item:item[1], reverse=True)[:50]
    top_clients = sorted(clients.items(), key=lambda item:item[1], reverse=True)[:50]

    top_pass = get_top_count(CowrieAuth, 'password', 50)
    top_users = get_top_count(CowrieAuth, 'username', 50)
    top_inputs = get_top_count(Input, 'input', 50)
    top_countries = get_top_count(Ipenrichments, 'country', 50)
    top_ips = get_top_count(Sessions, 'ip', 50)


    context = {
        'passwords': top_pass,
        'users': top_users,
        'combos': top_combos,
        'inputs': top_inputs,
        'clients': top_clients,
        'countries': top_countries,
        'ips': top_ips
    }
    return render(request, 'top50s.html', context)

def all_ips(request):
    sessions = Sessions.objects.all()
    ip_dict = {}
    for session in sessions:
        if session.ip in ip_dict.keys():
            ip_dict[session.ip] = ip_dict[session.ip] + 1
        else:
            ip_dict[session.ip] = 1
    ips = []
    for ip in ip_dict.keys():
        ip_query = Ipenrichments.objects.filter(ip=ip)
        if len(ip_query) != 0:
            ip_info = ip_query[0]
            ips.append(IP(ip, ip_dict[ip], ip_info.city, ip_info.country, ip_info.is_anonymous, ip_info.is_known_attacker,ip_info.is_known_abuser, ip_info.is_threat))
        else:
            ip_info = enrich_ip(ip)
            ips.append(IP(ip, ip_dict[ip], ip_info.city, ip_info.country, ip_info.is_anonymous, ip_info.is_known_attacker,ip_info.is_known_abuser, ip_info.is_threat))
    context = {
        'ips': ips,
    }
    return render(request,'ips.html',context)


def ip(request,ip):
    #regex for ip
    db_sessions = get_list_or_404(Sessions, ip=ip)
    class Session:
        def __init__(self,id,duration,client, commands, ipf, downloads):
            self.id = id
            self.duration = duration
            self.client = client
            self.commands = commands
            self.ipf = ipf
            self.downloads = downloads
    sessions = []
    ipr = Ipenrichments.objects.filter(ip=ip)
    if len(ipr) > 0:
        ip_enrichment = ipr[0]
    else:
        ip_enrichment = enrich_ip(ip)
    for session in db_sessions:
        try:
            client = Clients.objects.filter(pk=session.client)[0].version
        except:
            client = 'None'
        commands = len(Input.objects.filter(session=session.id))
        try:
            duration = session.endtime - session.starttime
        except:
            duration = 0
        ipf = len(Ipforwards.objects.filter(session=session.id))
        downloads = len(Downloads.objects.filter(session=session.id))
        sessions.append(Session(session.id, duration, client, commands, ipf, downloads))
    context = {
        'sessions': sessions,
        'ip': ip,
        'ipenrich': ip_enrichment,
        'fqdn': reverse_ip_search(ip)
    }
    return render(request,'sessions.html',context)
    
def session(request, id):

    session = get_list_or_404(Sessions, id=id)
    
    commands = Input.objects.filter(session=id)
    ipf = Ipforwards.objects.filter(session=id)
    ipf_data = Ipforwardsdata.objects.filter(session=id)
    downloads = Downloads.objects.filter(session=id)
    fp = Keyfingerprints.objects.filter(session=id)
    if len(fp) != 0:
        fingerprint = fp[0]
    else:
        fingerprint = ""
    try:
        duration = session.endtime - session.starttime
    except:
        duration = 0
    other_sessions = []
    if fingerprint != "":
        fp_other = Keyfingerprints.objects.filter(fingerprint = fingerprint.fingerprint)
        for x in fp_other:
            if x.session != id:
                other_sessions.append(Sessions.objects.filter(id=x.session)[0])
    try:
        ttylog = Ttylog.objects.filter(session=id)[0]
    except:
        ttylog = None
    try:
        client = Clients.objects.filter(pk=session.client)[0].version
    except:
        client = None
    auth = CowrieAuth.objects.filter(session=id)[0]

    
    context = {
        'session': session[0],
        'commands': commands,
        'ipf': ipf,
        'ipf_data': ipf_data,
        'downloads': downloads,
        'fp': fingerprint,
        'duration': duration,
        'other_sessions': other_sessions,
        'ttylog': ttylog,
        'client': client,
        'auth': auth,
    }
    return render(request,'session_info.html', context)
