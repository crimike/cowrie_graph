from django.shortcuts import *
from django.template import loader

# Create your views here.
from django.http import HttpResponse
from .models import *
from django_tables2 import RequestConfig
from .util import *

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
    

def index(request):
    auths = CowrieAuth.objects.all()
    #inputs = Input.objects.all()
    #sessions = Sessions.objects.all()
    
    passwords = {}
    users = {}
    combos = {}
    for auth in auths:
        if auth.password in passwords.keys():
            passwords[auth.password] += 1
        else:
            passwords[auth.password] = 1
        if auth.username in users.keys():
            users[auth.username] += 1
        else:
            users[auth.username] = 1
        combo = auth.username + ":" + auth.password
        if combo in combos.keys():
            combos[combo] += 1
        else:
            combos[combo] = 1
    
    commands = {}
    # for input in inputs:
    #     if input.input in commands.keys():
    #         commands[input.input] += 1
    #     else:
    #         commands[input.input] = 1
    
    clients = {}
    # for session in sessions:
    #     try:
    #         client_version = Clients.objects.filter(pk=session.client)[0].version
    #         if client_version in clients.keys():
    #             clients[client_version] += 1
    #         else:
    #             clients[client_version] = 1
    #     except:
    #         #handle list index out of range
    #         pass


    top10pass = sorted(passwords.items(), key=lambda item: item[1], reverse=True)[:10]
    top10users = sorted(users.items(), key=lambda item:item[1], reverse=True)[:10]
    top10combos = sorted(combos.items(),key=lambda item:item[1], reverse=True)[:10]
    top10inputs = sorted(commands.items(), key=lambda item:item[1], reverse=True)[:10]
    top10clients = sorted(clients.items(), key=lambda item:item[1], reverse=True)[:10]


    context = {
        'passwords': top10pass,
        'users': top10users,
        'combos': top10combos,
        'inputs': top10inputs,
        'clients': top10clients
    }
    return render(request, 'dashboard.html', context)

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

#     ipforwards with data
# username and password
# Downloads
# Duration
# Fingerprint
# sessions with same fingerprint(ip and link)
# ttylog
# Client

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
