import requests
import sqlite3
import IPython

api_key = '<ipdata API key>'

conn = sqlite3.connect( 'enrichment.db')

with open('distinct_ips', 'r') as f:
    for line in f.readlines():
        ip = line.replace('\n', '')
        # query IP first, and then issue api call
        tst = conn.execute("SELECT * from ip_enrichments where ip = ?", (ip, ))
        attempt = tst.fetchone()
        if attempt != None:
            print("Skipping for " + ip)
            continue
        try:
            data = requests.get(f'https://api.ipdata.co/{ip}?api-key={api_key}').json()
            city = data['city'] if data['city'] else ''
            t = (ip, city, data['country_name'], data['threat']['is_anonymous'], data['threat']['is_known_attacker'], data['threat']['is_threat'], data['threat']['is_known_abuser'], )
            conn.execute("INSERT INTO ip_enrichments(ip, city, country, is_anonymous, is_known_attacker, is_threat, is_known_abuser) VALUES (?, ?, ?, ?, ?, ?, ?)", t)
            conn.commit()
            print("Ran successfully for " + ip)
        except:
            IPython.embed()
            conn.commit()
            conn.close()
            break

conn.commit()
conn.close()
