import re
import requests
from pprint import pprint

alienvault_reputation = 'https://reputation.alienvault.com/reputation.unix'
et_tor = 'http://rules.emergingthreats.net/blockrules/emerging-tor.rules'
et_compromised_ips = 'http://rules.emergingthreats.net/blockrules/compromised-ips.txt'
et_emerging_compromised = 'http://rules.emergingthreats.net/blockrules/emerging-compromised.rules'
et_emerging_bot = 'http://rules.emergingthreats.net/blockrules/emerging-botcc.rules'
et_ciarmy = 'http://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules'
et_spamhaus = 'http://rules.emergingthreats.net/blockrules/emerging-drop.rules'
mdl_ips = 'http://www.malwaredomainlist.com/hostslist/ip.txt'
mdl_hosts = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
malware_domains_dyndns = 'http://mirror1.malwaredomains.com/files/dynamic_dns.txt'
malware_domains_url_short = 'http://mirror1.malwaredomains.com/files/url_shorteners.txt'
malware_domains_domains = 'http://mirror1.malwaredomains.com/files/domains.txt'
spyeye = 'https://spyeyetracker.abuse.ch/blocklist.php?download=hostsdeny'
zeus = 'https://zeustracker.abuse.ch/blocklist.php?download=hostsdeny'
sri_infected_client = 'http://cgi.mtc.sri.com/download/attackers/02-13-2013/Get_Top-583_30-Day_Filterset.html'
sri_malware = 'http://cgi.mtc.sri.com/download/malware_dns/02-13-2013/Get_Top-100_30-Day_WatchList.html'

headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.122 Safari/537.36'}


def extract_ips(text):
    regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    results = []
    for line in text.split('\n'):
        matches = re.findall(regex, line)
        if matches:
            for ip in matches:
                results.append(ip)
    return list(set(results))


def filter_comments(_list):
    filtered = []
    for line in _list:
        line = line.strip()
        if line.startswith('#') or not line or line.startswith('*') or line.startswith('!!') or line.startswith('<'):
            continue
        filtered.append(line)
    return filtered


def alienvault():
    data = requests.get(alienvault_reputation)
    lines = data.content.strip().split('\n')

    d = {}
    for line in lines:
        if not line.startswith('ALL:'):
            continue

        # Remove "ALL: " from the line
        data = line[5:]
        ip, tags = data.split(' # ')

        for tag in tags.split(';'):
            tag = tag.lower()
            tag = tag.replace(' ', '_')

            # Replace "c&c" with "c2" for consistency
            if tag == 'c&c':
                tag = 'c2'

            if tag not in d:
                d[tag] = []
            d[tag].append(ip)

    return d


def emerging_threats():
    d = {}
    text = requests.get(et_tor).text.strip()
    ips = extract_ips(text)
    d['tor_exit_node'] = ips

    text = requests.get(et_compromised_ips).text.strip()
    ips = extract_ips(text)
    d['compromised_ip'] = ips

    text = requests.get(et_emerging_compromised).text.strip()
    ips = extract_ips(text)
    d['compromised_host'] = ips

    text = requests.get(et_emerging_bot).text.strip()
    ips = extract_ips(text)
    d['c2'] = ips

    text = requests.get(et_ciarmy).text.strip()
    ips = extract_ips(text)
    d['poor_reputation_ip'] = ips

    text = requests.get(et_spamhaus).text.strip()
    ips = extract_ips(text)
    d['dont_route_or_peer'] = ips

    return d


def malware_domain_list():
    d = {}
    text = requests.get(mdl_ips).text
    ips = [i.strip() for i in text.strip().split('\n')]
    d['hosting_malware'] = ips

    text = requests.get(mdl_hosts).text
    for line in filter_comments(text.split('\n')):
        ioc = line.split()[1]
        ioc = re.sub('^www\.', '', ioc)
        d['hosting_malware'].append(ioc)

    # Dedup just to be safe
    d['hosting_malware'] = list(set(d['hosting_malware']))
    return d


def malware_domains():
    d = {'dyndns': [], 'url_shorteners': []}

    data = requests.get(malware_domains_dyndns).text
    for line in filter_comments(data.split('\n')):
        ioc = line.split()[0]
        ioc = re.sub('^www\.', '', ioc)
        d['dyndns'].append(ioc)

    data = requests.get(malware_domains_url_short).text
    for line in filter_comments(data.split('\n')):
        ioc = line.split()[0]
        ioc = re.sub('^www\.', '', ioc)
        d['url_shorteners'].append(ioc)

    data = requests.get(malware_domains_domains).text
    for line in filter_comments(data.split('\n')):
        line = line.split()

        if len(line) in [7, 8, 9, 10, 11]:
            ioc, tag = line[1], line[2]
        elif len(line) in [4, 5, 6]:
            ioc, tag = line[0], line[1]
        ioc = re.sub('^www\.', '', ioc)

        if tag not in d:
            d[tag] = []
        d[tag].append(ioc)

    return d


def spyeye_tracker():
    d = {'c2': []}
    data = requests.get(spyeye, headers=headers).content.strip()
    if 'Come back later' in data:
        return {}

    for line in filter_comments(data.split('\n')):
        ioc = line.split()[1]
        ioc = re.sub('^www\.', '', ioc)
        d['c2'].append(ioc)
    return d


def zeus_tracker():
    d = {'c2': []}
    data = requests.get(zeus).text.strip()
    if 'Come back later' in data:
        return {}

    for line in filter_comments(data.split('\n')):
        ioc = line.split()[1]
        ioc = re.sub('^www\.', '', ioc)
        d['c2'].append(ioc)
    return d


def sri():
    d = {'malware_related': []}

    data = requests.get(sri_infected_client).text.strip()
    text = data.split('<pre>')[1].split('</pre>')[0]
    ips = extract_ips(text)
    d['infected_client'] = ips

    data = requests.get(sri_malware).text.strip()
    text = data.split('<pre>')[1].split('</pre>')[0]
    for line in filter_comments(text.split('\n')):
        ioc = line.split()[0]
        ioc = re.sub('^www\.', '', ioc)
        d['malware_related'].append(ioc)

    return d


if __name__ == '__main__':
    alienvault()
    emerging_threats()
    malware_domain_list()
    malware_domains()
    spyeye_tracker()
    zeus_tracker()
    sri()
