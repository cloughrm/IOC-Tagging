OSINT-IOC-Summarizer
====================
Collects network IOCs (domains and IPs) from open source lists, stores them in MondoDB. A python web front end is provided for searching the data.

Notes
=====
This application is currently in a non working state. The python front end is legacy code and I would like to rewrite it using Flask.

Sources
=======
The code for collecting the intelligence data is located in backend/sources.py. Currently, the following sources are ingested:
* Alienvault reputation
* Emerging Threats tor
* Emerging Threats compromised ips
* Emerging Threats emerging compromised
* Emerging Threats emerging bot
* Emerging Threats ciarmy
* Emerging Threats spamhaus
* Malware Domain List ips
* Malware Domain List hosts
* Malware domains dyndns
* Malware domains url short
* Malware domains domains
* Spyeye Tracker
* Zeus Tracker
* SRI infected client
* SRI malware

Requirements (Ubuntu 14.04 LTS)
===============================
* Clone the project
* Install MongoDB
```
$ sudo apt-get install mongodb
```
* Install python packages
```
$ sudo pip install -r requirements.txt
```
* To run the project, run "python site.py"
