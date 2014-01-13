#!/usr/bin/python

import os
import json
import sys
import re
import requests
import tornado.web, tornadio, tornadio.router, tornadio.server

from bulkwhois.cymru import BulkWhoisCymru
bulk_whois = BulkWhoisCymru()

import pymongo
mongo_connection = pymongo.MongoClient('localhost', 27017)
dash_db = mongo_connection.osint_dashboard
ioc_coll = dash_db.ioc_tags
ioc_stats_coll = dash_db.ioc_tags_stats

ip_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
pages = [('HOME',''), ('EXTRACT IP', 'extractip'), ('TAGS', 'tags/'), ('BULK WHOIS', 'whois')]

class BaseHandler(tornado.web.RequestHandler):
    pass

class IndexHandler(BaseHandler):
    def get(self):
        self.render('index.html', pages=pages, page_title='Welcome', current_page='/')

class ExtractIPHandler(BaseHandler):
    def get(self):
        self.render('extract_ip.html', pages=pages, page_title='Extract IP', results=None, current_page='extractip')

    def post(self):
        if self.get_argument('textarea'):
            text = remove_non_ascii(self.get_argument('textarea'))
            self.search(text)

        elif self.request.files:
            file_info = self.request.files['filearg'][0]

            filename = file_info['filename']
            extension = os.path.splitext(filename)[1]
            content_type = file_info['content_type']

            # requires apt-get install python-pdfminer            
            if 'pdf' in content_type:
                write_name = 'pdf.pdf'
                fh = open(write_name, 'w')
                fh.write(file_info['body'])
                fh.close()

                txt = os.popen('pdf2txt ' + write_name).read()
                os.remove(write_name)
                self.search(txt)

            elif 'text' in content_type:
                txt = file_info['body']
                self.search(txt)

            else:
                # Unsupported file type
                self.render('extract_ip.html', pages=pages, page_title='Extract IP', results=['Unsupported file type'], current_page='extractip')

        elif self.request.files == {} and not self.get_argument('textarea'):
            # User didnt provide any files or text
            self.render('extract_ip.html', pages=pages, page_title='Extract IP', results=['Give me something to extract IPs from'], current_page='extractip')
        
        else:
            # Unhandeled condition
            self.render('extract_ip.html', pages=pages, page_title='Extract IP', results=['Unknown Error, your screwed'], current_page='extractip')

    def search(self, txt):
        matches = re.findall(ip_regex, txt)
        if matches:
            return self.render('extract_ip.html', pages=pages, page_title='Extract IP', results=set(matches), current_page='extractip')
        else:
            return self.render('extract_ip.html', pages=pages, page_title='Extract IP', results=['No IPs found'], current_page='extractip')

class WhoIsHandler(BaseHandler):
    def get(self):
        return self.render('whois.html', pages=pages, results=None, page_title='Bulk WhoIs', current_page='whois')

    def post(self):
        ip_list = []
        if self.get_argument('textarea'):
            text = remove_non_ascii(self.get_argument('textarea'))
            matches = re.findall(ip_regex, text)
            if matches:
                for ip in matches:
                    ip_list.append(ip.encode('ascii','ignore'))
                records = bulk_whois.lookup_ips(ip_list)
                return self.render('whois.html', pages=pages, results=records, page_title='Bulk WhoIs', current_page='whois')
            else:
                self.redirect('/whois')

        elif not self.get_argument('textarea'):
            self.redirect('/whois')

class TagHandler(BaseHandler):
    def get(self, option=None, query=None):
        top_tags = [i for i in ioc_stats_coll.find({'stats_type':'top_tags'})]
        sources = [i for i in ioc_stats_coll.find({'stats_type':'source_count'})]
        latest_iocs = [i for i in ioc_coll.find({}).sort('_id',-1).limit(30)]

        if option == 'ioc' and query:
            results = [i for i in ioc_coll.find({'ioc':re.compile(query, re.IGNORECASE)})]
            return self.render('tags.html',
                                pages=pages,
                                page_title='IP Tags',
                                current_page='tags/',
                                top_tags=top_tags,
                                sources=sources, 
                                latest_iocs=latest_iocs,
                                search_result=results,
                                query=query,
                                option='ioc')

        elif option == 'tag' and query:
            results = [i for i in ioc_coll.find({'tags.text':query}).limit(100)]
            return self.render('tags.html',
                                pages=pages,
                                page_title='IP Tags',
                                current_page='tags/',
                                top_tags=top_tags,
                                sources=sources, 
                                latest_iocs=latest_iocs,
                                search_result=results,
                                query=query,
                                option=option)

        elif option == 'source' and query:
            results = [i for i in ioc_coll.find({'tags.source':query}).limit(100)]
            return self.render('tags.html',
                                pages=pages,
                                page_title='IP Tags',
                                current_page='tags/',
                                top_tags=top_tags,
                                sources=sources, 
                                latest_iocs=latest_iocs,
                                search_result=results,
                                query=query,
                                option=option)

        else:        
            return self.render('tags.html',
                                pages=pages,
                                page_title='IP Tags',
                                current_page='tags/',
                                top_tags=top_tags,
                                sources=sources, 
                                latest_iocs=latest_iocs,
                                search_result=None)

def remove_non_ascii(s):
    return ''.join(i for i in s if ord(i)<128)

if __name__ == '__main__':
    settings = {
        'template_path' : os.path.join(os.path.dirname(__file__), 'templates'),
        'static_path' : os.path.join(os.path.dirname(__file__), 'static'),
    }
    app = tornado.web.Application([
            (r'/', IndexHandler),
            (r'favicon.ico', tornado.web.StaticFileHandler),
            (r'/extractip', ExtractIPHandler),
            (r'/tags/([a-zA-Z]*)/{0,1}(.*)', TagHandler),
            (r'/whois', WhoIsHandler),
        ],
        socket_io_port=8000,
        debug=True,
        **settings
    )
    tornadio.server.SocketServer(app)