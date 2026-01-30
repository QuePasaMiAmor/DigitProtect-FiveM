import os

def writenginxfile(serverslist, name, domainname):
    if domainname == "" or domainname == None:
        domainname = "play." + name + ".fr"
    if name == "serenity":
        domainname = "serenity.digitprotect.fr"
    elif name == "sneakylife":
        domainname = "sneakylife.digitprotect.fr"
    elif name == "blackstory":
        domainname = "play.blackstory.fr"
            
    print(domainname, name)
    nginxfile = open("/etc/nginx/sites-enabled/" + domainname + ".conf", "w")
    nginxstring = """upstream backendREPLACE_BY_NAME {
    REPLACE_BY_SERVERS 
}

server {
    listen 80; 
    server_name REPLACE_BY_DOMAINNAME;
    location / {
        # - IPv4
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# - IPv6
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

        real_ip_header CF-Connecting-IP;
        limit_req zone=flood burst=5 nodelay;
        proxy_set_header LB-Real-IP $remote_addr;
        proxy_pass http://backendREPLACE_BY_NAME;
    }
}"""

    if name == "devserver": 
        nginxstring = """upstream backendREPLACE_BY_NAME {
    REPLACE_BY_SERVERS
}

upstream antiscrapREPLACE_BY_NAME {
    server 127.0.0.1:61012;
}

server {
    listen 80; 
    server_name REPLACE_BY_DOMAINNAME;

    location /client {
        # - IPv4
        set_real_ip_from 173.245.48.0/20;
        set_real_ip_from 103.21.244.0/22;
        set_real_ip_from 103.22.200.0/22;
        set_real_ip_from 103.31.4.0/22;
        set_real_ip_from 141.101.64.0/18;
        set_real_ip_from 108.162.192.0/18;
        set_real_ip_from 190.93.240.0/20;
        set_real_ip_from 188.114.96.0/20;
        set_real_ip_from 197.234.240.0/22;
        set_real_ip_from 198.41.128.0/17;
        set_real_ip_from 162.158.0.0/15;
        set_real_ip_from 104.16.0.0/13;
        set_real_ip_from 104.24.0.0/14;
        set_real_ip_from 172.64.0.0/13;
        set_real_ip_from 131.0.72.0/22;

        # - IPv6
        set_real_ip_from 2400:cb00::/32;
        set_real_ip_from 2606:4700::/32;
        set_real_ip_from 2803:f800::/32;
        set_real_ip_from 2405:b500::/32;
        set_real_ip_from 2405:8100::/32;
        set_real_ip_from 2a06:98c0::/29;
        set_real_ip_from 2c0f:f248::/32;

        real_ip_header CF-Connecting-IP;
        proxy_set_header backendurl 46.105.209.77:30140;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        # required to pass auth headers correctly
        proxy_pass_request_headers on;
        # required to not make deferrals close the connection instantly
        proxy_http_version 1.1;
        limit_req zone=flood burst=5 nodelay;
        proxy_set_header LB-Real-IP $remote_addr;
        proxy_pass http://antiscrapREPLACE_BY_NAME;
    }

    location /info.json {
        # - IPv4
        set_real_ip_from 173.245.48.0/20;
        set_real_ip_from 103.21.244.0/22;
        set_real_ip_from 103.22.200.0/22;
        set_real_ip_from 103.31.4.0/22;
        set_real_ip_from 141.101.64.0/18;
        set_real_ip_from 108.162.192.0/18;
        set_real_ip_from 190.93.240.0/20;
        set_real_ip_from 188.114.96.0/20;
        set_real_ip_from 197.234.240.0/22;
        set_real_ip_from 198.41.128.0/17;
        set_real_ip_from 162.158.0.0/15;
        set_real_ip_from 104.16.0.0/13;
        set_real_ip_from 104.24.0.0/14;
        set_real_ip_from 172.64.0.0/13;
        set_real_ip_from 131.0.72.0/22;

        # - IPv6
        set_real_ip_from 2400:cb00::/32;
        set_real_ip_from 2606:4700::/32;
        set_real_ip_from 2803:f800::/32;
        set_real_ip_from 2405:b500::/32;
        set_real_ip_from 2405:8100::/32;
        set_real_ip_from 2a06:98c0::/29;
        set_real_ip_from 2c0f:f248::/32;

        real_ip_header CF-Connecting-IP;
        limit_req zone=flood burst=5 nodelay;
        proxy_set_header LB-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_pass_request_headers on;
        proxy_http_version 1.1;
        proxy_cache_lock on;
        proxy_cache fivem;
        proxy_cache_valid 1y;
        proxy_cache_key $request_uri$is_args$args;
        proxy_cache_revalidate on;
        proxy_cache_min_uses 1;
        proxy_pass http://backendREPLACE_BY_NAME;
    }

    location / {
        # - IPv4
        set_real_ip_from 173.245.48.0/20;
        set_real_ip_from 103.21.244.0/22;
        set_real_ip_from 103.22.200.0/22;
        set_real_ip_from 103.31.4.0/22;
        set_real_ip_from 141.101.64.0/18;
        set_real_ip_from 108.162.192.0/18;
        set_real_ip_from 190.93.240.0/20;
        set_real_ip_from 188.114.96.0/20;
        set_real_ip_from 197.234.240.0/22;
        set_real_ip_from 198.41.128.0/17;
        set_real_ip_from 162.158.0.0/15;
        set_real_ip_from 104.16.0.0/13;
        set_real_ip_from 104.24.0.0/14;
        set_real_ip_from 172.64.0.0/13;
        set_real_ip_from 131.0.72.0/22;

        # - IPv6
        set_real_ip_from 2400:cb00::/32;
        set_real_ip_from 2606:4700::/32;
        set_real_ip_from 2803:f800::/32;
        set_real_ip_from 2405:b500::/32;
        set_real_ip_from 2405:8100::/32;
        set_real_ip_from 2a06:98c0::/29;
        set_real_ip_from 2c0f:f248::/32;

        real_ip_header CF-Connecting-IP;
        limit_req zone=flood burst=5 nodelay;
        proxy_set_header LB-Real-IP $remote_addr;
        proxy_pass http://backendREPLACE_BY_NAME;
    }
}"""
    nginxstring = nginxstring.replace("REPLACE_BY_SERVERS", serverslist)
    nginxstring = nginxstring.replace("REPLACE_BY_DOMAINNAME", domainname)
    nginxstring = nginxstring.replace("REPLACE_BY_NAME", name)
    nginxfile.write(nginxstring)
    os.system("sudo service nginx reload")

from flask import Flask, request
from flask_restful import Api

app = Flask(__name__)
api = Api(app)

key_valid = "SECRET_KEY_HERE"

@app.route('/', methods=['GET', 'POST'])
def index():
    key = request.args.get("key")
    if str(key) == key_valid:

        action = request.args.get("action")
        if action == "setup":
            serverslist = request.args.get("serverslist")
            if serverslist != None: 
                name = request.args.get("name")
                if name != None: 
                    serverslist = serverslist.replace("[space]", " ")
                    serverslist = serverslist.replace("[backtoline]", "\n")
                    writenginxfile(serverslist, name, request.args.get("domainname"))
                    os.system("sudo service nginx reload")
                    return "true" 
                else:
                    return "false"
            else:
                return "false"
        else:    
            return "<h1>Good Key but not action set</h1>"
        

    else:
        return '<h1>En maintenance</h1><img src="https://image.noelshack.com/fichiers/2018/22/3/1527639157-dfqsf.png" alt="alternatetext">'

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=40321,debug=True)
