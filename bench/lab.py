"""Local lab for the raijin-probe benchmark: many tiny HTTP servers on 127.0.0.1, one process.

Each argument is port=kind. Kinds mimic what a probe sees in the wild: default pages that repeat
across hosts, a login panel, 403/401 responses, redirects, a 500, a Jenkins dashboard, a directory
listing, an API and a few different servers.

usage: python3 lab.py 19001=nginx 19002=login ...
"""
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NGINX = """<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
"""

APACHE = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">
<html xmlns="http://www.w3.org/1999/xhtml">
<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Apache2 Ubuntu Default Page: It works</title></head>
<body><div class="main_page"><div class="page_header floating_element">
<span class="floating_element">Apache2 Ubuntu Default Page</span></div>
<div class="section_header"><div id="about"></div>It works!</div>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after
installation on Ubuntu systems.</p></div></body></html>
"""

LOGIN = """<!DOCTYPE html><html><head><title>Admin Login</title></head><body>
<h1>Administration</h1><form method="post" action="/login">
<input name="username" type="text"><input name="password" type="password">
<button type="submit">Sign in</button></form></body></html>
"""

JENKINS = """<!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title>
<script src="/static/abc/scripts/hudson-behavior.js"></script></head>
<body id="jenkins" class="yui-skin-sam jenkins-2.401.3"><div id="page-header">Jenkins</div></body></html>
"""

TOMCAT = """<!DOCTYPE html><html lang="en"><head><title>Apache Tomcat/9.0.65</title></head>
<body><h1>Apache Tomcat/9.0.65</h1><p>If you're seeing this, you've successfully installed Tomcat.
Congratulations!</p><a href="/manager/html">Manager App</a></body></html>
"""

LISTING = """<!DOCTYPE HTML><html lang="en"><head><meta charset="utf-8">
<title>Directory listing for /</title></head><body><h1>Directory listing for /</h1><hr><ul>
<li><a href="backup.sql">backup.sql</a></li><li><a href="config.php.bak">config.php.bak</a></li>
</ul><hr></body></html>
"""


def page(status, body, server, ctype="text/html", headers=()):
    return status, body, server, ctype, list(headers)


KINDS = {
    "nginx": lambda port: page(200, NGINX, "nginx/1.18.0 (Ubuntu)"),
    "apache": lambda port: page(200, APACHE, "Apache/2.4.41 (Ubuntu)"),
    "notfound": lambda port: page(404, "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>\n", "nginx"),
    "login": lambda port: page(200, LOGIN, "nginx/1.18.0 (Ubuntu)"),
    "forbidden": lambda port: page(403, "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>\n", "nginx"),
    "basic": lambda port: page(401, "<html><head><title>401 Authorization Required</title></head><body>401</body></html>\n", "nginx", headers=[("WWW-Authenticate", 'Basic realm="Restricted"')]),
    "tologin": lambda port: page(302, "", "nginx/1.18.0 (Ubuntu)", headers=[("Location", "/admin/login")]),
    "tohttps": lambda port: page(301, "<html><head><title>301 Moved Permanently</title></head><body>301</body></html>\n", "nginx", headers=[("Location", "https://127.0.0.1/")]),
    "error": lambda port: page(500, "<html><head><title>Internal Server Error</title></head><body><h1>Internal Server Error</h1></body></html>\n", "gunicorn"),
    "jenkins": lambda port: page(200, JENKINS, "Jetty(10.0.13)", headers=[("X-Jenkins", "2.401.3"), ("X-Hudson", "1.395")]),
    "tomcat": lambda port: page(200, TOMCAT, "Apache-Coyote/1.1"),
    "listing": lambda port: page(200, LISTING, "SimpleHTTP/0.6 Python/3.12.3"),
    "api": lambda port: page(200, '{"status":"ok","version":"2.3.1"}\n', "Werkzeug/2.3.7 Python/3.11.4", "application/json"),
}


def handler(kind, port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body, server, ctype, headers = KINDS[kind](port)
            data = body.encode()
            self.send_response_only(status)
            self.send_header("Server", server)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        do_HEAD = do_GET

        def log_message(self, *args):
            pass

    return H


def main():
    servers = []
    for arg in sys.argv[1:]:
        port, kind = arg.split("=", 1)
        s = ThreadingHTTPServer(("127.0.0.1", int(port)), handler(kind, int(port)))
        servers.append(s)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print(f"lab: {len(servers)} servers up", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
