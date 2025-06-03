import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urldefrag
import urllib.request
import socket

class ContactLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.contact_link = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href and "contact" in href and self.contact_link is None:
                self.contact_link = href


def run_server(directory, port):
    handler = SimpleHTTPRequestHandler
    httpd = HTTPServer(("localhost", port), handler)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    return httpd, thread


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def test_contact_link_http_200():
    port = get_free_port()
    httpd, thread = run_server(Path(__file__).resolve().parent.parent, port)
    try:
        base_url = f"http://localhost:{port}/index.html"
        with urllib.request.urlopen(base_url) as resp:
            html = resp.read().decode()

        parser = ContactLinkParser()
        parser.feed(html)
        assert parser.contact_link, "Contact link not found"

        link = parser.contact_link
        url = urljoin(base_url, link)
        url, _ = urldefrag(url)
        if url.endswith("/index"):
            url += ".html"
        with urllib.request.urlopen(url) as resp:
            assert resp.status == 200
    finally:
        httpd.shutdown()
        thread.join()

