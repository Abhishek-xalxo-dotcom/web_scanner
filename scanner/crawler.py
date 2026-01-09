import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from queue import Queue, Empty
import urllib.robotparser
from database.models import add_crawled_url

class Crawler:
    def __init__(self, scan_id, base_url, scope_domain=None, max_pages=100, max_depth=3, max_workers=5):
        self.scan_id = scan_id
        self.base_url = base_url.rstrip('/')
        parsed_base = urlparse(base_url)
        self.scope_domain = scope_domain or parsed_base.netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_workers = max_workers
        
        self.visited = set()
        self.url_queue = Queue()
        self.url_queue.put((self.base_url, 0))
        self.lock = threading.Lock()
        self.forms = []
        self.page_count = 0
        self.crawling_active = True
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        
        # Setup robots.txt parser
        self.robot_parser = urllib.robotparser.RobotFileParser()
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            self.robot_parser.set_url(robots_url)
            self.robot_parser.read()
        except:
            self.robot_parser = None
    
    def can_fetch(self, url):
        """Check if URL can be fetched according to robots.txt"""
        if not self.robot_parser:
            return True
        return self.robot_parser.can_fetch('*', url)
    
    def is_in_scope(self, url):
        """Check if URL is within scope"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True
            return parsed.netloc == self.scope_domain
        except:
            return False
    
    def normalize_url(self, url):
        """Normalize URL for comparison"""
        try:
            parsed = urlparse(url)
            # Remove fragment and query for comparison
            normalized = parsed._replace(fragment='', query='').geturl()
            return normalized.rstrip('/')
        except:
            return url
    
    def extract_links(self, html, base_url):
        """Extract links from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href and not href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                absolute_url = urljoin(base_url, href)
                normalized = self.normalize_url(absolute_url)
                if self.is_in_scope(absolute_url):
                    links.add(normalized)
        
        return links
    
    def extract_forms(self, url, html):
        """Extract forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            if action.startswith('javascript:'):
                continue
            
            form_url = urljoin(url, action) if action else url
            
            form_data = {
                'url': form_url,
                'method': method,
                'action': form_url,
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text').lower()
                if input_type in ['submit', 'button', 'image', 'reset']:
                    continue
                
                input_name = input_tag.get('name')
                if not input_name:
                    continue
                
                input_data = {
                    'name': input_name,
                    'type': input_type,
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            if form_data['inputs']:
                with self.lock:
                    self.forms.append(form_data)
    
    def crawl_page(self, url, depth):
        """Crawl a single page"""
        normalized_url = self.normalize_url(url)
        
        with self.lock:
            if normalized_url in self.visited:
                return False
            if depth > self.max_depth:
                return False
            if not self.can_fetch(url):
                return False
            if self.page_count >= self.max_pages:
                return False
            
            self.visited.add(normalized_url)
            self.page_count += 1
        
        try:
            print(f"[Crawler] [{self.page_count}/{self.max_pages}] Crawling: {url}")
            
            response = self.session.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Check if it's HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                return True
            
            # Store crawled URL
            add_crawled_url(self.scan_id, url, 'GET')
            
            # Extract forms
            self.extract_forms(url, response.text)
            
            # Extract new links
            if depth < self.max_depth:
                new_links = self.extract_links(response.text, url)
                
                with self.lock:
                    for link in new_links:
                        if link not in self.visited:
                            self.url_queue.put((link, depth + 1))
            
            return True
            
        except requests.RequestException as e:
            print(f"[Crawler] Error crawling {url}: {e}")
            return False
        except Exception as e:
            print(f"[Crawler] Unexpected error crawling {url}: {e}")
            return False
    
    def crawl(self):
        """Main crawling function"""
        print(f"[Crawler] Starting crawl for {self.base_url}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            while self.crawling_active and self.page_count < self.max_pages:
                try:
                    # Get next URL from queue
                    url, depth = self.url_queue.get(timeout=10)
                    
                    # Submit crawling task
                    future = executor.submit(self.crawl_page, url, depth)
                    futures[future] = url
                    
                    # Process completed futures
                    completed = []
                    for future in list(futures.keys()):
                        if future.done():
                            try:
                                future.result()
                            except Exception as e:
                                print(f"[Crawler] Task error: {e}")
                            completed.append(future)
                    
                    # Remove completed futures
                    for future in completed:
                        del futures[future]
                    
                except Empty:
                    # Queue empty, check if any tasks are running
                    if not futures:
                        break
                    time.sleep(0.1)
                except Exception as e:
                    print(f"[Crawler] Error in crawl loop: {e}")
                    break
        
        # Wait for remaining tasks
        for future in futures:
            try:
                future.result(timeout=5)
            except:
                pass
        
        self.crawling_active = False
        print(f"[Crawler] Complete. Visited {self.page_count} pages, found {len(self.forms)} forms.")
        
        return list(self.visited), self.forms