from flask import Flask, render_template, request, jsonify, redirect, url_for
from database.models import init_db, add_scan, update_scan_status, get_scans, get_scan, get_scan_findings, get_crawled_urls
from scanner.crawler import Crawler
from scanner.vulnerabilities import VulnerabilityScanner
import threading
import traceback
from urllib.parse import urlparse

app = Flask(__name__)

# Initialize database
init_db()

def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

@app.route('/')
def index():
    """Dashboard home page"""
    try:
        scans = get_scans()
        return render_template('index.html', scans=scans)
    except Exception as e:
        return f"Error loading dashboard: {str(e)}", 500

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Start a new scan"""
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        
        if not target_url:
            return render_template('scan.html', error="URL is required")
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        if not is_valid_url(target_url):
            return render_template('scan.html', error="Invalid URL format")
        
        scope_domain = request.form.get('scope_domain', '').strip()
        
        try:
            scan_id = add_scan(target_url, scope_domain)
            
            # Start background scan
            thread = threading.Thread(
                target=run_scan, 
                args=(scan_id, target_url, scope_domain),
                daemon=True
            )
            thread.start()
            
            return redirect(url_for('scan_status', scan_id=scan_id))
        
        except Exception as e:
            return render_template('scan.html', error=f"Error: {str(e)}")
    
    return render_template('scan.html')

@app.route('/scan/<int:scan_id>')
def scan_status(scan_id):
    """View scan status and findings"""
    try:
        scan = get_scan(scan_id)
        if not scan:
            return render_template('error.html', error="Scan not found"), 404
        
        findings = get_scan_findings(scan_id)
        crawled_urls = get_crawled_urls(scan_id, limit=500)
        
        # Calculate statistics
        severity_counts = {
            'Critical': sum(1 for f in findings if f['severity'] == 'Critical'),
            'High': sum(1 for f in findings if f['severity'] == 'High'),
            'Medium': sum(1 for f in findings if f['severity'] == 'Medium'),
            'Low': sum(1 for f in findings if f['severity'] == 'Low'),
        }
        
        return render_template(
            'findings.html',
            scan=scan,
            findings=findings,
            crawled_urls=crawled_urls,
            severity_counts=severity_counts
        )
    except Exception as e:
        return render_template('error.html', error=str(e)), 500

def run_scan(scan_id, target_url, scope_domain):
    """Run scan in background thread"""
    try:
        print(f"[Scan {scan_id}] Starting scan for {target_url}")
        
        # Phase 1: Crawling
        update_scan_status(scan_id, 'Crawling')
        crawler = Crawler(scan_id, target_url, scope_domain, max_pages=50, max_depth=2)
        crawled_urls, forms = crawler.crawl()
        
        print(f"[Scan {scan_id}] Crawled {len(crawled_urls)} URLs, found {len(forms)} forms")
        
        # Phase 2: Scanning
        update_scan_status(scan_id, 'Scanning', len(crawled_urls))
        scanner = VulnerabilityScanner(scan_id, delay=0.3)
        
        # Scan URLs
        for i, url in enumerate(crawled_urls[:50], 1):  # Limit to 50 URLs
            try:
                scanner.scan_url(url)
            except Exception as e:
                print(f"[Scan {scan_id}] Error scanning {url}: {e}")
        
        # Scan forms
        for i, form in enumerate(forms[:20], 1):  # Limit to 20 forms
            try:
                scanner.scan_form(form)
            except Exception as e:
                print(f"[Scan {scan_id}] Error scanning form: {e}")
        
        # Complete
        update_scan_status(scan_id, 'Completed', len(crawled_urls))
        print(f"[Scan {scan_id}] Scan completed successfully")
        
    except Exception as e:
        print(f"[Scan {scan_id}] Fatal error: {e}")
        traceback.print_exc()
        update_scan_status(scan_id, 'Failed')

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error="Server error"), 500

if __name__ == '__main__':
    print("Starting Web Application Security Scanner...")
    print("Database initialized...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000)