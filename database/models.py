import sqlite3
from contextlib import contextmanager
import json
import os

# Database in current directory - works on Windows, Mac, and Linux
DATABASE_PATH = 'scanner.db'

def init_db():
    """Initialize the database with required tables"""
    # Database will be created automatically in current directory
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scope_domain TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT DEFAULT 'running',
                pages_crawled INTEGER DEFAULT 0
            )
        ''')
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                parameter TEXT,
                evidence TEXT,
                severity TEXT NOT NULL,
                impact TEXT,
                recommendation TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
        ''')
        
        # Crawled URLs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crawled_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                method TEXT,
                parameters TEXT,
                crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
                UNIQUE(scan_id, url)
            )
        ''')
        
        conn.commit()
        print(f"✅ Database initialized at: {os.path.abspath(DATABASE_PATH)}")

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        conn.close()

def add_scan(target_url, scope_domain=None):
    """Add a new scan to the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (target_url, scope_domain, status) VALUES (?, ?, ?)',
            (target_url, scope_domain, 'running')
        )
        scan_id = cursor.lastrowid
        print(f"✅ Added scan #{scan_id} for {target_url}")
        return scan_id

def update_scan_status(scan_id, status, pages_crawled=None):
    """Update scan status"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if status in ['Completed', 'Failed']:
            cursor.execute(
                '''UPDATE scans 
                   SET status = ?, 
                       end_time = datetime('now'),
                       pages_crawled = ? 
                   WHERE id = ?''',
                (status, pages_crawled or 0, scan_id)
            )
        else:
            cursor.execute(
                '''UPDATE scans 
                   SET status = ?, 
                       pages_crawled = ? 
                   WHERE id = ?''',
                (status, pages_crawled or 0, scan_id)
            )
        print(f"✅ Updated scan #{scan_id} status to: {status}")

def add_finding(scan_id, url, vulnerability_type, parameter=None, evidence=None, 
                severity='Low', impact=None, recommendation=None):
    """Add a vulnerability finding to the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO findings 
            (scan_id, url, vulnerability_type, parameter, evidence, severity, impact, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, url, vulnerability_type, parameter, evidence, 
              severity, impact, recommendation))
        print(f"✅ Added {severity} finding: {vulnerability_type} at {url}")

def add_crawled_url(scan_id, url, method=None, parameters=None):
    """Add a crawled URL to the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Convert parameters to string if provided
        params_str = None
        if parameters:
            try:
                params_str = json.dumps(parameters) if isinstance(parameters, (dict, list)) else str(parameters)
            except:
                params_str = str(parameters)
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO crawled_urls (scan_id, url, method, parameters)
                VALUES (?, ?, ?, ?)
            ''', (scan_id, url, method, params_str))
            return True
        except Exception as e:
            # Silently ignore duplicate URL errors
            return False

def get_scans():
    """Get all scans"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT *, 
                   CASE 
                       WHEN status = 'Completed' THEN 1
                       WHEN status = 'Scanning' THEN 2
                       WHEN status = 'Crawling' THEN 3
                       WHEN status = 'running' THEN 4
                       WHEN status = 'Failed' THEN 5
                       ELSE 6
                   END as sort_order
            FROM scans 
            ORDER BY sort_order, start_time DESC
        ''')
        scans = [dict(row) for row in cursor.fetchall()]
        
        # Remove the temporary sort_order field
        for scan in scans:
            scan.pop('sort_order', None)
        
        return scans

def get_scan(scan_id):
    """Get a specific scan by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_scan_findings(scan_id):
    """Get findings for a specific scan"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM findings 
            WHERE scan_id = ? 
            ORDER BY 
                CASE severity 
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                timestamp DESC
        ''', (scan_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_crawled_urls(scan_id, limit=500):
    """Get crawled URLs for a scan"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM crawled_urls 
            WHERE scan_id = ? 
            ORDER BY crawled_at DESC
            LIMIT ?
        ''', (scan_id, limit))
        return [dict(row) for row in cursor.fetchall()]

def get_findings_count_by_severity(scan_id):
    """Get count of findings grouped by severity"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM findings 
            WHERE scan_id = ?
            GROUP BY severity
        ''', (scan_id,))
        
        result = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Ensure all severity levels are present
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity not in result:
                result[severity] = 0
        
        return result

# Test function to verify database works
def test_database():
    """Test the database connection and basic operations"""
    try:
        init_db()
        
        # Test adding a scan
        scan_id = add_scan("http://test.com")
        
        # Test updating scan
        update_scan_status(scan_id, "Completed", 10)
        
        # Test adding a finding
        add_finding(
            scan_id=scan_id,
            url="http://test.com/page",
            vulnerability_type="SQL Injection",
            parameter="id",
            evidence="' OR '1'='1 triggered error",
            severity="High",
            impact="Database compromise",
            recommendation="Use parameterized queries"
        )
        
        # Test adding crawled URL
        add_crawled_url(scan_id, "http://test.com/page", "GET", {"id": "1"})
        
        # Test retrieving data
        scans = get_scans()
        findings = get_scan_findings(scan_id)
        urls = get_crawled_urls(scan_id)
        
        print(f"✅ Database test successful!")
        print(f"   Scans: {len(scans)}")
        print(f"   Findings: {len(findings)}")
        print(f"   URLs: {len(urls)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# Run test if this file is executed directly
if __name__ == "__main__":
    test_database()