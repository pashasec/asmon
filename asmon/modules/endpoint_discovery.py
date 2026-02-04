"""
asmon/modules/endpoint_discovery.py — Sensitive endpoint discovery.

Discovers exposed sensitive resources:
  - Admin panels and management interfaces
  - Backup files and archives
  - Configuration files
  - Source code and version control
  - Debug endpoints
  - API documentation
  - Directory listings
"""

import logging
import re
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from asmon.modules.base import (
    BaseModule,
    ModuleRegistry,
    Finding,
    FindingSeverity,
    FindingConfidence,
    FindingType,
)
from asmon.modules.http_utils import SecurityHTTPClient, build_url

logger = logging.getLogger("asmon.modules.endpoint_discovery")


# ---------------------------------------------------------------------------
# Wordlists for discovery
# ---------------------------------------------------------------------------

ADMIN_PATHS = [
    # Generic admin
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin.php", "/admin.asp", "/admin.aspx", "/admin.jsp",
    "/admincp", "/admincp/", "/admin_area", "/admin_area/",
    "/panel", "/panel/", "/controlpanel", "/cpanel",
    "/manage", "/manage/", "/management", "/management/",
    "/backend", "/backend/", "/backoffice", "/backoffice/",

    # CMS specific
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/administrator/index.php",  # Joomla
    "/admin/config.php",  # Various
    "/user/login", "/user/admin",  # Drupal
    "/bitrix/admin/", "/bitrix/admin/index.php",  # Bitrix
    "/modx/", "/manager/",  # MODx
    "/typo3/", "/typo3/index.php",  # TYPO3
    "/sitefinity", "/sitefinity/",  # Sitefinity
    "/umbraco", "/umbraco/",  # Umbraco
    "/sitecore", "/sitecore/admin/",  # Sitecore

    # Frameworks
    "/rails/info/properties",  # Rails debug
    "/elmah.axd",  # ASP.NET error log
    "/__debug__/",  # Various debug
    "/debug/default/view",  # Yii debug
    "/app_dev.php",  # Symfony dev

    # Database
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
    "/adminer", "/adminer.php",
    "/mysql", "/mysql/", "/mysqladmin",
    "/pgadmin", "/pgadmin/",
    "/mongodb", "/rockmongo",

    # Server management
    "/server-status", "/server-info",  # Apache
    "/nginx_status",  # Nginx
    "/status", "/health", "/healthcheck",
]

BACKUP_PATHS = [
    # Archives
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.bak",
    "/site.zip", "/site.tar.gz", "/www.zip", "/www.tar.gz",
    "/htdocs.zip", "/htdocs.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql", "/data.sql",
    "/backup/", "/backups/", "/bak/", "/old/",

    # Common backup patterns
    "/.backup", "/~backup", "/backup~",
    "/web.zip", "/web.tar", "/web.rar",
    "/archive.zip", "/archive.tar.gz",
    "/export.sql", "/export.zip",
]

CONFIG_PATHS = [
    # Environment files
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.backup", "/.env.bak", "/.env.old", "/.env.save",
    "/env.js", "/env.json",

    # Config files
    "/config.php", "/config.inc.php", "/configuration.php",
    "/config.yml", "/config.yaml", "/config.json", "/config.xml",
    "/settings.php", "/settings.py", "/settings.json",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/web.config", "/web.config.bak",
    "/app.config", "/appsettings.json",

    # Credentials
    "/credentials.json", "/credentials.xml",
    "/secrets.json", "/secrets.yml",
    "/.htpasswd", "/.htaccess",
    "/passwd", "/shadow",  # Unlikely but checked

    # Database configs
    "/database.yml", "/db.php", "/db_config.php",
    "/connection.php", "/conn.php",
]

SOURCE_PATHS = [
    # Version control
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/hgrc", "/.hg/store",
    "/.bzr/README", "/.bzr/branch-format",
    "/CVS/Root", "/CVS/Entries",

    # IDE / Editor
    "/.idea/workspace.xml", "/.idea/modules.xml",
    "/.vscode/settings.json", "/.vscode/launch.json",
    "/.project", "/.classpath",
    "/.settings/",

    # Source files (common leaks)
    "/index.php~", "/index.php.bak", "/index.php.old",
    "/app.py", "/main.py", "/server.py",
    "/package.json", "/composer.json", "/Gemfile",
    "/requirements.txt", "/Pipfile",
]

DEBUG_PATHS = [
    # Debug endpoints
    "/debug", "/debug/", "/_debug", "/_debug/",
    "/trace", "/trace.axd",
    "/phpinfo.php", "/info.php", "/test.php", "/i.php",
    "/pi.php", "/php_info.php", "/phpversion.php",
    "/console", "/console/",
    "/shell", "/shell/",
    "/repl", "/repl/",

    # Logs
    "/logs/", "/log/", "/error_log", "/errors.log",
    "/debug.log", "/app.log", "/application.log",
    "/var/log/", "/tmp/",

    # Test files
    "/test", "/test/", "/testing/", "/tests/",
    "/dev", "/dev/", "/development/",
    "/staging", "/staging/",
]

API_DOC_PATHS = [
    # Swagger / OpenAPI
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
    "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs/", "/api/docs",
    "/openapi.json", "/openapi.yaml",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",

    # GraphQL
    "/graphql", "/graphiql", "/graphql/console",
    "/playground", "/altair",

    # Other
    "/api", "/api/", "/api/v1", "/api/v2",
    "/docs", "/docs/", "/documentation",
    "/redoc", "/rapidoc",
]


# ---------------------------------------------------------------------------
# Response analysis patterns
# ---------------------------------------------------------------------------

DIRECTORY_LISTING_PATTERNS = [
    r"Index of /",
    r"<title>Directory listing",
    r"Directory Listing For",
    r"<h1>Index of",
    r"\[To Parent Directory\]",
    r"Parent Directory</a>",
]

SENSITIVE_CONTENT_PATTERNS = {
    "config": [
        r"DB_PASSWORD\s*=",
        r"DATABASE_URL\s*=",
        r"SECRET_KEY\s*=",
        r"API_KEY\s*=",
        r"AWS_SECRET",
        r"PRIVATE_KEY",
        r"password\s*[=:]\s*['\"]",
    ],
    "source": [
        r"<\?php",
        r"<%@\s*Page",
        r"#!/usr/bin",
        r"import\s+\w+",
        r"from\s+\w+\s+import",
        r"require\s*\(",
    ],
    "git": [
        r"ref:\s*refs/heads/",
        r"\[core\]",
        r"\[remote\s+",
    ],
}


@ModuleRegistry.register
class EndpointDiscoveryModule(BaseModule):
    """Discovers sensitive endpoints and exposed resources."""

    name = "endpoint_discovery"
    description = "Discovers admin panels, backups, configs, and sensitive files"
    risk_level = "medium"
    requires_authorization = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            user_agent=self.user_agent,
        )
        self.check_admin = True
        self.check_backup = True
        self.check_config = True
        self.check_source = True
        self.check_debug = True
        self.check_api = True
        self.concurrent_requests = kwargs.get("max_concurrent", 10)

    def run(self, target: dict) -> list[Finding]:
        """
        Run endpoint discovery.

        Args:
            target: Dict with 'host', 'port', 'url' (base URL)
        """
        self.findings = []

        host = target.get("host")
        port = target.get("port", 443)
        base_url = target.get("url")

        if not base_url:
            scheme = "https" if port == 443 else "http"
            base_url = f"{scheme}://{host}"
            if port not in (80, 443):
                base_url += f":{port}"

        self.logger.info("Starting endpoint discovery on %s", base_url)

        # Collect all paths to check
        paths_to_check = []

        if self.check_admin:
            paths_to_check.extend([(p, "admin") for p in ADMIN_PATHS])
        if self.check_backup:
            paths_to_check.extend([(p, "backup") for p in BACKUP_PATHS])
        if self.check_config:
            paths_to_check.extend([(p, "config") for p in CONFIG_PATHS])
        if self.check_source:
            paths_to_check.extend([(p, "source") for p in SOURCE_PATHS])
        if self.check_debug:
            paths_to_check.extend([(p, "debug") for p in DEBUG_PATHS])
        if self.check_api:
            paths_to_check.extend([(p, "api") for p in API_DOC_PATHS])

        # Run concurrent checks
        with ThreadPoolExecutor(max_workers=self.concurrent_requests) as executor:
            futures = {
                executor.submit(self._check_path, base_url, path, category): (path, category)
                for path, category in paths_to_check
            }

            for future in as_completed(futures):
                path, category = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        self.add_finding(finding)
                except Exception as e:
                    self.logger.debug("Error checking %s: %s", path, e)

        return self.findings

    def _check_path(
        self,
        base_url: str,
        path: str,
        category: str
    ) -> Optional[Finding]:
        """Check a single path for interesting responses."""
        url = build_url(base_url, path)

        result = self.http.get(url)

        if not result.success or not result.response:
            return None

        status = result.response.status_code
        body = result.response.body_preview
        headers = result.response.headers

        # Skip obvious 404s
        if status == 404:
            return None

        # Check for interesting responses
        finding = None

        if status == 200:
            finding = self._analyze_200_response(url, path, category, body, headers)
        elif status in (401, 403):
            # Protected resource exists
            finding = self._create_protected_finding(url, path, category, status)
        elif status in (301, 302):
            # Redirect - might indicate existence
            location = headers.get("Location", "")
            if self._is_interesting_redirect(path, location):
                finding = self._create_redirect_finding(url, path, category, location)

        return finding

    def _analyze_200_response(
        self,
        url: str,
        path: str,
        category: str,
        body: str,
        headers: dict
    ) -> Optional[Finding]:
        """Analyze successful response for sensitive content."""

        # Check for directory listing
        for pattern in DIRECTORY_LISTING_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return Finding(
                    finding_id=self.generate_finding_id("dirlist", url),
                    finding_type=FindingType.DIRECTORY_LISTING.value,
                    module=self.name,
                    severity=FindingSeverity.MEDIUM.value,
                    confidence=FindingConfidence.CONFIRMED.value,
                    host=self._extract_host(url),
                    url=url,
                    title=f"Directory listing enabled: {path}",
                    description="Directory listing is enabled, exposing file structure.",
                    evidence={
                        "path": path,
                        "matched_pattern": pattern,
                    },
                    remediation="Disable directory listing in server configuration.",
                    cwe_ids=["CWE-548"],
                )

        # Category-specific analysis
        if category == "admin":
            return self._analyze_admin_response(url, path, body, headers)
        elif category == "backup":
            return self._analyze_backup_response(url, path, body, headers)
        elif category == "config":
            return self._analyze_config_response(url, path, body, headers)
        elif category == "source":
            return self._analyze_source_response(url, path, body, headers)
        elif category == "debug":
            return self._analyze_debug_response(url, path, body, headers)
        elif category == "api":
            return self._analyze_api_response(url, path, body, headers)

        return None

    def _analyze_admin_response(self, url: str, path: str, body: str, headers: dict) -> Optional[Finding]:
        """Analyze potential admin panel response."""
        # Look for login forms or admin indicators
        admin_indicators = [
            r"<input[^>]*password",
            r"login|signin|authenticate",
            r"admin|dashboard|control\s*panel",
            r"username|email.*password",
        ]

        for pattern in admin_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                return Finding(
                    finding_id=self.generate_finding_id("admin", url),
                    finding_type=FindingType.EXPOSED_ADMIN.value,
                    module=self.name,
                    severity=FindingSeverity.MEDIUM.value,
                    confidence=FindingConfidence.HIGH.value,
                    host=self._extract_host(url),
                    url=url,
                    title=f"Admin panel discovered: {path}",
                    description="An administrative interface was discovered.",
                    evidence={
                        "path": path,
                        "matched_pattern": pattern,
                        "content_type": headers.get("Content-Type", ""),
                    },
                    remediation="Restrict access to admin panels via IP whitelist or VPN.",
                    cwe_ids=["CWE-200"],
                )

        return None

    def _analyze_backup_response(self, url: str, path: str, body: str, headers: dict) -> Optional[Finding]:
        """Analyze potential backup file response."""
        content_type = headers.get("Content-Type", "").lower()

        # Check if it's a downloadable file
        if any(t in content_type for t in ["application/zip", "application/x-tar",
                                            "application/octet-stream", "application/x-gzip"]):
            return Finding(
                finding_id=self.generate_finding_id("backup", url),
                finding_type=FindingType.EXPOSED_BACKUP.value,
                module=self.name,
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.HIGH.value,
                host=self._extract_host(url),
                url=url,
                title=f"Backup file exposed: {path}",
                description="A backup archive is publicly accessible.",
                evidence={
                    "path": path,
                    "content_type": content_type,
                    "content_length": headers.get("Content-Length", "unknown"),
                },
                remediation="Remove backup files from web-accessible directories.",
                cwe_ids=["CWE-530"],
            )

        # Check for SQL dump content
        if "INSERT INTO" in body or "CREATE TABLE" in body:
            return Finding(
                finding_id=self.generate_finding_id("sqldump", url),
                finding_type=FindingType.EXPOSED_BACKUP.value,
                module=self.name,
                severity=FindingSeverity.CRITICAL.value,
                confidence=FindingConfidence.CONFIRMED.value,
                host=self._extract_host(url),
                url=url,
                title=f"Database dump exposed: {path}",
                description="A SQL database dump is publicly accessible.",
                evidence={
                    "path": path,
                    "contains_sql": True,
                },
                remediation="Remove database dumps from web-accessible directories immediately.",
                cwe_ids=["CWE-530", "CWE-200"],
            )

        return None

    def _analyze_config_response(self, url: str, path: str, body: str, headers: dict) -> Optional[Finding]:
        """Analyze potential config file response."""
        for pattern in SENSITIVE_CONTENT_PATTERNS["config"]:
            if re.search(pattern, body, re.IGNORECASE):
                return Finding(
                    finding_id=self.generate_finding_id("config", url),
                    finding_type=FindingType.EXPOSED_CONFIG.value,
                    module=self.name,
                    severity=FindingSeverity.CRITICAL.value,
                    confidence=FindingConfidence.CONFIRMED.value,
                    host=self._extract_host(url),
                    url=url,
                    title=f"Configuration file exposed: {path}",
                    description="A configuration file containing sensitive data is exposed.",
                    evidence={
                        "path": path,
                        "matched_pattern": pattern,
                    },
                    remediation="Remove config files from web root or block access via server config.",
                    cwe_ids=["CWE-200", "CWE-538"],
                )

        return None

    def _analyze_source_response(self, url: str, path: str, body: str, headers: dict) -> Optional[Finding]:
        """Analyze potential source code exposure."""
        # Git repository check
        if ".git" in path:
            for pattern in SENSITIVE_CONTENT_PATTERNS["git"]:
                if re.search(pattern, body):
                    return Finding(
                        finding_id=self.generate_finding_id("git", url),
                        finding_type=FindingType.EXPOSED_SOURCE.value,
                        module=self.name,
                        severity=FindingSeverity.HIGH.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=self._extract_host(url),
                        url=url,
                        title=f"Git repository exposed: {path}",
                        description="Git repository files are accessible, source code can be recovered.",
                        evidence={
                            "path": path,
                            "matched_pattern": pattern,
                        },
                        remediation="Block access to .git directories in server configuration.",
                        references=["https://github.com/internetwache/GitTools"],
                        cwe_ids=["CWE-527"],
                    )

        # Source code patterns
        for pattern in SENSITIVE_CONTENT_PATTERNS["source"]:
            if re.search(pattern, body):
                return Finding(
                    finding_id=self.generate_finding_id("source", url),
                    finding_type=FindingType.EXPOSED_SOURCE.value,
                    module=self.name,
                    severity=FindingSeverity.MEDIUM.value,
                    confidence=FindingConfidence.HIGH.value,
                    host=self._extract_host(url),
                    url=url,
                    title=f"Source code exposed: {path}",
                    description="Source code file is publicly accessible.",
                    evidence={
                        "path": path,
                        "matched_pattern": pattern,
                    },
                    remediation="Remove source files from web-accessible directories.",
                    cwe_ids=["CWE-540"],
                )

        return None

    def _analyze_debug_response(self, url: str, path: str, body: str, headers: dict) -> Optional[Finding]:
        """Analyze potential debug endpoint response."""
        debug_indicators = [
            r"phpinfo\(\)",
            r"PHP Version",
            r"System.*Linux",
            r"Configuration.*PHP",
            r"Loaded Modules",
            r"stack\s*trace",
            r"debug\s*mode",
            r"DOCUMENT_ROOT",
        ]

        for pattern in debug_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                severity = FindingSeverity.HIGH.value if "phpinfo" in path.lower() else FindingSeverity.MEDIUM.value

                return Finding(
                    finding_id=self.generate_finding_id("debug", url),
                    finding_type=FindingType.EXPOSED_DEBUG.value,
                    module=self.name,
                    severity=severity,
                    confidence=FindingConfidence.CONFIRMED.value,
                    host=self._extract_host(url),
                    url=url,
                    title=f"Debug endpoint exposed: {path}",
                    description="A debug or information disclosure endpoint is accessible.",
                    evidence={
                        "path": path,
                        "matched_pattern": pattern,
                    },
                    remediation="Disable debug endpoints in production environments.",
                    cwe_ids=["CWE-200", "CWE-215"],
                )

        return None

    def _analyze_api_response(self, url: str, path: str, body: str, headers: dict) -> Optional[Finding]:
        """Analyze potential API documentation response."""
        api_indicators = [
            r"swagger",
            r"openapi",
            r'"paths"\s*:',
            r'"info"\s*:\s*\{',
            r"graphql",
            r"__schema",
        ]

        for pattern in api_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                return Finding(
                    finding_id=self.generate_finding_id("api", url),
                    finding_type=FindingType.EXPOSED_DEBUG.value,
                    module=self.name,
                    severity=FindingSeverity.LOW.value,
                    confidence=FindingConfidence.HIGH.value,
                    host=self._extract_host(url),
                    url=url,
                    title=f"API documentation exposed: {path}",
                    description="API documentation is publicly accessible, revealing endpoint structure.",
                    evidence={
                        "path": path,
                        "matched_pattern": pattern,
                    },
                    remediation="Restrict API documentation to authenticated users.",
                    cwe_ids=["CWE-200"],
                )

        return None

    def _create_protected_finding(
        self,
        url: str,
        path: str,
        category: str,
        status: int
    ) -> Optional[Finding]:
        """Create finding for protected but existing resource."""
        # Only report for high-value targets
        if category not in ("admin", "config", "source"):
            return None

        return Finding(
            finding_id=self.generate_finding_id("protected", url),
            finding_type=FindingType.EXPOSED_ADMIN.value,
            module=self.name,
            severity=FindingSeverity.INFO.value,
            confidence=FindingConfidence.MEDIUM.value,
            host=self._extract_host(url),
            url=url,
            title=f"Protected resource exists: {path}",
            description=f"Resource returned HTTP {status}, indicating it exists but is protected.",
            evidence={
                "path": path,
                "status_code": status,
            },
            remediation="Ensure authentication is properly configured.",
        )

    def _create_redirect_finding(
        self,
        url: str,
        path: str,
        category: str,
        location: str
    ) -> Optional[Finding]:
        """Create finding for interesting redirect."""
        return None  # Most redirects are not interesting

    def _is_interesting_redirect(self, path: str, location: str) -> bool:
        """Check if a redirect is interesting."""
        # Redirects to login pages indicate protected resources
        return "login" in location.lower() or "auth" in location.lower()

    def _extract_host(self, url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0]
