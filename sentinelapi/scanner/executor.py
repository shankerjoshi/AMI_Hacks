import httpx
import asyncio
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin
import time
import logging
from dataclasses import dataclass

from .schemas import ScanRequest, Endpoint, AuthProfile

logger = logging.getLogger(__name__)

@dataclass
class RequestResult:
    status_code: int
    headers: Dict[str, str]
    body: Any
    duration_ms: float
    error: Optional[str] = None

class SafeRequestExecutor:
    def __init__(self, scan_request: ScanRequest):
        self.scan_request = scan_request
        self.request_count = 0
        self.client = None
    
    async def __aenter__(self):
        limits = httpx.Limits(
            max_connections=self.scan_request.concurrency,
            max_keepalive_connections=self.scan_request.concurrency
        )
        timeout = httpx.Timeout(self.scan_request.timeout_seconds)
        self.client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            follow_redirects=False  # We handle redirects ourselves for safety
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()
    
    def _is_url_allowed(self, url: str) -> bool:
        """Check if URL is within allowlist"""
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False
        
        # Check against allowlist
        for allowed in self.scan_request.allowlist:
            if allowed in hostname:
                return True
        
        # Allow local Docker hostnames
        if hostname in ["localhost", "127.0.0.1", "demo-api", "scanner", "dashboard"]:
            return True
            
        return False
    
    def _check_request_budget(self) -> bool:
        """Check if we have request budget remaining"""
        if self.request_count >= self.scan_request.request_budget:
            return False
        return True
    
    def _redact_credentials(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive credentials from headers for logging"""
        redacted = {}
        for key, value in headers.items():
            if key.lower() in ["authorization", "cookie", "x-api-key", "api-key"]:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        return redacted
    
    def _build_auth_headers(self, auth_profile: AuthProfile) -> Dict[str, str]:
        """Build authentication headers from profile"""
        headers = {}
        if auth_profile.token:
            headers[auth_profile.header] = f"{auth_profile.prefix} {auth_profile.token}"
        return headers
    
    async def execute_request(
        self, 
        endpoint: Endpoint, 
        auth_profile: AuthProfile,
        path_params: Dict[str, str] = None,
        query_params: Dict[str, str] = None,
        body: Any = None
    ) -> RequestResult:
        """Execute a single safe request with all safety controls"""
        
        if not self._check_request_budget():
            return RequestResult(
                status_code=0,
                headers={},
                body=None,
                duration_ms=0,
                error="Request budget exhausted"
            )
        
        # Build URL
        url = urljoin(self.scan_request.base_url, endpoint.path)
        
        # Apply path parameters
        if path_params:
            for key, value in path_params.items():
                url = url.replace(f"{{{key}}}", value)
        
        # Validate URL is allowed
        if not self._is_url_allowed(url):
            return RequestResult(
                status_code=0,
                headers={},
                body=None,
                duration_ms=0,
                error=f"URL not in allowlist: {url}"
            )
        
        # Build headers
        headers = self._build_auth_headers(auth_profile)
        headers["User-Agent"] = "SentinelAPI-Scanner/1.0"
        
        # Build query parameters
        params = query_params or {}
        
        start_time = time.time()
        
        try:
            # For safety, we only do GET requests in core scan
            if endpoint.method.upper() != "GET":
                return RequestResult(
                    status_code=0,
                    headers={},
                    body=None,
                    duration_ms=0,
                    error=f"Method {endpoint.method} not allowed in core scan"
                )
            
            response = await self.client.get(
                url,
                headers=headers,
                params=params,
                timeout=self.scan_request.timeout_seconds
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Parse response body
            try:
                body = response.json()
            except:
                body = response.text
            
            self.request_count += 1
            
            return RequestResult(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body,
                duration_ms=duration_ms
            )
            
        except httpx.TimeoutException:
            duration_ms = (time.time() - start_time) * 1000
            return RequestResult(
                status_code=0,
                headers={},
                body=None,
                duration_ms=duration_ms,
                error=f"Request timeout after {self.scan_request.timeout_seconds}s"
            )
        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            return RequestResult(
                status_code=0,
                headers={},
                body=None,
                duration_ms=duration_ms,
                error=f"Request error: {str(e)}"
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return RequestResult(
                status_code=0,
                headers={},
                body=None,
                duration_ms=duration_ms,
                error=f"Unexpected error: {str(e)}"
            )
    
    def get_redacted_request_log(self, endpoint: Endpoint, auth_profile: AuthProfile, 
                                 path_params: Dict = None, query_params: Dict = None) -> Dict[str, Any]:
        """Generate a redacted request log for evidence"""
        url = urljoin(self.scan_request.base_url, endpoint.path)
        
        if path_params:
            for key, value in path_params.items():
                url = url.replace(f"{{{key}}}", value)
        
        headers = self._build_auth_headers(auth_profile)
        redacted_headers = self._redact_credentials(headers)
        
        return {
            "method": endpoint.method,
            "url": url,
            "headers": redacted_headers,
            "params": query_params or {},
            "auth_profile": auth_profile.name  # Just the name, not the token
        }