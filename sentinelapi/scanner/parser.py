import json
import yaml
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import re

from .schemas import Endpoint, EndpointParameter

class OpenAPIParser:
    def __init__(self):
        self.spec = None
        self.base_path = ""
    
    def parse_spec(self, spec_content: str, spec_format: str = "auto") -> Dict[str, Any]:
        """Parse OpenAPI/Swagger spec from JSON or YAML"""
        try:
            if spec_format == "auto":
                # Try JSON first, then YAML
                try:
                    self.spec = json.loads(spec_content)
                except json.JSONDecodeError:
                    self.spec = yaml.safe_load(spec_content)
            elif spec_format == "json":
                self.spec = json.loads(spec_content)
            elif spec_format == "yaml":
                self.spec = yaml.safe_load(spec_content)
            else:
                raise ValueError(f"Unsupported spec format: {spec_format}")
            
            # Extract base path
            self.base_path = self.spec.get("servers", [{}])[0].get("url", "")
            if not self.base_path:
                self.base_path = self.spec.get("basePath", "")
            
            return self.spec
        except Exception as e:
            raise ValueError(f"Failed to parse OpenAPI spec: {str(e)}")
    
    def discover_endpoints(self) -> List[Endpoint]:
        """Discover and normalize endpoints from OpenAPI spec"""
        if not self.spec:
            raise ValueError("No spec parsed. Call parse_spec first.")
        
        endpoints = []
        paths = self.spec.get("paths", {})
        
        for path, path_item in paths.items():
            full_path = urljoin(self.base_path, path) if self.base_path else path
            
            for method, operation in path_item.items():
                if method.lower() in ["get", "post", "put", "delete", "patch", "head", "options"]:
                    endpoint = self._parse_operation(full_path, method.upper(), operation)
                    if endpoint:
                        endpoints.append(endpoint)
        
        return endpoints
    
    def _parse_operation(self, path: str, method: str, operation: Dict[str, Any]) -> Optional[Endpoint]:
        """Parse a single OpenAPI operation"""
        # Skip non-GET methods for core safety (as per requirements)
        if method.upper() != "GET":
            return None
            
        parameters = []
        
        # Path parameters
        for param in operation.get("parameters", []):
            param_schema = {}
            if "schema" in param:
                param_schema = param["schema"]
            elif "type" in param:  # Swagger 2.0
                param_schema = {"type": param["type"]}
            
            endpoint_param = EndpointParameter(
                name=param["name"],
                location=param["in"],
                schema=param_schema,
                required=param.get("required", False)
            )
            parameters.append(endpoint_param)
        
        # Request body parameters (for POST/PUT etc, but we focus on GET)
        if "requestBody" in operation:
            # For simplicity in GET-focused scanner, we'll note body exists but not parse deeply
            pass
        
        # Identify candidate object identifiers in parameters
        candidate_identifiers = self._identify_object_identifiers(parameters, path)
        
        endpoint = Endpoint(
            method=method,
            path=path,
            operation_id=operation.get("operationId"),
            parameters=parameters,
            auth_required=True,  # Conservative assumption
            candidate_identifiers=candidate_identifiers
        )
        
        return endpoint
    
    def _identify_object_identifiers(self, parameters: List[EndpointParameter], path: str) -> List[str]:
        """Identify parameters that likely represent object identifiers"""
        candidates = []
        
        # Common ID parameter names
        id_patterns = [
            r'.*id$', r'.*_id$', r'.*Id$', r'.*ID$',
            r'.*uuid$', r'.*_uuid$', r'.*guid$', r'.*_guid$',
            r'.*key$', r'.*_key$', r'.*Key$', r'.*KEY$'
        ]
        
        for param in parameters:
            param_name = param["name"]
            
            # Check parameter name against patterns
            for pattern in id_patterns:
                if re.match(pattern, param_name, re.IGNORECASE):
                    candidates.append(param_name)
                    break
            
            # Also check path for {param} patterns
            path_param_pattern = rf'\{{{re.escape(param_name)}}}'
            if re.search(path_param_pattern, path):
                if param_name not in candidates:
                    candidates.append(param_name)
        
        return candidates

def load_spec_from_file(file_path: str) -> str:
    """Load spec content from file"""
    with open(file_path, 'r') as f:
        return f.read()

def load_spec_from_url(url: str) -> str:
    """Load spec content from URL (placeholder - would use httpx in real implementation)"""
    # In production, this would use httpx to fetch the URL
    # For now, we'll raise an error to indicate this needs implementation
    raise NotImplementedError("URL loading not implemented in this version - use file upload")