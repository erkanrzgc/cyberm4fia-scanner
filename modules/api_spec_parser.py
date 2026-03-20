"""
cyberm4fia-scanner – OpenAPI / Swagger spec parsing & endpoint extraction.
Extracted from api_scanner.py to keep the scanning logic separate.
"""

"""
cyberm4fia-scanner - API Security Scanner
Tests REST/GraphQL endpoints for OWASP API Top 10 vulnerabilities
"""

import json  # noqa: E402
from urllib.parse import urlencode, urljoin, urlparse  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is optional at runtime
    yaml = None

from utils.colors import log_success, log_warning  # noqa: E402
from utils.request import smart_request  # noqa: E402
from utils.request import ScanExceptions  # noqa: E402

# ─────────────────────────────────────────────────────
# Common API paths to discover
# ─────────────────────────────────────────────────────
API_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/graphql",
    "/graphiql",
    "/playground",
    "/api-docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi/v3/api-docs",
    "/v1",
    "/v2",
    "/v3",
    "/.well-known/openid-configuration",
    "/api/health",
    "/api/status",
    "/api/info",
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/test",
    "/api/docs",
    "/api/graphql",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
]

OPENAPI_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api-docs",
    "/v3/api-docs",
    "/openapi/v3/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
]

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

# IDOR test patterns
IDOR_PATTERNS = [
    (r"/api/v\d+/users/(\d+)", "user_id"),
    (r"/api/v\d+/orders/(\d+)", "order_id"),
    (r"/api/v\d+/accounts/(\d+)", "account_id"),
    (r"/api/v\d+/profiles/(\d+)", "profile_id"),
    (r"/users/(\d+)", "user_id"),
    (r"/orders/(\d+)", "order_id"),
]

def _is_openapi_spec(doc):
    """Return True if the parsed document looks like OpenAPI/Swagger."""
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("paths"), dict)
        and ("openapi" in doc or "swagger" in doc)
    )

def _parse_api_spec_text(text):
    """Parse OpenAPI/Swagger JSON or YAML text."""
    if not text or not text.strip():
        return None

    parsers = [json.loads]
    if yaml is not None:
        parsers.append(yaml.safe_load)

    for parser in parsers:
        try:
            doc = parser(text)
        except ScanExceptions:
            continue
        if _is_openapi_spec(doc):
            return doc

    return None

def _resolve_ref(spec, value):
    """Resolve a local JSON pointer reference from an OpenAPI spec."""
    if not isinstance(value, dict) or "$ref" not in value:
        return value

    ref = value.get("$ref", "")
    if not ref.startswith("#/"):
        return value

    current = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return value
        current = current[part]

    if current is value:
        return value
    return _resolve_ref(spec, current)

def _first_example_value(examples, spec):
    """Extract the first usable example value from an examples object."""
    if not isinstance(examples, dict):
        return None

    for example in examples.values():
        resolved = _resolve_ref(spec, example)
        if isinstance(resolved, dict) and "value" in resolved:
            return resolved["value"]
        if resolved not in (None, {}):
            return resolved

    return None

def _guess_schema_value(spec, schema, name="param"):
    """Generate a simple sample value for a schema."""
    schema = _resolve_ref(spec, schema or {})

    if not isinstance(schema, dict):
        return "test"

    if "allOf" in schema:
        merged = {}
        for sub_schema in schema.get("allOf", []):
            sample = _guess_schema_value(spec, sub_schema, name)
            if isinstance(sample, dict):
                merged.update(sample)
        if merged:
            return merged

    for key in ("oneOf", "anyOf"):
        variants = schema.get(key)
        if isinstance(variants, list) and variants:
            return _guess_schema_value(spec, variants[0], name)

    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]

    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return enum_values[0]

    fmt = str(schema.get("format", "")).lower()
    schema_type = str(schema.get("type", "")).lower()
    lower_name = str(name).lower()

    if "uuid" in fmt or "uuid" in lower_name:
        return "00000000-0000-4000-8000-000000000000"
    if "email" in fmt or "email" in lower_name:
        return "test@example.com"
    if schema_type in {"integer", "number"} or lower_name == "id" or lower_name.endswith("_id"):
        return 1
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        item_schema = schema.get("items", {})
        return [_guess_schema_value(spec, item_schema, name)]
    if schema_type == "object":
        properties = schema.get("properties", {})
        sample = {}
        for prop_name, prop_schema in properties.items():
            sample[prop_name] = _guess_schema_value(spec, prop_schema, prop_name)
        return sample

    return "test"

def _guess_parameter_value(spec, parameter):
    """Infer a safe sample value for a parameter."""
    resolved = _resolve_ref(spec, parameter)
    if not isinstance(resolved, dict):
        return "test"

    if "example" in resolved:
        return resolved["example"]

    example_value = _first_example_value(resolved.get("examples"), spec)
    if example_value is not None:
        return example_value

    schema = _resolve_ref(spec, resolved.get("schema", {}))
    return _guess_schema_value(spec, schema, resolved.get("name", "param"))

def _pick_media_type(content):
    """Pick the best media type from an OpenAPI requestBody content map."""
    if not isinstance(content, dict) or not content:
        return "", {}

    preferred = [
        "application/json",
        "application/*+json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    ]

    for media_type in preferred:
        if media_type in content:
            return media_type, content[media_type]

    for media_type, media_obj in content.items():
        if media_type.endswith("+json"):
            return media_type, media_obj

    media_type = next(iter(content))
    return media_type, content[media_type]

def _extract_request_body(spec, operation):
    """Generate a sample request body from an OpenAPI operation."""
    resolved_operation = _resolve_ref(spec, operation)
    if not isinstance(resolved_operation, dict):
        return None, ""

    request_body = _resolve_ref(spec, resolved_operation.get("requestBody", {}))
    if not isinstance(request_body, dict):
        return None, ""

    media_type, media_obj = _pick_media_type(request_body.get("content", {}))
    if not media_type or not isinstance(media_obj, dict):
        return None, ""

    if "example" in media_obj:
        return media_obj["example"], media_type

    example_value = _first_example_value(media_obj.get("examples"), spec)
    if example_value is not None:
        return example_value, media_type

    schema = media_obj.get("schema", {})
    sample = _guess_schema_value(spec, schema, "body")
    return sample, media_type

def _extract_auth_schemes(spec, operation):
    """Extract auth requirements from spec-level and operation-level security."""
    resolved_operation = _resolve_ref(spec, operation)
    if not isinstance(resolved_operation, dict):
        return []

    if "security" in resolved_operation:
        security_requirements = resolved_operation.get("security") or []
    else:
        security_requirements = spec.get("security") or []

    if not security_requirements:
        return []

    security_schemes = (
        spec.get("components", {}).get("securitySchemes", {})
        if isinstance(spec.get("components"), dict)
        else {}
    )

    extracted = []
    seen = set()

    for requirement in security_requirements:
        if not isinstance(requirement, dict):
            continue
        for scheme_name, scopes in requirement.items():
            scheme_obj = _resolve_ref(spec, security_schemes.get(scheme_name, {}))
            if not isinstance(scheme_obj, dict):
                continue

            item = {
                "id": scheme_name,
                "type": scheme_obj.get("type", ""),
                "scheme": scheme_obj.get("scheme", ""),
                "in": scheme_obj.get("in", ""),
                "name": scheme_obj.get("name", ""),
                "bearer_format": scheme_obj.get("bearerFormat", ""),
                "description": scheme_obj.get("description", ""),
                "scopes": scopes or [],
                "open_id_connect_url": scheme_obj.get("openIdConnectUrl", ""),
            }

            key = (
                item["id"],
                item["type"],
                item["scheme"],
                item["in"],
                item["name"],
            )
            if key in seen:
                continue
            seen.add(key)
            extracted.append(item)

    return extracted

def _describe_auth_scheme(auth_scheme):
    """Create a human-readable description for an auth scheme."""
    scheme_type = auth_scheme.get("type", "").lower()
    scheme_name = auth_scheme.get("id", "auth")

    if scheme_type == "http":
        scheme = auth_scheme.get("scheme", "http").upper()
        if auth_scheme.get("bearer_format"):
            scheme += f" ({auth_scheme['bearer_format']})"
        return f"{scheme_name}: HTTP {scheme}"

    if scheme_type == "apikey":
        location = auth_scheme.get("in", "header")
        name = auth_scheme.get("name", "api_key")
        return f"{scheme_name}: API key via {location} '{name}'"

    if scheme_type == "oauth2":
        scopes = ", ".join(auth_scheme.get("scopes", [])) or "no scopes declared"
        return f"{scheme_name}: OAuth2 ({scopes})"

    if scheme_type == "openidconnect":
        return f"{scheme_name}: OpenID Connect"

    return f"{scheme_name}: {auth_scheme.get('type', 'unknown auth')}"

def _build_auth_placeholders(auth_schemes):
    """Build request placeholder material from OpenAPI auth schemes."""
    placeholders = {"headers": {}, "cookies": {}, "query": {}}

    for auth_scheme in auth_schemes or []:
        scheme_type = str(auth_scheme.get("type", "")).lower()
        scheme = str(auth_scheme.get("scheme", "")).lower()
        location = str(auth_scheme.get("in", "")).lower()
        name = auth_scheme.get("name") or auth_scheme.get("id") or "auth"

        if scheme_type == "http":
            if scheme == "bearer":
                token_name = auth_scheme.get("bearer_format") or "TOKEN"
                placeholders["headers"]["Authorization"] = (
                    f"Bearer <{str(token_name).upper()}_TOKEN>"
                )
            elif scheme == "basic":
                placeholders["headers"]["Authorization"] = (
                    "Basic <BASE64_USERNAME_PASSWORD>"
                )
            else:
                placeholders["headers"]["Authorization"] = (
                    f"{scheme.upper()} <TOKEN>"
                )
            continue

        if scheme_type == "apikey":
            placeholder_value = f"<{str(name).upper().replace('-', '_')}>"
            if location == "cookie":
                placeholders["cookies"][name] = placeholder_value
            elif location == "query":
                placeholders["query"][name] = placeholder_value
            else:
                placeholders["headers"][name] = placeholder_value
            continue

        if scheme_type == "oauth2":
            placeholders["headers"]["Authorization"] = "Bearer <OAUTH_ACCESS_TOKEN>"
            continue

        if scheme_type == "openidconnect":
            placeholders["headers"]["Authorization"] = "Bearer <OPENID_ACCESS_TOKEN>"

    return {k: v for k, v in placeholders.items() if v}

def _flatten_form_payload(value, prefix=""):
    """Flatten nested dict/list payloads for form-style encodings."""
    items = []

    if isinstance(value, dict):
        for key, sub_value in value.items():
            new_prefix = f"{prefix}[{key}]" if prefix else str(key)
            items.extend(_flatten_form_payload(sub_value, new_prefix))
        return items

    if isinstance(value, list):
        for sub_value in value:
            new_prefix = f"{prefix}[]"
            items.extend(_flatten_form_payload(sub_value, new_prefix))
        return items

    items.append((prefix, value))
    return items

def _merge_request_body(sample_body, injection_fields):
    """Blend a spec-derived body sample with mass-assignment test fields."""
    if isinstance(sample_body, dict):
        merged = dict(sample_body)
        merged.update(injection_fields)
        return merged
    return dict(injection_fields)

def _build_request_body_kwargs(target, injection_fields):
    """Choose request kwargs based on spec-derived request body metadata."""
    if not isinstance(target, dict):
        return {"json": injection_fields}

    sample_body = target.get("request_body")
    content_type = str(target.get("request_body_content_type", "")).lower()
    payload = _merge_request_body(sample_body, injection_fields)

    if "application/x-www-form-urlencoded" in content_type:
        return {
            "data": _flatten_form_payload(payload),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        }
    if "multipart/form-data" in content_type:
        return {
            "data": _flatten_form_payload(payload),
            "headers": {"Content-Type": "multipart/form-data"},
        }
    if content_type.startswith("text/"):
        return {
            "data": json.dumps(payload),
            "headers": {"Content-Type": content_type},
        }
    return {"json": payload}

def collect_auth_findings(api_endpoints):
    """Turn detected auth schemes into informational findings."""
    findings = []
    seen = set()

    for endpoint in api_endpoints:
        if not isinstance(endpoint, dict):
            continue

        for auth_scheme in endpoint.get("auth_schemes", []):
            description = _describe_auth_scheme(auth_scheme)
            placeholders = endpoint.get("auth_placeholders", {})
            key = (
                auth_scheme.get("id"),
                auth_scheme.get("type"),
                auth_scheme.get("name"),
            )
            if key in seen:
                continue
            seen.add(key)
            placeholder_parts = []
            if placeholders.get("headers"):
                placeholder_parts.append(f"headers={placeholders['headers']}")
            if placeholders.get("cookies"):
                placeholder_parts.append(f"cookies={placeholders['cookies']}")
            if placeholders.get("query"):
                placeholder_parts.append(f"query={placeholders['query']}")
            placeholder_text = (
                f" Suggested placeholders: {'; '.join(placeholder_parts)}."
                if placeholder_parts
                else ""
            )
            findings.append(
                {
                    "type": "API_Auth_Scheme",
                    "severity": "INFO",
                    "url": endpoint.get("url", ""),
                    "param": auth_scheme.get("name") or auth_scheme.get("id", ""),
                    "evidence": description + placeholder_text,
                    "description": (
                        f"API spec declares authentication requirement: "
                        f"{description}.{placeholder_text}"
                    ),
                    "source": endpoint.get("source"),
                    "auth_scheme": auth_scheme,
                    "auth_placeholders": placeholders or None,
                }
            )

    return findings

def _render_path_template(spec, raw_path, parameters):
    """Replace path template variables with sample values."""
    rendered = raw_path
    query_params = {}

    for parameter in parameters:
        resolved = _resolve_ref(spec, parameter)
        if not isinstance(resolved, dict):
            continue

        name = resolved.get("name")
        location = resolved.get("in")
        if not name or not location:
            continue

        value = _guess_parameter_value(spec, resolved)
        if location == "path":
            rendered = rendered.replace("{" + name + "}", str(value))
        elif location == "query":
            query_params[name] = value

    return rendered, query_params

def _normalize_server_url(base_url, server_url):
    """Resolve OpenAPI server URLs against the scanned target."""
    if not server_url:
        return base_url

    if server_url.startswith(("http://", "https://")):
        return server_url

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return urljoin(origin, server_url)

def _build_endpoint_url(base_url, server_url, rendered_path):
    """Construct a request URL from base server URL and OpenAPI path."""
    server_base = _normalize_server_url(base_url, server_url).rstrip("/") + "/"
    return urljoin(server_base, rendered_path.lstrip("/"))

def load_api_spec(spec_path):
    """Load a local OpenAPI/Swagger JSON or YAML file."""
    if not spec_path:
        return None

    try:
        with open(spec_path, "r", encoding="utf-8") as handle:
            spec = _parse_api_spec_text(handle.read())
    except OSError as exc:
        log_warning(f"Could not read API spec '{spec_path}': {exc}")
        return None

    if not spec:
        log_warning(f"File is not a valid OpenAPI/Swagger spec: {spec_path}")
        return None

    log_success(f"Loaded API spec: {spec_path}")
    return spec

def fetch_openapi_spec(url, delay=0):
    """Try to fetch an OpenAPI/Swagger document from common endpoints."""
    for path in OPENAPI_SPEC_PATHS:
        try:
            spec_url = urljoin(url, path)
            resp = smart_request("get", spec_url, delay=delay, timeout=5)
            if resp.status_code not in (200, 401, 403):
                continue

            spec = _parse_api_spec_text(resp.text)
            if spec:
                log_success(f"OpenAPI spec discovered: {spec_url}")
                return spec, spec_url
        except ScanExceptions:
            continue

    return None, None

def extract_openapi_endpoints(spec, base_url, source="openapi"):
    """Extract concrete endpoint URLs and methods from an OpenAPI spec."""
    if not _is_openapi_spec(spec):
        return []

    endpoints = []
    servers = spec.get("servers") or [{"url": base_url}]

    for raw_path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        path_parameters = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue

            resolved_operation = _resolve_ref(spec, operation)
            if not isinstance(resolved_operation, dict):
                continue

            operation_parameters = resolved_operation.get("parameters", [])
            parameters = list(path_parameters) + list(operation_parameters)
            rendered_path, query_params = _render_path_template(
                spec, raw_path, parameters
            )
            request_body, request_body_content_type = _extract_request_body(
                spec, resolved_operation
            )
            auth_schemes = _extract_auth_schemes(spec, resolved_operation)
            auth_placeholders = _build_auth_placeholders(auth_schemes)

            for server in servers:
                server_obj = _resolve_ref(spec, server)
                server_url = ""
                if isinstance(server_obj, dict):
                    server_url = server_obj.get("url", "")

                endpoint_url = _build_endpoint_url(base_url, server_url, rendered_path)
                if query_params:
                    endpoint_url = (
                        f"{endpoint_url}?{urlencode(query_params, doseq=True)}"
                    )
                endpoints.append(
                    {
                        "url": endpoint_url,
                        "method": method.upper(),
                        "status": "spec",
                        "content_type": "openapi/spec",
                        "is_api": True,
                        "source": source,
                        "path": raw_path,
                        "query_params": query_params,
                        "operation_id": resolved_operation.get("operationId", ""),
                        "request_body": request_body,
                        "request_body_content_type": request_body_content_type,
                        "auth_schemes": auth_schemes,
                        "auth_placeholders": auth_placeholders,
                    }
                )

    return endpoints

