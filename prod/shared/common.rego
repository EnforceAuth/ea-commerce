package shared.common

import rego.v1

# Default deny
default allow := false

# Allow health checks
allow if {
	input.request.http.method == "GET"
	input.request.http.path in ["/health", "/healthz", "/ready", "/status"]
}

# Allow CORS preflight
allow if {
	input.request.http.method == "OPTIONS"
}

# HTTP method to action mapping
method_to_action(method) := action if {
	method_map := {
		"GET": "read",
		"POST": "create",
		"PUT": "update",
		"PATCH": "update",
		"DELETE": "delete",
	}
	action := method_map[method]
}

# Check if user has permission
has_permission(user_claims, permission) if {
	permission in user_claims.permissions
}

# Check if user has any of the listed roles
has_any_role(user_claims, roles) if {
	user_claims.role in roles
}

# Time helpers
current_hour := ((time.now_ns() / 1000000000) / 3600) % 24

within_business_hours if {
	current_hour >= 6
	current_hour <= 22
}
