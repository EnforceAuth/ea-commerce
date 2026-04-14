package shared.authentication

import rego.v1

# Extract bearer token from authorization header
extract_token := token if {
	auth_header := input.request.http.headers.authorization
	startswith(auth_header, "Bearer ")
	token := substring(auth_header, 7, -1)
}

# Validate token is present and non-empty
valid_token(token) if {
	token != ""
	token != null
}

# Extract claims from token (mock - production uses JWT validation)
claims(token) := user_claims if {
	users := data.users
	some username, user in users
	user.token == token

	user_claims := {
		"sub": username,
		"role": user.role,
		"permissions": user.permissions,
		"department": user.department,
		"active": user.active,
		"exp": user.exp,
		"store_id": object.get(user, "store_id", null),
	}
}

# Check if user is active
user_active(user_claims) if {
	user_claims.active == true
}

# Helper to get authenticated user claims
authenticated_claims := user_claims if {
	token := extract_token
	valid_token(token)
	user_claims := claims(token)
	user_active(user_claims)
}
