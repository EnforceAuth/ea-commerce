# METADATA
# title: Website API Authorization
# description: >-
#   Controls access to the e-commerce REST API — product catalog,
#   orders, customer profiles, and admin operations
# authors:
#   - name: Website Engineering
package website.api.authorization

import rego.v1

import data.shared.authentication

# -------------------------------------------------------
# Public endpoints - no auth required
# -------------------------------------------------------
allow_public if {
	input.request.http.method == "GET"
	input.request.http.path in [
		"/api/products",
		"/api/categories",
		"/api/store-locations",
	]
}

allow_public_product if {
	input.request.http.method == "GET"
	startswith(input.request.http.path, "/api/products/")
}

# -------------------------------------------------------
# Customer: view own orders
# -------------------------------------------------------
allow_view_own_orders if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/api/orders/mine"
	"orders:read_own" in user_claims.permissions
}

# -------------------------------------------------------
# Customer: place order
# -------------------------------------------------------
allow_place_order if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/api/orders"
	"orders:create" in user_claims.permissions
}

# -------------------------------------------------------
# Customer: view / update own profile
# -------------------------------------------------------
allow_view_profile if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/api/profile"
	"profile:read" in user_claims.permissions
}

allow_update_profile if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "PUT"
	input.request.http.path == "/api/profile"
	"profile:update" in user_claims.permissions
}

# -------------------------------------------------------
# Admin: manage products
# -------------------------------------------------------
allow_admin_create_product if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/api/admin/products"
	"products:create" in user_claims.permissions
	user_claims.role in ["merchandiser", "catalog_admin", "platform_admin"]
}

allow_admin_update_product if {
	user_claims := authentication.authenticated_claims
	input.request.http.method in ["PUT", "PATCH"]
	startswith(input.request.http.path, "/api/admin/products/")
	"products:update" in user_claims.permissions
	user_claims.role in ["merchandiser", "catalog_admin", "platform_admin"]
}

# -------------------------------------------------------
# Admin: view all orders (customer support)
# -------------------------------------------------------
allow_admin_view_orders if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/api/admin/orders"
	"orders:read_all" in user_claims.permissions
	user_claims.role in ["cs_agent", "cs_lead", "platform_admin"]
}

# -------------------------------------------------------
# Admin: issue refund
# -------------------------------------------------------
allow_admin_refund if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	startswith(input.request.http.path, "/api/admin/orders/")
	contains(input.request.http.path, "/refund")
	"orders:refund" in user_claims.permissions
	user_claims.role in ["cs_lead", "platform_admin"]
}
