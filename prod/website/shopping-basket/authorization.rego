# METADATA
# title: Shopping Basket Authorization
# description: Controls access to shopping cart operations — add/remove items, apply coupons, checkout
# authors:
#   - name: Website Engineering
package website.shopping_basket.authorization

import rego.v1

import data.shared.authentication

# -------------------------------------------------------
# View own basket - any authenticated customer
# -------------------------------------------------------
allow_view_basket if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/basket"
	"basket:read" in user_claims.permissions
}

# -------------------------------------------------------
# Add / remove items
# -------------------------------------------------------
allow_modify_basket if {
	user_claims := authentication.authenticated_claims
	input.request.http.method in ["POST", "DELETE"]
	startswith(input.request.http.path, "/basket/items")
	"basket:write" in user_claims.permissions
}

# -------------------------------------------------------
# Apply coupon code
# -------------------------------------------------------
allow_apply_coupon if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/basket/coupon"
	"basket:write" in user_claims.permissions

	# Max one coupon per basket
	input.request.body.coupon_code != ""
}

# -------------------------------------------------------
# Apply employee discount (store employees get 20% off online)
# -------------------------------------------------------
allow_employee_discount if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/basket/employee-discount"
	"basket:employee_discount" in user_claims.permissions
	user_claims.department == "store_ops"
}

# -------------------------------------------------------
# Checkout / submit order
# -------------------------------------------------------
allow_checkout if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/basket/checkout"
	"basket:checkout" in user_claims.permissions
}
