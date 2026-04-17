# METADATA
# title: POS Transaction Authorization
# description: Controls who can perform point-of-sale operations including sales, returns, voids, and manager overrides
# related_resources:
#   - ref: https://wiki.acmecorp.internal/retail-ops/pos-security
# authors:
#   - name: Retail Operations Team
package store_ops.pos.authorization

import rego.v1

import data.shared.authentication

# -------------------------------------------------------
# Sale transactions - any active cashier or above
# -------------------------------------------------------
allow_sale if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/pos/sale"
	"pos:sale" in user_claims.permissions
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# Returns - cashiers up to $50, shift leads up to $200,
# managers unlimited
# -------------------------------------------------------
allow_return if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/pos/return"
	"pos:return" in user_claims.permissions
	_at_assigned_store(user_claims)
	_within_return_limit(user_claims)
}

# -------------------------------------------------------
# Void last transaction - shift lead or above only
# -------------------------------------------------------
allow_void if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/pos/void"
	"pos:void" in user_claims.permissions
	user_claims.role in ["shift_lead", "store_manager", "district_manager"]
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# Price override - shift lead or above, max 25% discount
# -------------------------------------------------------
allow_price_override if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/pos/price-override"
	"pos:price_override" in user_claims.permissions
	user_claims.role in ["shift_lead", "store_manager", "district_manager"]
	_at_assigned_store(user_claims)
	_within_discount_limit(user_claims)
}

# -------------------------------------------------------
# Cash drawer open - must have explicit permission
# -------------------------------------------------------
allow_open_drawer if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/pos/open-drawer"
	"pos:open_drawer" in user_claims.permissions
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# End-of-day register close - shift lead or store manager
# -------------------------------------------------------
allow_close_register if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/pos/close-register"
	"pos:close_register" in user_claims.permissions
	user_claims.role in ["shift_lead", "store_manager"]
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# Helper: user is operating at their assigned store
# -------------------------------------------------------
_at_assigned_store(user_claims) if {
	# District managers can access any store
	user_claims.role == "district_manager"
}

_at_assigned_store(user_claims) if {
	# Others must match their assigned store
	user_claims.store_id == input.request.headers["x-store-id"]
}

# -------------------------------------------------------
# Helper: return amount within role limit
# -------------------------------------------------------
_return_limit_for_role := {"cashier": 50, "shift_lead": 200, "store_manager": 999999, "district_manager": 999999}

_within_return_limit(user_claims) if {
	is_number(input.request.body.amount)
	input.request.body.amount >= 0
	limit := _return_limit_for_role[user_claims.role]
	input.request.body.amount <= limit
}

# -------------------------------------------------------
# Helper: discount percentage within role limit
# -------------------------------------------------------
_discount_limit_for_role := {"shift_lead": 15, "store_manager": 25, "district_manager": 50}

_within_discount_limit(user_claims) if {
	is_number(input.request.body.discount_percent)
	input.request.body.discount_percent >= 0
	limit := _discount_limit_for_role[user_claims.role]
	input.request.body.discount_percent <= limit
}
