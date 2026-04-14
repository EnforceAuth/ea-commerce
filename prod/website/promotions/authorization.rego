# METADATA
# title: Promotions Engine Authorization
# description: Controls who can create, approve, and publish promotional campaigns, flash sales, and discount rules
# authors:
#   - name: Merchandising Engineering
package website.promotions.authorization

import rego.v1

import data.shared.authentication

# -------------------------------------------------------
# View active promotions - public
# -------------------------------------------------------
allow_view_promotions if {
	input.request.http.method == "GET"
	input.request.http.path == "/promotions/active"
}

# -------------------------------------------------------
# Create promotion draft - merchandiser or above
# -------------------------------------------------------
allow_create_promotion if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/promotions"
	"promotions:create" in user_claims.permissions
	user_claims.role in ["merchandiser", "marketing_manager", "platform_admin"]
}

# -------------------------------------------------------
# Approve promotion (move from draft to scheduled)
# Must be different person than creator (four-eyes principle)
# -------------------------------------------------------
allow_approve_promotion if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	startswith(input.request.http.path, "/promotions/")
	contains(input.request.http.path, "/approve")
	"promotions:approve" in user_claims.permissions
	user_claims.role in ["marketing_manager", "platform_admin"]

	# Four-eyes: approver must not be the creator
	user_claims.sub != input.request.body.created_by
}

# -------------------------------------------------------
# Publish promotion (make live immediately)
# -------------------------------------------------------
allow_publish_promotion if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	startswith(input.request.http.path, "/promotions/")
	contains(input.request.http.path, "/publish")
	"promotions:publish" in user_claims.permissions
	user_claims.role in ["marketing_manager", "platform_admin"]
}

# -------------------------------------------------------
# Kill switch - immediately disable a running promotion
# -------------------------------------------------------
allow_kill_promotion if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "DELETE"
	startswith(input.request.http.path, "/promotions/")
	"promotions:kill" in user_claims.permissions
	user_claims.role in ["marketing_manager", "platform_admin"]
}

# -------------------------------------------------------
# Create flash sale (time-boxed, higher discount ceiling)
# Requires platform_admin - flash sales can impact margin
# -------------------------------------------------------
allow_create_flash_sale if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/promotions/flash-sale"
	"promotions:flash_sale" in user_claims.permissions
	user_claims.role == "platform_admin"

	# PROD: flash sales capped at 40% to protect margins
	input.request.body.max_discount_percent <= 40
}
