# METADATA
# title: Cyber Monday Rate Limiter
# description: >-
#   Traffic-shaping policies for high-volume sale events.
#   Enforces per-customer request ceilings, bot-detection signals,
#   and tiered checkout queue priority.
# authors:
#   - name: Platform Reliability Engineering
package website.cyber_monday_rate_limiter.authorization

import rego.v1

import data.shared.authentication

# -------------------------------------------------------
# Per-customer request rate check
# Request metadata carries x-ratelimit-remaining from edge
# -------------------------------------------------------
allow_request if {
	_not_rate_limited
	_not_bot
}

# Authenticated users get higher limits
allow_authenticated_request if {
	user_claims := authentication.authenticated_claims
	_not_rate_limited
	_not_bot

	# Loyalty-tier customers get priority during events
	_priority_tier(user_claims)
}

# -------------------------------------------------------
# Checkout queue - tiered by loyalty status
# -------------------------------------------------------
allow_checkout_during_event if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/basket/checkout"
	"basket:checkout" in user_claims.permissions

	# During Cyber Monday, only loyalty+ customers can checkout
	# when queue depth exceeds threshold
	_checkout_allowed(user_claims)
}

# -------------------------------------------------------
# Admin: toggle event mode on/off
# -------------------------------------------------------
allow_toggle_event_mode if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path == "/admin/event-mode"
	user_claims.role == "platform_admin"
	"admin:event_mode" in user_claims.permissions
}

# -------------------------------------------------------
# Admin: adjust rate limits in real-time
# -------------------------------------------------------
allow_adjust_limits if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "PUT"
	input.request.http.path == "/admin/rate-limits"
	user_claims.role == "platform_admin"
	"admin:rate_limits" in user_claims.permissions
}

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
_not_rate_limited if {
	remaining := to_number(input.request.http.headers["x-ratelimit-remaining"])
	remaining > 0
}

_not_bot if {
	score := to_number(input.request.http.headers["x-bot-score"])
	score < 80
}

_priority_tier(user_claims) if {
	user_claims.role in ["loyalty_gold", "loyalty_platinum", "platform_admin"]
}

_priority_tier(user_claims) if {
	# Standard customers also allowed when not at peak
	not _at_peak_load
}

_at_peak_load if {
	queue_depth := to_number(input.request.http.headers["x-queue-depth"])
	queue_depth > 10000
}

_checkout_allowed(user_claims) if {
	# Loyalty customers always allowed
	user_claims.role in ["loyalty_gold", "loyalty_platinum"]
}

_checkout_allowed(user_claims) if {
	# Standard customers allowed when queue is manageable
	not _at_peak_load
}
