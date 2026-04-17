package website.cyber_monday_rate_limiter.authorization_test

import rego.v1

import data.website.cyber_monday_rate_limiter.authorization

mock_users := {
	"standard_shopper": {
		"token": "token-standard",
		"role": "customer",
		"permissions": ["basket:read", "basket:write", "basket:checkout"],
		"department": "customers",
		"active": true,
		"exp": 9999999999,
	},
	"gold_member": {
		"token": "token-gold",
		"role": "loyalty_gold",
		"permissions": ["basket:read", "basket:write", "basket:checkout"],
		"department": "customers",
		"active": true,
		"exp": 9999999999,
	},
	"plat_admin": {
		"token": "token-platadmin",
		"role": "platform_admin",
		"permissions": ["admin:event_mode", "admin:rate_limits", "basket:checkout"],
		"department": "engineering",
		"active": true,
		"exp": 9999999999,
	},
}

# =============================================================================
# RATE LIMIT TESTS
# =============================================================================

test_allow_request_with_remaining_quota if {
	authorization.allow_request with input as {"request": {"http": {
		"method": "GET",
		"path": "/api/products",
		"headers": {
			"x-ratelimit-remaining": "50",
			"x-bot-score": "10",
		},
	}}}
}

test_deny_request_rate_limited if {
	not authorization.allow_request with input as {"request": {"http": {
		"method": "GET",
		"path": "/api/products",
		"headers": {
			"x-ratelimit-remaining": "0",
			"x-bot-score": "10",
		},
	}}}
}

test_deny_bot_traffic if {
	not authorization.allow_request with input as {"request": {"http": {
		"method": "GET",
		"path": "/api/products",
		"headers": {
			"x-ratelimit-remaining": "50",
			"x-bot-score": "95",
		},
	}}}
}

# =============================================================================
# CHECKOUT DURING EVENT TESTS
# =============================================================================

test_gold_member_checkout_at_peak if {
	authorization.allow_checkout_during_event with input as {"request": {"http": {
		"method": "POST",
		"path": "/basket/checkout",
		"headers": {
			"authorization": "Bearer token-gold",
			"x-queue-depth": "15000",
		},
	}}}
		with data.users as mock_users
}

test_standard_customer_denied_at_peak if {
	not authorization.allow_checkout_during_event with input as {"request": {"http": {
		"method": "POST",
		"path": "/basket/checkout",
		"headers": {
			"authorization": "Bearer token-standard",
			"x-queue-depth": "15000",
		},
	}}}
		with data.users as mock_users
}

test_standard_customer_allowed_off_peak if {
	authorization.allow_checkout_during_event with input as {"request": {"http": {
		"method": "POST",
		"path": "/basket/checkout",
		"headers": {
			"authorization": "Bearer token-standard",
			"x-queue-depth": "500",
		},
	}}}
		with data.users as mock_users
}

# =============================================================================
# ADMIN TESTS
# =============================================================================

test_admin_toggle_event_mode if {
	authorization.allow_toggle_event_mode with input as {"request": {"http": {
		"method": "POST",
		"path": "/admin/event-mode",
		"headers": {"authorization": "Bearer token-platadmin"},
	}}}
		with data.users as mock_users
}

test_non_admin_toggle_denied if {
	not authorization.allow_toggle_event_mode with input as {"request": {"http": {
		"method": "POST",
		"path": "/admin/event-mode",
		"headers": {"authorization": "Bearer token-gold"},
	}}}
		with data.users as mock_users
}

test_admin_adjust_limits if {
	authorization.allow_adjust_limits with input as {"request": {"http": {
		"method": "PUT",
		"path": "/admin/rate-limits",
		"headers": {"authorization": "Bearer token-platadmin"},
	}}}
		with data.users as mock_users
}
