package website.api.authorization_test

import rego.v1

import data.website.api.authorization

mock_users := {
	"shopper1": {
		"token": "token-shopper",
		"role": "customer",
		"permissions": ["orders:read_own", "orders:create", "profile:read", "profile:update"],
		"department": "customers",
		"active": true,
		"exp": 9999999999,
	},
	"cs_agent1": {
		"token": "token-csagent",
		"role": "cs_agent",
		"permissions": ["orders:read_all", "profile:read"],
		"department": "customer_support",
		"active": true,
		"exp": 9999999999,
	},
	"cs_lead1": {
		"token": "token-cslead",
		"role": "cs_lead",
		"permissions": ["orders:read_all", "orders:refund", "profile:read"],
		"department": "customer_support",
		"active": true,
		"exp": 9999999999,
	},
	"merch1": {
		"token": "token-merch",
		"role": "merchandiser",
		"permissions": ["products:create", "products:update"],
		"department": "merchandising",
		"active": true,
		"exp": 9999999999,
	},
	"admin1": {
		"token": "token-admin",
		"role": "platform_admin",
		"permissions": ["products:create", "products:update", "orders:read_all", "orders:refund", "profile:read"],
		"department": "engineering",
		"active": true,
		"exp": 9999999999,
	},
}

# =============================================================================
# PUBLIC ENDPOINT TESTS
# =============================================================================

test_anyone_browse_products if {
	authorization.allow_public with input as {
		"request": {"http": {"method": "GET", "path": "/api/products"}},
	}
}

test_anyone_view_single_product if {
	authorization.allow_public_product with input as {
		"request": {"http": {"method": "GET", "path": "/api/products/SKU-12345"}},
	}
}

test_anyone_browse_categories if {
	authorization.allow_public with input as {
		"request": {"http": {"method": "GET", "path": "/api/categories"}},
	}
}

# =============================================================================
# CUSTOMER ORDER TESTS
# =============================================================================

test_customer_view_own_orders if {
	authorization.allow_view_own_orders with input as {
		"request": {
			"http": {
				"method": "GET",
				"path": "/api/orders/mine",
				"headers": {"authorization": "Bearer token-shopper"},
			},
		}
	} with data.users as mock_users
}

test_customer_place_order if {
	authorization.allow_place_order with input as {
		"request": {
			"http": {
				"method": "POST",
				"path": "/api/orders",
				"headers": {"authorization": "Bearer token-shopper"},
			},
		}
	} with data.users as mock_users
}

test_customer_cannot_view_all_orders if {
	not authorization.allow_admin_view_orders with input as {
		"request": {
			"http": {
				"method": "GET",
				"path": "/api/admin/orders",
				"headers": {"authorization": "Bearer token-shopper"},
			},
		}
	} with data.users as mock_users
}

# =============================================================================
# PROFILE TESTS
# =============================================================================

test_customer_view_profile if {
	authorization.allow_view_profile with input as {
		"request": {
			"http": {
				"method": "GET",
				"path": "/api/profile",
				"headers": {"authorization": "Bearer token-shopper"},
			},
		}
	} with data.users as mock_users
}

test_customer_update_profile if {
	authorization.allow_update_profile with input as {
		"request": {
			"http": {
				"method": "PUT",
				"path": "/api/profile",
				"headers": {"authorization": "Bearer token-shopper"},
			},
		}
	} with data.users as mock_users
}

# =============================================================================
# ADMIN PRODUCT MANAGEMENT TESTS
# =============================================================================

test_merchandiser_create_product if {
	authorization.allow_admin_create_product with input as {
		"request": {
			"http": {
				"method": "POST",
				"path": "/api/admin/products",
				"headers": {"authorization": "Bearer token-merch"},
			},
		}
	} with data.users as mock_users
}

test_customer_create_product_denied if {
	not authorization.allow_admin_create_product with input as {
		"request": {
			"http": {
				"method": "POST",
				"path": "/api/admin/products",
				"headers": {"authorization": "Bearer token-shopper"},
			},
		}
	} with data.users as mock_users
}

test_merchandiser_update_product if {
	authorization.allow_admin_update_product with input as {
		"request": {
			"http": {
				"method": "PATCH",
				"path": "/api/admin/products/SKU-12345",
				"headers": {"authorization": "Bearer token-merch"},
			},
		}
	} with data.users as mock_users
}

# =============================================================================
# REFUND TESTS
# =============================================================================

test_cs_agent_refund_denied if {
	not authorization.allow_admin_refund with input as {
		"request": {
			"http": {
				"method": "POST",
				"path": "/api/admin/orders/ORD-999/refund",
				"headers": {"authorization": "Bearer token-csagent"},
			},
		}
	} with data.users as mock_users
}

test_cs_lead_refund_allowed if {
	authorization.allow_admin_refund with input as {
		"request": {
			"http": {
				"method": "POST",
				"path": "/api/admin/orders/ORD-999/refund",
				"headers": {"authorization": "Bearer token-cslead"},
			},
		}
	} with data.users as mock_users
}

test_admin_refund_allowed if {
	authorization.allow_admin_refund with input as {
		"request": {
			"http": {
				"method": "POST",
				"path": "/api/admin/orders/ORD-999/refund",
				"headers": {"authorization": "Bearer token-admin"},
			},
		}
	} with data.users as mock_users
}
