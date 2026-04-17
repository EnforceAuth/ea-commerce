package store_ops.pos.authorization_test

import rego.v1

import data.store_ops.pos.authorization

mock_users := {
	"cashier1": {
		"token": "token-cashier1",
		"role": "cashier",
		"permissions": ["pos:sale", "pos:return", "pos:open_drawer"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
	"shift_lead1": {
		"token": "token-shiftlead",
		"role": "shift_lead",
		"permissions": ["pos:sale", "pos:return", "pos:void", "pos:price_override", "pos:open_drawer", "pos:close_register"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
	"store_mgr": {
		"token": "token-storemgr",
		"role": "store_manager",
		"permissions": ["pos:sale", "pos:return", "pos:void", "pos:price_override", "pos:open_drawer", "pos:close_register"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
	"district_mgr": {
		"token": "token-districtmgr",
		"role": "district_manager",
		"permissions": ["pos:sale", "pos:return", "pos:void", "pos:price_override", "pos:open_drawer", "pos:close_register"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-HQ",
	},
	"inactive_cashier": {
		"token": "token-inactive",
		"role": "cashier",
		"permissions": ["pos:sale"],
		"department": "store_ops",
		"active": false,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
}

# =============================================================================
# SALE TESTS
# =============================================================================

test_cashier_can_sell if {
	authorization.allow_sale with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/sale",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_inactive_cashier_denied if {
	not authorization.allow_sale with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/sale",
			"headers": {"authorization": "Bearer token-inactive"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_cashier_wrong_store_denied if {
	not authorization.allow_sale with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/sale",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-099"},
	}}
		with data.users as mock_users
}

test_district_mgr_any_store if {
	authorization.allow_sale with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/sale",
			"headers": {"authorization": "Bearer token-districtmgr"},
		},
		"headers": {"x-store-id": "STORE-099"},
	}}
		with data.users as mock_users
}

# =============================================================================
# RETURN TESTS
# =============================================================================

test_cashier_return_under_limit if {
	authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": 49.99},
	}}
		with data.users as mock_users
}

test_cashier_return_over_limit_denied if {
	not authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": 75.00},
	}}
		with data.users as mock_users
}

test_shift_lead_return_higher_limit if {
	authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": 150.00},
	}}
		with data.users as mock_users
}

test_shift_lead_return_over_limit_denied if {
	not authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": 250.00},
	}}
		with data.users as mock_users
}

test_store_mgr_return_unlimited if {
	authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-storemgr"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": 5000.00},
	}}
		with data.users as mock_users
}

# =============================================================================
# RETURN INPUT VALIDATION TESTS
# =============================================================================

test_return_string_amount_denied if {
	not authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": "49.99"},
	}}
		with data.users as mock_users
}

test_return_null_amount_denied if {
	not authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": null},
	}}
		with data.users as mock_users
}

test_return_negative_amount_denied if {
	not authorization.allow_return with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/return",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"amount": -10.00},
	}}
		with data.users as mock_users
}

# =============================================================================
# VOID TESTS
# =============================================================================

test_cashier_void_denied if {
	not authorization.allow_void with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/void",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_shift_lead_void_allowed if {
	authorization.allow_void with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/void",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

# =============================================================================
# PRICE OVERRIDE TESTS
# =============================================================================

test_shift_lead_discount_within_limit if {
	authorization.allow_price_override with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/price-override",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"discount_percent": 10},
	}}
		with data.users as mock_users
}

test_shift_lead_discount_over_limit_denied if {
	not authorization.allow_price_override with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/price-override",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"discount_percent": 20},
	}}
		with data.users as mock_users
}

test_store_mgr_higher_discount if {
	authorization.allow_price_override with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/price-override",
			"headers": {"authorization": "Bearer token-storemgr"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"discount_percent": 25},
	}}
		with data.users as mock_users
}

# =============================================================================
# PRICE OVERRIDE INPUT VALIDATION TESTS
# =============================================================================

test_discount_string_value_denied if {
	not authorization.allow_price_override with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/price-override",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"discount_percent": "10"},
	}}
		with data.users as mock_users
}

test_discount_null_value_denied if {
	not authorization.allow_price_override with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/price-override",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"discount_percent": null},
	}}
		with data.users as mock_users
}

test_discount_negative_value_denied if {
	not authorization.allow_price_override with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/price-override",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"discount_percent": -5},
	}}
		with data.users as mock_users
}

# =============================================================================
# CLOSE REGISTER TESTS
# =============================================================================

test_cashier_close_register_denied if {
	not authorization.allow_close_register with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/close-register",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_shift_lead_close_register if {
	authorization.allow_close_register with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/pos/close-register",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}
