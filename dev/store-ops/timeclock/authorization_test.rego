package store_ops.timeclock.authorization_test

import rego.v1

import data.store_ops.timeclock.authorization

mock_users := {
	"cashier1": {
		"token": "token-cashier1",
		"role": "cashier",
		"permissions": ["pos:sale", "timeclock:punch"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
	"shift_lead1": {
		"token": "token-shiftlead",
		"role": "shift_lead",
		"permissions": ["timeclock:punch", "timeclock:view_team"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
	"store_mgr": {
		"token": "token-storemgr",
		"role": "store_manager",
		"permissions": ["timeclock:punch", "timeclock:view_team", "timeclock:approve", "timeclock:edit"],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-042",
	},
	"district_mgr": {
		"token": "token-districtmgr",
		"role": "district_manager",
		"permissions": [
			"timeclock:punch", "timeclock:view_team",
			"timeclock:approve", "timeclock:edit",
			"timeclock:payroll_export",
		],
		"department": "store_ops",
		"active": true,
		"exp": 9999999999,
		"store_id": "STORE-HQ",
	},
}

# =============================================================================
# PUNCH TESTS
# =============================================================================

test_cashier_clock_in if {
	authorization.allow_punch with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/timeclock/clock-in",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_cashier_clock_out if {
	authorization.allow_punch with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/timeclock/clock-out",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_cashier_wrong_store_denied if {
	not authorization.allow_punch with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/timeclock/clock-in",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-099"},
	}}
		with data.users as mock_users
}

# =============================================================================
# VIEW TIMECARD TESTS
# =============================================================================

test_cashier_view_own_timecard if {
	authorization.allow_view_own_timecard with input as {"request": {"http": {
		"method": "GET",
		"path": "/timeclock/my-timecard",
		"headers": {"authorization": "Bearer token-cashier1"},
	}}}
		with data.users as mock_users
}

test_cashier_view_team_denied if {
	not authorization.allow_view_team_timecards with input as {"request": {
		"http": {
			"method": "GET",
			"path": "/timeclock/team",
			"headers": {"authorization": "Bearer token-cashier1"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_shift_lead_view_team if {
	authorization.allow_view_team_timecards with input as {"request": {
		"http": {
			"method": "GET",
			"path": "/timeclock/team",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

# =============================================================================
# APPROVE TESTS
# =============================================================================

test_shift_lead_approve_denied if {
	not authorization.allow_approve_timecard with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/timeclock/approve/TC-001",
			"headers": {"authorization": "Bearer token-shiftlead"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

test_store_mgr_approve if {
	authorization.allow_approve_timecard with input as {"request": {
		"http": {
			"method": "POST",
			"path": "/timeclock/approve/TC-001",
			"headers": {"authorization": "Bearer token-storemgr"},
		},
		"headers": {"x-store-id": "STORE-042"},
	}}
		with data.users as mock_users
}

# =============================================================================
# EDIT TESTS
# =============================================================================

test_store_mgr_edit_with_reason if {
	authorization.allow_edit_timecard with input as {"request": {
		"http": {
			"method": "PATCH",
			"path": "/timeclock/timecard/TC-001",
			"headers": {"authorization": "Bearer token-storemgr"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"reason": "Employee forgot to clock out - verified by shift lead"},
	}}
		with data.users as mock_users
}

test_store_mgr_edit_no_reason_denied if {
	not authorization.allow_edit_timecard with input as {"request": {
		"http": {
			"method": "PATCH",
			"path": "/timeclock/timecard/TC-001",
			"headers": {"authorization": "Bearer token-storemgr"},
		},
		"headers": {"x-store-id": "STORE-042"},
		"body": {"reason": ""},
	}}
		with data.users as mock_users
}

# =============================================================================
# PAYROLL EXPORT TESTS
# =============================================================================

test_store_mgr_payroll_denied if {
	not authorization.allow_payroll_export with input as {"request": {"http": {
		"method": "GET",
		"path": "/timeclock/payroll-export",
		"headers": {"authorization": "Bearer token-storemgr"},
	}}}
		with data.users as mock_users
}

test_district_mgr_payroll_export if {
	authorization.allow_payroll_export with input as {"request": {"http": {
		"method": "GET",
		"path": "/timeclock/payroll-export",
		"headers": {"authorization": "Bearer token-districtmgr"},
	}}}
		with data.users as mock_users
}
