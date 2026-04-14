# METADATA
# title: Timeclock Access Control
# description: Governs clock-in/out, timecard viewing, manager approvals, and payroll export
# authors:
#   - name: Retail Operations Team
package store_ops.timeclock.authorization

import rego.v1

import data.shared.authentication

# -------------------------------------------------------
# Clock in / Clock out - any active employee at their store
# -------------------------------------------------------
allow_punch if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	input.request.http.path in ["/timeclock/clock-in", "/timeclock/clock-out"]
	"timeclock:punch" in user_claims.permissions
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# View own timecard
# -------------------------------------------------------
allow_view_own_timecard if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/timeclock/my-timecard"
	"timeclock:punch" in user_claims.permissions
}

# -------------------------------------------------------
# View team timecards - shift lead, store manager, district manager
# -------------------------------------------------------
allow_view_team_timecards if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/timeclock/team"
	"timeclock:view_team" in user_claims.permissions
	user_claims.role in ["shift_lead", "store_manager", "district_manager"]
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# Approve timecards - store manager or district manager
# -------------------------------------------------------
allow_approve_timecard if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "POST"
	startswith(input.request.http.path, "/timeclock/approve/")
	"timeclock:approve" in user_claims.permissions
	user_claims.role in ["store_manager", "district_manager"]
	_at_assigned_store(user_claims)
}

# -------------------------------------------------------
# Edit timecard (correct missed punches) - store manager only
# -------------------------------------------------------
allow_edit_timecard if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "PATCH"
	startswith(input.request.http.path, "/timeclock/timecard/")
	"timeclock:edit" in user_claims.permissions
	user_claims.role in ["store_manager", "district_manager"]
	_at_assigned_store(user_claims)

	# Edits must include a reason
	input.request.body.reason != ""
}

# -------------------------------------------------------
# Payroll export - district manager only
# -------------------------------------------------------
allow_payroll_export if {
	user_claims := authentication.authenticated_claims
	input.request.http.method == "GET"
	input.request.http.path == "/timeclock/payroll-export"
	"timeclock:payroll_export" in user_claims.permissions
	user_claims.role == "district_manager"
}

# -------------------------------------------------------
# Helper: user is at their assigned store
# -------------------------------------------------------
_at_assigned_store(user_claims) if {
	user_claims.role == "district_manager"
}

_at_assigned_store(user_claims) if {
	user_claims.store_id == input.request.headers["x-store-id"]
}
