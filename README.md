# ea-commerce

OPA policies for **EA Commerce** — a fictional e-commerce and brick-and-mortar retailer.
Used to demonstrate the [EnforceAuth](https://enforceauth.com) platform.

## Structure

Trunk-based: single `main` branch, environments live in folders.

```
├── dev/
├── stage/
├── prod/
│   ├── shared/              # Auth helpers, common utilities
│   ├── store-ops/           # Brick & mortar organization
│   │   ├── pos/             # Point-of-sale authorization
│   │   └── timeclock/       # Employee time & attendance
│   └── website/             # E-commerce organization
│       ├── api/             # REST API access control
│       ├── shopping-basket/  # Cart operations
│       ├── cyber-monday-rate-limiter/  # Event traffic shaping
│       └── promotions/      # Campaign & discount management
```

### Environment differences

Policies are mostly identical across environments. Where they diverge:

| Policy | Dev / Stage | Prod |
|--------|------------|------|
| Bot detection threshold | `< 80` score | `< 50` score |
| Peak load queue depth | `> 10,000` | `> 5,000` |
| Flash sale max discount | 60% | 40% |

## Running tests

```bash
# All tests in an environment
opa test dev/ -v

# Specific system
opa test dev/store-ops/pos/ dev/shared/ -v
opa test dev/website/ dev/shared/ -v
```

## Organizations

### Store Operations (`store-ops/`)

Brick-and-mortar retail — POS terminals and workforce management.

**Roles**: `cashier` → `shift_lead` → `store_manager` → `district_manager`

**Key policies**:
- Cashiers can only operate at their assigned store
- Return limits escalate by role ($50 / $200 / unlimited)
- Price overrides require shift lead+, capped by role (15% / 25% / 50%)
- Timeclock edits require a reason field
- Payroll export is district manager only

### Website (`website/`)

E-commerce platform — storefront, checkout, merchandising.

**Roles**: `customer` / `loyalty_gold` / `loyalty_platinum` (external), `cs_agent` / `cs_lead` / `merchandiser` / `marketing_manager` / `platform_admin` (internal)

**Key policies**:
- Product catalog is public; orders require auth
- Refunds require `cs_lead` or above (not regular agents)
- Promotions use four-eyes approval (creator ≠ approver)
- Cyber Monday rate limiter gives loyalty customers priority checkout
- Flash sales require `platform_admin` with discount ceiling
