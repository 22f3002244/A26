-- =====================================================================
-- EVENT TICKETING PLATFORM — CONSOLIDATED SCHEMA (v2 + v3–v7 merged)
-- Supports: multi-venue events (tours), multi-day/multi-session shows,
-- multiple ticket categories per session, phased pricing, passes/bundles,
-- inventory holds (anti-oversell), promo codes, waitlists, reserved seating,
-- reverse-QR gate verification (rotating gate-side QR, no static ticket
-- QR to screenshot/share), business accounts with role-based access,
-- resale/transfer price controls, payouts, and platform-level admin.
-- =====================================================================
-- Engine assumption: PostgreSQL
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- 1. USERS & IDENTITY
-- =====================================================================

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name           VARCHAR(150) NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    phone               VARCHAR(20) UNIQUE,
    password_hash       TEXT NOT NULL,
    profile_photo_url   TEXT,
    id_proof_type       VARCHAR(30),
    id_proof_number     VARCHAR(100),
    id_verified         BOOLEAN DEFAULT FALSE,
    date_of_birth       DATE,                        -- for age-restricted sessions
    is_active           BOOLEAN DEFAULT TRUE,
    -- notification preferences (v5)
    notify_email        BOOLEAN DEFAULT TRUE,
    notify_sms          BOOLEAN DEFAULT TRUE,
    notify_push         BOOLEAN DEFAULT TRUE,
    -- MFA (v7) — required before a session can use any role with roles.requires_mfa = TRUE
    mfa_enabled         BOOLEAN DEFAULT FALSE,
    mfa_secret_ref       VARCHAR(200),                -- reference into secrets vault/KMS, never the raw TOTP secret
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE user_devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint  TEXT NOT NULL,
    device_name         VARCHAR(100),
    push_token          TEXT,
    is_trusted          BOOLEAN DEFAULT FALSE,
    last_seen_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now(),
    UNIQUE (user_id, device_fingerprint)
);

CREATE TABLE user_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           UUID REFERENCES user_devices(id),
    auth_token_hash     TEXT NOT NULL,
    ip_address          INET,
    is_active           BOOLEAN DEFAULT TRUE,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Auth flow completeness: email verify / phone OTP / password reset (v3)
CREATE TABLE verification_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_type          VARCHAR(20) NOT NULL,   -- 'email_verify','phone_otp','password_reset'
    token_hash          TEXT NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Consent / policy acceptance trail (v6) — DPDP Act / GDPR-style compliance
CREATE TABLE user_consents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_type        VARCHAR(30) NOT NULL,  -- 'terms_of_service','privacy_policy','marketing_emails'
    policy_version      VARCHAR(20) NOT NULL,
    accepted_at         TIMESTAMPTZ DEFAULT now(),
    ip_address          INET
);

-- Right-to-erasure request tracking (v7)
CREATE TABLE data_deletion_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id),
    status              VARCHAR(20) DEFAULT 'pending', -- pending/in_progress/completed/rejected
    reason              TEXT,
    requested_at        TIMESTAMPTZ DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    handled_by          UUID  -- REFERENCES platform_admins(id), FK added after that table below
);

-- Fraud / risk signal tracking (v5)
CREATE TABLE fraud_signals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID REFERENCES users(id),
    signal_type         VARCHAR(50) NOT NULL,  -- 'excessive_transfers','repeated_failed_entry','chargeback','device_sharing'
    severity            VARCHAR(20) DEFAULT 'low', -- low/medium/high
    details             JSONB,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 2. BUSINESS ACCOUNTS & ROLE-BASED ACCESS CONTROL (v3)
-- =====================================================================
-- A "normal user" is just a `users` row with no organization ties.
-- A "business user" is the SAME `users` row, plus a row in
-- organization_members linking them to an organizations account with a
-- role. One person can be a paying customer and a team member of one or
-- more organizations at the same time.

CREATE TABLE organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name          VARCHAR(200) NOT NULL,
    display_name        VARCHAR(150) NOT NULL,
    business_type       VARCHAR(50),                 -- 'sole_proprietor','partnership','pvt_ltd','llp'
    tax_id              VARCHAR(50),                 -- GSTIN / VAT / EIN etc.
    contact_email       VARCHAR(255) NOT NULL,
    contact_phone       VARCHAR(20),
    billing_address     TEXT,
    country             VARCHAR(100),
    kyc_status          VARCHAR(20) DEFAULT 'pending', -- pending/verified/rejected
    kyc_document_url    TEXT,
    status              VARCHAR(20) DEFAULT 'active',  -- active/suspended/closed
    created_by          UUID NOT NULL REFERENCES users(id), -- becomes Owner
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);

-- Bank details for payout settlement. Store tokenized/masked data only.
CREATE TABLE organization_bank_accounts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_holder_name VARCHAR(150) NOT NULL,
    account_number_masked VARCHAR(50) NOT NULL,     -- e.g. 'XXXXXX4321'
    bank_name           VARCHAR(150),
    ifsc_or_swift       VARCHAR(20),
    is_primary          BOOLEAN DEFAULT TRUE,
    verified            BOOLEAN DEFAULT FALSE,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Commission/fee schedule that payouts.platform_fee is computed from
CREATE TABLE organization_fee_plans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    fee_type            VARCHAR(20) NOT NULL,   -- 'percentage','flat_per_ticket'
    fee_value           DECIMAL(10,4) NOT NULL,
    effective_from      TIMESTAMPTZ NOT NULL,
    effective_to        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE permissions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code                VARCHAR(60) UNIQUE NOT NULL,  -- e.g. 'event:publish', 'gate:override'
    category            VARCHAR(40) NOT NULL,         -- 'events','finance','gate','staff','org'
    description         TEXT
);

-- Roles can be system-wide templates (organization_id NULL) or org-specific.
CREATE TABLE roles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE, -- NULL = system template
    name                VARCHAR(60) NOT NULL,
    description         TEXT,
    is_system_role      BOOLEAN DEFAULT FALSE,
    requires_mfa        BOOLEAN DEFAULT FALSE,  -- (v7) MFA mandatory to act with this role's permissions
    created_at          TIMESTAMPTZ DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE role_permissions (
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id       UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE organization_members (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id),
    role_id             UUID NOT NULL REFERENCES roles(id),
    status              VARCHAR(20) DEFAULT 'invited', -- invited/active/suspended/removed
    invited_by          UUID REFERENCES users(id),
    joined_at           TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now(),
    UNIQUE (organization_id, user_id)
);

CREATE TABLE organization_invitations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email               VARCHAR(255) NOT NULL,
    role_id             UUID NOT NULL REFERENCES roles(id),
    invited_by          UUID NOT NULL REFERENCES users(id),
    token               TEXT UNIQUE NOT NULL,
    status              VARCHAR(20) DEFAULT 'pending', -- pending/accepted/expired/revoked
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Optional narrower scoping: restrict a member to specific events.
-- No rows for a member = full org-wide access.
CREATE TABLE organization_member_event_scopes (
    organization_member_id UUID NOT NULL REFERENCES organization_members(id) ON DELETE CASCADE,
    event_id                UUID NOT NULL,  -- FK to events(id) added below, after `events` is defined
    PRIMARY KEY (organization_member_id, event_id)
);

-- Platform-level administration — separate from org-scoped RBAC above.
-- Controls access that spans across organizations (KYC approval, org
-- suspension, event force-cancellation, flagged-account review).
CREATE TABLE platform_admins (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id),
    role                VARCHAR(30) NOT NULL,  -- 'super_admin','compliance_officer','support_agent','finance_ops'
    is_active           BOOLEAN DEFAULT TRUE,
    created_at          TIMESTAMPTZ DEFAULT now(),
    UNIQUE (user_id)
);

ALTER TABLE data_deletion_requests
    ADD CONSTRAINT fk_deletion_handled_by FOREIGN KEY (handled_by) REFERENCES platform_admins(id);

-- =====================================================================
-- 3. VENUES, SEATING, GATES
-- =====================================================================

CREATE TABLE venues (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(150) NOT NULL,
    address             TEXT,
    city                VARCHAR(100),
    country             VARCHAR(100),
    timezone            VARCHAR(50) NOT NULL,        -- e.g. 'Asia/Kolkata'
    latitude            DECIMAL(9,6),
    longitude           DECIMAL(9,6),
    total_capacity      INTEGER,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Optional reserved-seating structure
CREATE TABLE venue_sections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    venue_id            UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    section_name        VARCHAR(50) NOT NULL,        -- e.g. 'Balcony-A'
    capacity            INTEGER NOT NULL
);

CREATE TABLE venue_seats (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    section_id          UUID NOT NULL REFERENCES venue_sections(id) ON DELETE CASCADE,
    row_label           VARCHAR(10) NOT NULL,
    seat_number         VARCHAR(10) NOT NULL,
    is_accessible       BOOLEAN DEFAULT FALSE,
    UNIQUE (section_id, row_label, seat_number)
);

-- Reverse-QR gate: the gate displays a rotating code; the ticket holder's
-- app scans IT (no static ticket QR exists anywhere to screenshot/share).
CREATE TABLE gates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    venue_id            UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    gate_code           VARCHAR(30) NOT NULL,
    gate_name           VARCHAR(100),
    hardware_device_id  VARCHAR(100),
    is_entry            BOOLEAN DEFAULT TRUE,
    status              VARCHAR(20) DEFAULT 'online',
    last_heartbeat_at   TIMESTAMPTZ,
    qr_rotation_seconds INTEGER NOT NULL DEFAULT 60,   -- (v4) how often the on-screen QR rotates
    qr_signing_key_id   VARCHAR(100),                  -- (v4) reference into secrets manager/KMS, never the raw key
    created_at          TIMESTAMPTZ DEFAULT now(),
    UNIQUE (venue_id, gate_code)
);

CREATE TABLE gate_qr_tokens (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gate_id                   UUID NOT NULL REFERENCES gates(id) ON DELETE CASCADE,
    token                     TEXT NOT NULL UNIQUE,
    issued_at                 TIMESTAMPTZ DEFAULT now(),
    expires_at                TIMESTAMPTZ NOT NULL,
    is_used_for_replay_check  BOOLEAN DEFAULT FALSE
    -- NOTE: this token is NOT single-use — many legitimate people scan the
    -- same on-screen code during its rotation window. This flag is for
    -- forensic/fraud review only; actual replay protection is the unique
    -- constraint on entry_attempts(ticket_id, gate_qr_token_id) below.
);

-- =====================================================================
-- 4. EVENT HIERARCHY: Event -> Leg (venue) -> Session (date+time)
-- =====================================================================

CREATE TABLE events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id),  -- was organizer_id -> users(id) in v2; moved to organizations in v3
    title               VARCHAR(200) NOT NULL,
    description         TEXT,
    category            VARCHAR(50),
    cover_image_url     TEXT,
    status              VARCHAR(20) DEFAULT 'published', -- draft/published/cancelled/completed
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE organization_member_event_scopes
    ADD CONSTRAINT fk_scope_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE;

-- One row per venue occurrence of the event (a tour "leg")
CREATE TABLE event_legs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    venue_id            UUID NOT NULL REFERENCES venues(id),
    leg_name            VARCHAR(150),               -- e.g. 'Mumbai Leg'
    currency            VARCHAR(10) NOT NULL,       -- differs per country
    status              VARCHAR(20) DEFAULT 'scheduled', -- scheduled/cancelled/completed
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- One row per date+showtime at a given leg
CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_leg_id        UUID NOT NULL REFERENCES event_legs(id) ON DELETE CASCADE,
    session_date        DATE NOT NULL,
    doors_open_time     TIMESTAMPTZ NOT NULL,
    start_time          TIMESTAMPTZ NOT NULL,
    end_time            TIMESTAMPTZ,
    min_age             SMALLINT,                  -- age restriction, nullable
    status              VARCHAR(20) DEFAULT 'scheduled', -- scheduled/cancelled/sold_out/completed
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Which gates are active for a given session, and their open/close window
CREATE TABLE session_gates (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id                  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    gate_id                     UUID NOT NULL REFERENCES gates(id),
    opens_at                    TIMESTAMPTZ NOT NULL,
    closes_at                   TIMESTAMPTZ NOT NULL,
    restricted_to_category_id   UUID,                    -- nullable FK to ticket_categories, e.g. VIP-only gate
    UNIQUE (session_id, gate_id)
);

-- Audit trail for post-sale changes (venue/time/lineup/price/cancellation).
-- Material changes should trigger notifications + refund eligibility
-- regardless of what refund_policies would otherwise allow this close
-- to the event. (v7)
CREATE TABLE event_changes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id       UUID NOT NULL REFERENCES events(id),
    session_id     UUID REFERENCES sessions(id),  -- NULL = event-level change
    change_type    VARCHAR(30) NOT NULL,  -- 'venue_change','time_change','cancellation','lineup_change','price_change'
    old_value      JSONB,
    new_value      JSONB,
    changed_by     UUID REFERENCES users(id),
    is_material    BOOLEAN DEFAULT FALSE,
    notified_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 5. TICKET CATEGORIES & PHASED PRICING
-- =====================================================================

-- Category defined at event level (name/perks consistent across legs)
CREATE TABLE ticket_categories (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id                UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    name                    VARCHAR(100) NOT NULL,
    description             TEXT,
    is_seated               BOOLEAN DEFAULT FALSE,
    perks                   TEXT,
    -- reverse-QR / resale controls (v4, v5)
    entry_verification_mode VARCHAR(20) NOT NULL DEFAULT 'reverse_qr', -- 'reverse_qr' | 'static_qr' (legacy fallback)
    requires_photo_id_check BOOLEAN NOT NULL DEFAULT FALSE,            -- steward visually matches ID for high-risk categories
    resale_policy           VARCHAR(30) NOT NULL DEFAULT 'transfer_at_face_value',
        -- 'no_transfer' | 'transfer_at_face_value' | 'organizer_marketplace'
    max_tickets_per_user    SMALLINT,             -- NULL = no limit; anti-bulk-buy cap
    created_at              TIMESTAMPTZ DEFAULT now()
);

-- Availability + capacity of a category FOR a specific session
CREATE TABLE session_ticket_categories (
    id                             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id                     UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ticket_category_id             UUID NOT NULL REFERENCES ticket_categories(id),
    venue_section_id               UUID REFERENCES venue_sections(id),  -- nullable, for reserved seating
    quantity_total                 INTEGER NOT NULL,
    quantity_sold                  INTEGER DEFAULT 0,
    quantity_held                  INTEGER DEFAULT 0,          -- reserved by active checkout holds
    is_active                      BOOLEAN DEFAULT TRUE,
    max_tickets_per_user_override  SMALLINT,   -- (v6) overrides ticket_categories.max_tickets_per_user for this session
    created_at                     TIMESTAMPTZ DEFAULT now(),
    UNIQUE (session_id, ticket_category_id),
    CONSTRAINT chk_stc_quantities CHECK (quantity_sold + quantity_held <= quantity_total)
    -- NOTE: this CHECK is defense-in-depth only. It does not fully prevent
    -- overselling under concurrency by itself — the application must take a
    -- row lock (SELECT ... FOR UPDATE) or use SERIALIZABLE isolation when
    -- incrementing quantity_held/quantity_sold.
);

-- Time-bound price tiers within a category for a session
CREATE TABLE pricing_phases (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_ticket_category_id UUID NOT NULL REFERENCES session_ticket_categories(id) ON DELETE CASCADE,
    phase_name                  VARCHAR(50) NOT NULL,        -- 'Early Bird','Phase 2','Door Price'
    price                       DECIMAL(10,2) NOT NULL,
    starts_at                   TIMESTAMPTZ NOT NULL,
    ends_at                     TIMESTAMPTZ NOT NULL,
    quantity_cap                INTEGER,                 -- optional cap independent of overall category stock
    quantity_sold                INTEGER DEFAULT 0,
    created_at                    TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 6. MULTI-SESSION PASSES / BUNDLES (e.g. "3-Day Festival Pass")
-- =====================================================================

CREATE TABLE passes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    name                VARCHAR(150) NOT NULL,
    description         TEXT,
    price               DECIMAL(10,2) NOT NULL,
    currency            VARCHAR(10) NOT NULL,
    quantity_total      INTEGER NOT NULL,
    quantity_sold       INTEGER DEFAULT 0,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Which sessions a pass grants access to
CREATE TABLE pass_sessions (
    pass_id             UUID NOT NULL REFERENCES passes(id) ON DELETE CASCADE,
    session_id          UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    PRIMARY KEY (pass_id, session_id)
);

-- =====================================================================
-- 7. INVENTORY HOLDS (prevents overselling under concurrent checkout)
-- =====================================================================

CREATE TABLE inventory_holds (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_ticket_category_id UUID NOT NULL REFERENCES session_ticket_categories(id),
    user_id                     UUID NOT NULL REFERENCES users(id),
    quantity                    INTEGER NOT NULL,
    status                      VARCHAR(20) DEFAULT 'active', -- active/converted/expired/released
    expires_at                  TIMESTAMPTZ NOT NULL,          -- e.g. now() + 10 minutes
    created_at                  TIMESTAMPTZ DEFAULT now()
);
-- App logic: on checkout start, insert hold + increment quantity_held.
-- On payment success: convert hold -> booking, decrement quantity_held, increment quantity_sold.
-- On expiry/cancel: decrement quantity_held via scheduled job.
-- Also enforce max_tickets_per_user / max_tickets_per_user_override here.

-- =====================================================================
-- 8. PROMO CODES
-- =====================================================================

CREATE TABLE promo_codes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID REFERENCES events(id),        -- nullable = platform-wide code
    code                VARCHAR(50) UNIQUE NOT NULL,
    discount_type       VARCHAR(20) NOT NULL,            -- 'percentage','flat'
    discount_value      DECIMAL(10,2) NOT NULL,
    max_total_uses      INTEGER,
    max_uses_per_user   SMALLINT DEFAULT 1,
    valid_from          TIMESTAMPTZ,
    valid_to            TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE promo_code_redemptions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    promo_code_id       UUID NOT NULL REFERENCES promo_codes(id),
    user_id             UUID NOT NULL REFERENCES users(id),
    booking_id          UUID,                          -- FK added after bookings table below
    redeemed_at         TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 9. WAITLISTS (sold-out category demand capture)
-- =====================================================================

CREATE TABLE waitlists (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_ticket_category_id UUID NOT NULL REFERENCES session_ticket_categories(id),
    user_id                     UUID NOT NULL REFERENCES users(id),
    quantity_wanted             SMALLINT DEFAULT 1,
    status                      VARCHAR(20) DEFAULT 'waiting', -- waiting/notified/expired/converted
    created_at                  TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 10. NOTIFICATIONS (v5)
-- =====================================================================

CREATE TABLE notifications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id),
    type                VARCHAR(40) NOT NULL,   -- 'waitlist_available','transfer_request','refund_processed','otp','event_update'
    channel             VARCHAR(20) NOT NULL,   -- 'push','email','sms','in_app'
    title               VARCHAR(200),
    body                TEXT,
    related_entity_type VARCHAR(50),
    related_entity_id   UUID,
    status              VARCHAR(20) DEFAULT 'pending', -- pending/sent/failed/read
    sent_at             TIMESTAMPTZ,
    read_at             TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 11. REFUND / CANCELLATION POLICY
-- =====================================================================

CREATE TABLE refund_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_category_id  UUID NOT NULL REFERENCES ticket_categories(id),
    hours_before_event  INTEGER NOT NULL,      -- cutoff window, e.g. 48
    refund_percentage   DECIMAL(5,2) NOT NULL -- e.g. 80.00
);

-- =====================================================================
-- 12. BOOKINGS & TICKETS
-- =====================================================================

CREATE TABLE bookings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id),
    session_id          UUID REFERENCES sessions(id),      -- nullable if booking is a pass
    pass_id             UUID REFERENCES passes(id),        -- nullable if booking is per-session
    booking_reference   VARCHAR(20) UNIQUE NOT NULL,
    status              VARCHAR(20) DEFAULT 'confirmed', -- pending/confirmed/cancelled/refunded
    subtotal_amount     DECIMAL(10,2) NOT NULL,
    discount_amount     DECIMAL(10,2) DEFAULT 0,
    tax_amount          DECIMAL(10,2) DEFAULT 0,
    total_amount        DECIMAL(10,2) NOT NULL,
    currency            VARCHAR(10) NOT NULL,
    payment_id          UUID,
    invoice_number      VARCHAR(30) UNIQUE,             -- (v5) tax/GST invoice numbering
    idempotency_key      VARCHAR(100) UNIQUE,            -- (v6) prevents duplicate bookings from retried checkout
    created_at          TIMESTAMPTZ DEFAULT now(),
    CHECK (session_id IS NOT NULL OR pass_id IS NOT NULL)
);

ALTER TABLE promo_code_redemptions
    ADD CONSTRAINT fk_redemption_booking FOREIGN KEY (booking_id) REFERENCES bookings(id);

-- Individual ticket entitlement (no static scannable artifact — server-verified only)
CREATE TABLE tickets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id          UUID NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    session_id          UUID NOT NULL REFERENCES sessions(id), -- concrete session even if bought via a pass
    ticket_category_id  UUID NOT NULL REFERENCES ticket_categories(id),
    assigned_user_id    UUID REFERENCES users(id),
    seat_id             UUID REFERENCES venue_seats(id), -- nullable for GA
    status              VARCHAR(20) DEFAULT 'valid',  -- valid/used/cancelled/transferred
    is_transferable     BOOLEAN DEFAULT FALSE,
    price_paid          DECIMAL(10,2),   -- (v5) face value at time of purchase — needed for refunds + transfer price caps
    currency            VARCHAR(10),     -- (v5)
    used_at             TIMESTAMPTZ,
    used_gate_id        UUID REFERENCES gates(id),
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Prevent double-selling a reserved seat. A cancelled ticket frees the
-- seat back up, so this only applies to tickets that still hold it. (v6)
CREATE UNIQUE INDEX uq_ticket_seat_per_session
    ON tickets (session_id, seat_id)
    WHERE seat_id IS NOT NULL AND status IN ('valid', 'used', 'transferred');

CREATE TABLE ticket_transfers (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id                   UUID NOT NULL REFERENCES tickets(id),
    from_user_id                UUID NOT NULL REFERENCES users(id),
    to_user_id                  UUID NOT NULL REFERENCES users(id),
    transfer_status              VARCHAR(20) DEFAULT 'pending', -- pending/accepted/rejected
    transfer_price                DECIMAL(10,2) NOT NULL DEFAULT 0,      -- (v5)
    requires_organizer_approval    BOOLEAN NOT NULL DEFAULT FALSE,        -- (v5)
    approved_by_member_id            UUID REFERENCES organization_members(id), -- (v5)
    approved_at                        TIMESTAMPTZ,                             -- (v5)
    requested_at                         TIMESTAMPTZ DEFAULT now(),
    resolved_at                            TIMESTAMPTZ
    -- App-layer enforcement against ticket_categories.resale_policy:
    --   'no_transfer'            -> reject outright
    --   'transfer_at_face_value' -> reject unless transfer_price = tickets.price_paid
    --   'organizer_marketplace'  -> require requires_organizer_approval = TRUE and a
    --                                non-null approved_by_member_id before 'accepted'
);

-- =====================================================================
-- 13. REVERSE-QR GATE VERIFICATION LOG
-- =====================================================================

CREATE TABLE entry_attempts (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id                UUID NOT NULL REFERENCES tickets(id),
    user_id                  UUID NOT NULL REFERENCES users(id),
    gate_id                  UUID NOT NULL REFERENCES gates(id),
    gate_qr_token_id         UUID NOT NULL REFERENCES gate_qr_tokens(id),
    device_id                UUID REFERENCES user_devices(id),
    scanned_at               TIMESTAMPTZ DEFAULT now(),
    server_decision          VARCHAR(20) NOT NULL,  -- approved/denied
    denial_reason            VARCHAR(100),
    latitude                 DECIMAL(9,6),
    longitude                DECIMAL(9,6),
    response_time_ms         INTEGER,
    id_checked_by_member_id  UUID REFERENCES organization_members(id), -- (v4) steward who did a photo-ID cross-check
    CONSTRAINT uq_entry_attempt_ticket_token UNIQUE (ticket_id, gate_qr_token_id)
        -- (v4) blocks a literally-replayed captured request for the same ticket+token
);

-- Hard stop against double check-in — DB-level guarantee that only one
-- approved entry exists per ticket, even under a race from a screenshot
-- passed to a second person within the QR's rotation window. (v4)
CREATE UNIQUE INDEX uq_ticket_single_approved_entry
    ON entry_attempts (ticket_id)
    WHERE server_decision = 'approved';
-- NOTE: if you support re-entry (wristband events, smoking-area re-entry),
-- don't use a global index like this — scope uniqueness on an added
-- entry_type ('entry'/'exit') column instead.

-- Manual override log when staff let someone in outside the normal flow
CREATE TABLE gate_manual_overrides (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id                UUID REFERENCES tickets(id),
    booking_reference        VARCHAR(20),                -- fallback lookup if ticket_id unknown at time of override
    gate_id                  UUID NOT NULL REFERENCES gates(id),
    organization_member_id   UUID NOT NULL REFERENCES organization_members(id), -- was staff_member_id -> staff_members(id) in v2
    reason                   TEXT NOT NULL,
    overridden_at            TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 14. PAYMENTS, REFUNDS, PAYOUTS
-- =====================================================================

CREATE TABLE payments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id          UUID NOT NULL REFERENCES bookings(id),
    amount              DECIMAL(10,2) NOT NULL,
    currency            VARCHAR(10) NOT NULL,
    payment_gateway     VARCHAR(50),
    gateway_txn_id      VARCHAR(150),
    status              VARCHAR(20) DEFAULT 'pending', -- pending/success/failed/refunded
    created_at          TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT uq_payments_gateway_txn UNIQUE (gateway_txn_id) -- (v6) webhook idempotency; NULLs unaffected
);

-- Explicit refund ledger — bookings.status='refunded' alone can't
-- represent partial refunds, retries, or gateway failure states. (v3)
CREATE TABLE refunds (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id          UUID NOT NULL REFERENCES bookings(id),
    payment_id          UUID NOT NULL REFERENCES payments(id),
    amount              DECIMAL(10,2) NOT NULL,
    reason              TEXT,
    initiated_by        UUID REFERENCES users(id),
    status              VARCHAR(20) DEFAULT 'pending', -- pending/processed/failed
    gateway_refund_id   VARCHAR(150),
    processed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Platform -> organizer settlement trail (v3)
CREATE TABLE payouts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id),
    bank_account_id     UUID NOT NULL REFERENCES organization_bank_accounts(id),
    period_start        DATE NOT NULL,
    period_end          DATE NOT NULL,
    gross_amount        DECIMAL(12,2) NOT NULL,
    platform_fee        DECIMAL(12,2) NOT NULL,
    net_amount          DECIMAL(12,2) NOT NULL,
    currency            VARCHAR(10) NOT NULL,
    status              VARCHAR(20) DEFAULT 'pending', -- pending/processing/paid/failed
    paid_at             TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 15. AUDIT LOG (v3)
-- =====================================================================

CREATE TABLE audit_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id       UUID REFERENCES users(id),
    organization_id     UUID REFERENCES organizations(id),
    action               VARCHAR(60) NOT NULL,   -- 'role.assigned','member.removed','refund.issued', etc.
    entity_type            VARCHAR(50),
    entity_id                 UUID,
    metadata                    JSONB,
    ip_address                    INET,
    created_at                      TIMESTAMPTZ DEFAULT now()
);

-- =====================================================================
-- 16. SEED DATA — permissions + default system role templates
-- =====================================================================

INSERT INTO permissions (code, category, description) VALUES
    ('org:settings_manage',   'org',     'Edit organization profile, KYC docs, tax info'),
    ('org:billing_manage',    'org',     'Manage bank accounts and view payouts'),
    ('staff:manage',          'staff',   'Invite, remove, and change roles of team members'),
    ('event:create',          'events',  'Create new events'),
    ('event:edit',            'events',  'Edit event/leg/session details'),
    ('event:publish',         'events',  'Publish or cancel an event'),
    ('event:delete',          'events',  'Delete a draft event'),
    ('pricing:manage',        'events',  'Manage ticket categories and pricing phases'),
    ('promo:manage',          'events',  'Create and manage promo codes'),
    ('venue:manage',          'events',  'Manage venue/section/seat/gate configuration'),
    ('finance:view',          'finance', 'View payments, payouts, and settlement reports'),
    ('refund:process',        'finance', 'Approve and issue refunds'),
    ('gate:scan',              'gate',    'Operate a gate scanning device'),
    ('gate:override',           'gate',    'Manually admit a ticket holder outside normal flow'),
    ('report:view',              'events',  'View sales and attendance reports');

INSERT INTO roles (id, organization_id, name, description, is_system_role, requires_mfa) VALUES
    (gen_random_uuid(), NULL, 'Owner',          'Full control, including billing and staff management', TRUE, TRUE),
    (gen_random_uuid(), NULL, 'Admin',          'Full operational control, excluding billing/payout config', TRUE, TRUE),
    (gen_random_uuid(), NULL, 'Event Manager',  'Create and manage events, pricing, and promos', TRUE, FALSE),
    (gen_random_uuid(), NULL, 'Finance Manager','View finances and process refunds', TRUE, TRUE),
    (gen_random_uuid(), NULL, 'Gate Steward',   'Scan tickets and perform manual gate overrides', TRUE, FALSE),
    (gen_random_uuid(), NULL, 'Viewer',         'Read-only access to events and reports', TRUE, FALSE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Owner' AND r.organization_id IS NULL;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Admin' AND r.organization_id IS NULL
  AND p.code NOT IN ('org:billing_manage');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Event Manager' AND r.organization_id IS NULL
  AND p.code IN ('event:create','event:edit','event:publish','pricing:manage',
                 'promo:manage','venue:manage','report:view');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Finance Manager' AND r.organization_id IS NULL
  AND p.code IN ('finance:view','refund:process','report:view');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Gate Steward' AND r.organization_id IS NULL
  AND p.code IN ('gate:scan','gate:override');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Viewer' AND r.organization_id IS NULL
  AND p.code IN ('report:view','finance:view');

-- =====================================================================
-- 17. INDEXES
-- =====================================================================

CREATE INDEX idx_legs_event ON event_legs(event_id);
CREATE INDEX idx_sessions_leg ON sessions(event_leg_id);
CREATE INDEX idx_stc_session ON session_ticket_categories(session_id);
CREATE INDEX idx_phases_stc ON pricing_phases(session_ticket_category_id);
CREATE INDEX idx_tickets_session ON tickets(session_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_bookings_user ON bookings(user_id);
CREATE INDEX idx_bookings_session ON bookings(session_id);
CREATE INDEX idx_holds_stc ON inventory_holds(session_ticket_category_id);
CREATE INDEX idx_holds_expiry ON inventory_holds(expires_at) WHERE status = 'active';
CREATE INDEX idx_entry_attempts_ticket ON entry_attempts(ticket_id);
CREATE INDEX idx_entry_attempts_gate ON entry_attempts(gate_id);
CREATE INDEX idx_session_gates_session ON session_gates(session_id);
CREATE INDEX idx_waitlists_stc ON waitlists(session_ticket_category_id);
CREATE INDEX idx_gate_qr_tokens_gate_active ON gate_qr_tokens(gate_id, expires_at);

CREATE INDEX idx_org_members_org ON organization_members(organization_id);
CREATE INDEX idx_org_members_user ON organization_members(user_id);
CREATE INDEX idx_org_members_role ON organization_members(role_id);
CREATE INDEX idx_roles_org ON roles(organization_id);
CREATE INDEX idx_invitations_org ON organization_invitations(organization_id);
CREATE INDEX idx_invitations_email ON organization_invitations(email);
CREATE INDEX idx_events_organization ON events(organization_id);
CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_user_id);
CREATE INDEX idx_payouts_org ON payouts(organization_id);
CREATE INDEX idx_refunds_booking ON refunds(booking_id);
CREATE INDEX idx_verification_tokens_user ON verification_tokens(user_id);
CREATE INDEX idx_verification_tokens_type ON verification_tokens(token_type);

CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);
CREATE INDEX idx_fee_plans_org ON organization_fee_plans(organization_id);
CREATE INDEX idx_fraud_signals_user ON fraud_signals(user_id);
CREATE INDEX idx_platform_admins_user ON platform_admins(user_id);
CREATE INDEX idx_user_consents_user ON user_consents(user_id);
CREATE INDEX idx_event_changes_event ON event_changes(event_id);
CREATE INDEX idx_event_changes_session ON event_changes(session_id);
CREATE INDEX idx_deletion_requests_user ON data_deletion_requests(user_id);

-- =====================================================================
-- EXECUTION ORDER NOTE
-- Some tables reference forward (e.g. organization_member_event_scopes
-- references events, platform_admins is referenced by
-- data_deletion_requests). This file adds those foreign keys via ALTER
-- TABLE immediately after the referenced table is defined, so running it
-- top-to-bottom in a single transaction works correctly in Postgres.
-- =====================================================================
