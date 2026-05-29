CREATE TABLE IF NOT EXISTS marketplace_vendor_profile (
    creator_user_id VARCHAR(50) PRIMARY KEY,
    verification_status VARCHAR(50) NOT NULL DEFAULT 'unverified' CHECK (
        verification_status IN ('unverified', 'pending', 'verified', 'rejected')
    ),
    onboarding_status VARCHAR(50) NOT NULL DEFAULT 'not_started' CHECK (
        onboarding_status IN ('not_started', 'in_progress', 'completed')
    ),
    payouts_enabled BOOLEAN NOT NULL DEFAULT false,
    payout_provider VARCHAR(100),
    payout_account_ref VARCHAR(255),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
