ALTER TABLE webauthn_challenges DROP CONSTRAINT IF EXISTS webauthn_challenges_operation_check;
ALTER TABLE webauthn_challenges ADD CONSTRAINT webauthn_challenges_operation_check
    CHECK (operation IN ('register', 'login', 'reauth', 'add_passkey', 'recovery', 'delete_cancel'));
