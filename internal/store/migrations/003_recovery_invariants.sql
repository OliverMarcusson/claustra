CREATE UNIQUE INDEX IF NOT EXISTS recoveries_one_active_per_user
    ON recoveries(user_id)
    WHERE state IN ('link_sent', 'quarantine');
