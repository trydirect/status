INSERT INTO agreement (id, name, text, created_at, updated_at)
VALUES (
    1,
    'Terms of Service',
    'By using the TryDirect Stacker platform you agree to our Terms of Service and Privacy Policy available at https://try.direct/terms',
    NOW() AT TIME ZONE 'utc',
    NOW() AT TIME ZONE 'utc'
)
ON CONFLICT (id) DO NOTHING;

SELECT setval(pg_get_serial_sequence('agreement', 'id'), GREATEST(1, (SELECT MAX(id) FROM agreement)));
