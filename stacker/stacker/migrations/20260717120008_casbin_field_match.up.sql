-- Add Casbin rules for field-match endpoint
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/v1/pipes/field-match', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/pipes/field-match', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
