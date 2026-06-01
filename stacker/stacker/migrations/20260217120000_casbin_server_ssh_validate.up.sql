-- Add missing Casbin rule for SSH key validate endpoint
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/server/:id/ssh-key/validate', 'POST', '', '', ''),
    ('p', 'root', '/server/:id/ssh-key/validate', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
