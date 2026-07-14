INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/server/:id/cloud-firewall', 'POST', '', '', ''),
    ('p', 'group_admin', '/server/:id/cloud-firewall', 'POST', '', '', ''),
    ('p', 'root', '/server/:id/cloud-firewall', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
