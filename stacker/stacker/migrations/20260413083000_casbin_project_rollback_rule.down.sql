DELETE FROM public.casbin_rule
WHERE (ptype, v0, v1, v2, v3, v4, v5) IN (
    ('p', 'group_user', '/project/:id/rollback', 'POST', '', '', ''),
    ('p', 'client', '/project/:id/rollback', 'POST', '', '', '')
);
