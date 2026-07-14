-- Add Casbin rules for admin pricing PATCH endpoint
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'admin_service', '/api/admin/templates/:id/pricing', 'PATCH', '', '', ''),
    ('p', 'group_admin', '/api/admin/templates/:id/pricing', 'PATCH', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
