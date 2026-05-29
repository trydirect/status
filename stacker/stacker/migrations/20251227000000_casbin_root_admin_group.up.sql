-- Add root group assigned to group_admin for external application access
-- Idempotent insert; ignore if the mapping already exists
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('g', 'root', 'group_admin', '', '', '', '')
ON CONFLICT DO NOTHING;
