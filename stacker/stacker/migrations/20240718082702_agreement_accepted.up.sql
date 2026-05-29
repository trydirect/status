-- Add up migration script here
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/agreement/accepted/:id', 'GET', '', '', '');