-- Add up migration script here

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/agreement', 'GET', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/agreement/:id', 'GET', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/agreement', 'GET', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/agreement/:id', 'GET', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/admin/agreement', 'POST', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/admin/agreement/:id', 'GET', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/admin/agreement/:id', 'POST', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/admin/agreement/:id', 'PUT', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/admin/agreement/:id', 'DELETE', '', '', '');
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/agreement', 'POST', '', '', '');
