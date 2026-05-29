-- Allow authenticated users and admins to access chat history endpoints

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
  ('p', 'group_user',  '/chat/history', 'GET',    '', '', ''),
  ('p', 'group_user',  '/chat/history', 'PUT',    '', '', ''),
  ('p', 'group_user',  '/chat/history', 'DELETE', '', '', ''),
  ('p', 'group_admin', '/chat/history', 'GET',    '', '', ''),
  ('p', 'group_admin', '/chat/history', 'PUT',    '', '', ''),
  ('p', 'group_admin', '/chat/history', 'DELETE', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
