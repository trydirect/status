DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/chat/history';
