DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/server/:id/ssh-key/validate'
  AND v2 = 'POST';
