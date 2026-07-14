-- Remove the inheritance edge if rolled back
DELETE FROM public.casbin_rule
WHERE ptype = 'g'
  AND v0 = 'group_admin'
  AND v1 = 'group_user'
  AND (v2 = '' OR v2 IS NULL)
  AND (v3 = '' OR v3 IS NULL)
  AND (v4 = '' OR v4 IS NULL)
  AND (v5 = '' OR v5 IS NULL);
