DELETE FROM public.casbin_rule
WHERE ptype = 'g' AND v0 IN ('creator', 'vendor') AND v1 = 'group_user';
