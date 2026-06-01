-- Rollback: Remove root group from group_admin
DELETE FROM public.casbin_rule 
WHERE ptype = 'g' AND v0 = 'root' AND v1 = 'group_admin';
