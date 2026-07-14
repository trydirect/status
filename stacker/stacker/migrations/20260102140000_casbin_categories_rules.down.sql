-- Rollback: Remove Casbin rules for Categories endpoint

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' AND v1 = '/api/categories' AND v2 = 'GET';
