-- Remove Casbin rules for command management endpoints
DELETE FROM public.casbin_rule
WHERE (ptype = 'p' AND v0 = 'group_user' AND v1 LIKE '/api/v1/commands%')
   OR (ptype = 'p' AND v0 = 'group_admin' AND v1 LIKE '/api/v1/commands%');
