-- Remove Casbin ACL rules for /api/v1/agent/commands/enqueue endpoint

DELETE FROM public.casbin_rule 
WHERE ptype='p' AND v1='/api/v1/agent/commands/enqueue' AND v2='POST';
