-- Remove Casbin rules for server endpoints

DELETE FROM public.casbin_rule 
WHERE v1 LIKE '/server%' 
  AND v0 IN ('group_user', 'root');
