-- Add down migration script here

DELETE FROM public.casbin_rule where id IN (49,50,51,52,53,54,55,56,57,58);