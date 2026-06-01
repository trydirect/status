-- Add down migration script here
DELETE FROM public.casbin_rule where id IN (59);
