-- Add up migration script here
ALTER TABLE public.agreement ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE public.agreement ALTER COLUMN created_at SET DEFAULT NOW();

ALTER TABLE public.agreement ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE public.agreement ALTER COLUMN updated_at SET DEFAULT NOW();
