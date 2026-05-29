-- Add Casbin rules for project app CRUD and configuration endpoints
-- These routes were added via project_app table but never got Casbin policies

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    -- List apps in a project
    ('p', 'group_user', '/project/:id/apps', 'GET', '', '', ''),
    -- Create app in a project
    ('p', 'group_user', '/project/:id/apps', 'POST', '', '', ''),
    -- Get a specific app by code
    ('p', 'group_user', '/project/:id/apps/:code', 'GET', '', '', ''),
    -- Get app configuration
    ('p', 'group_user', '/project/:id/apps/:code/config', 'GET', '', '', ''),
    -- Get app environment variables
    ('p', 'group_user', '/project/:id/apps/:code/env', 'GET', '', '', ''),
    -- Update app environment variables
    ('p', 'group_user', '/project/:id/apps/:code/env', 'PUT', '', '', ''),
    -- Delete a specific environment variable
    ('p', 'group_user', '/project/:id/apps/:code/env/:name', 'DELETE', '', '', ''),
    -- Update app port mappings
    ('p', 'group_user', '/project/:id/apps/:code/ports', 'PUT', '', '', ''),
    -- Update app domain settings
    ('p', 'group_user', '/project/:id/apps/:code/domain', 'PUT', '', '', '')
ON CONFLICT DO NOTHING;
