DELETE FROM project_app
WHERE regexp_replace(lower(trim(both from trim(leading '/' from code))), '[-_]+', '_', 'g') = 'nginx_proxy_manager';
