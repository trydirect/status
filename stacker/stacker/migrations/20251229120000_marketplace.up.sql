-- TryDirect Marketplace Schema Migration
-- Integrates with existing Product/Rating system

-- Ensure UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Categories (needed by templates)
CREATE TABLE IF NOT EXISTS stack_category (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

-- 2. Core marketplace table - templates become products when approved
CREATE TABLE IF NOT EXISTS stack_template (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_user_id VARCHAR(50) NOT NULL,
    creator_name VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    short_description TEXT,
    long_description TEXT,
    category_id INTEGER REFERENCES stack_category(id),
    tags JSONB DEFAULT '[]'::jsonb,
    tech_stack JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'draft' CHECK (
        status IN ('draft', 'submitted', 'under_review', 'approved', 'rejected', 'deprecated')
    ),
    is_configurable BOOLEAN DEFAULT true,
    view_count INTEGER DEFAULT 0,
    deploy_count INTEGER DEFAULT 0,
    product_id INTEGER, -- Links to product table when approved for ratings
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    approved_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_product FOREIGN KEY(product_id) REFERENCES product(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS stack_template_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES stack_template(id) ON DELETE CASCADE,
    version VARCHAR(20) NOT NULL,
    stack_definition JSONB NOT NULL,
    definition_format VARCHAR(20) DEFAULT 'yaml',
    changelog TEXT,
    is_latest BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(template_id, version)
);

CREATE TABLE IF NOT EXISTS stack_template_review (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES stack_template(id) ON DELETE CASCADE,
    reviewer_user_id VARCHAR(50),
    decision VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (
        decision IN ('pending', 'approved', 'rejected', 'needs_changes')
    ),
    review_reason TEXT,
    security_checklist JSONB DEFAULT '{
        "no_secrets": null,
        "no_hardcoded_creds": null,
        "valid_docker_syntax": null,
        "no_malicious_code": null
    }'::jsonb,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    reviewed_at TIMESTAMP WITH TIME ZONE
);

-- Extend existing tables
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'project' AND column_name = 'source_template_id'
    ) THEN
        ALTER TABLE project ADD COLUMN source_template_id UUID REFERENCES stack_template(id);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'project' AND column_name = 'template_version'
    ) THEN
        ALTER TABLE project ADD COLUMN template_version VARCHAR(20);
    END IF;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_stack_template_creator ON stack_template(creator_user_id);
CREATE INDEX IF NOT EXISTS idx_stack_template_status ON stack_template(status);
CREATE INDEX IF NOT EXISTS idx_stack_template_slug ON stack_template(slug);
CREATE INDEX IF NOT EXISTS idx_stack_template_category ON stack_template(category_id);
CREATE INDEX IF NOT EXISTS idx_stack_template_product ON stack_template(product_id);

CREATE INDEX IF NOT EXISTS idx_template_version_template ON stack_template_version(template_id);
CREATE INDEX IF NOT EXISTS idx_template_version_latest ON stack_template_version(template_id, is_latest) WHERE is_latest = true;

CREATE INDEX IF NOT EXISTS idx_review_template ON stack_template_review(template_id);
CREATE INDEX IF NOT EXISTS idx_review_decision ON stack_template_review(decision);

CREATE INDEX IF NOT EXISTS idx_project_source_template ON project(source_template_id);

-- Triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_stack_template_updated_at ON stack_template;
CREATE TRIGGER update_stack_template_updated_at
    BEFORE UPDATE ON stack_template
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to create product entry when template is approved
CREATE OR REPLACE FUNCTION create_product_for_approved_template()
RETURNS TRIGGER AS $$
DECLARE
    new_product_id INTEGER;
BEGIN
    -- When status changes to 'approved' and no product exists yet
    IF NEW.status = 'approved' AND OLD.status != 'approved' AND NEW.product_id IS NULL THEN
        -- Generate product_id from template UUID (use hashtext for deterministic integer)
        new_product_id := hashtext(NEW.id::text);
        
        -- Insert into product table
        INSERT INTO product (id, obj_id, obj_type, created_at, updated_at)
        VALUES (new_product_id, new_product_id, 'marketplace_template', now(), now())
        ON CONFLICT (id) DO NOTHING;
        
        -- Link template to product
        NEW.product_id := new_product_id;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS auto_create_product_on_approval ON stack_template;
CREATE TRIGGER auto_create_product_on_approval
    BEFORE UPDATE ON stack_template
    FOR EACH ROW 
    WHEN (NEW.status = 'approved' AND OLD.status != 'approved')
    EXECUTE FUNCTION create_product_for_approved_template();

-- Seed sample categories
INSERT INTO stack_category (name) 
VALUES 
    ('AI Agents'), 
    ('Data Pipelines'), 
    ('SaaS Starter'), 
    ('Dev Tools'),
    ('Automation')
ON CONFLICT DO NOTHING;

