ALTER TABLE stack_template
DROP CONSTRAINT IF EXISTS stack_template_status_check;

ALTER TABLE stack_template
ADD CONSTRAINT stack_template_status_check CHECK (
    status IN (
        'draft',
        'submitted',
        'under_review',
        'approved',
        'rejected',
        'deprecated'
    )
);
