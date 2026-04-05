"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── ENUMS ────────────────────────────────────────────────────────────────
    op.execute("CREATE TYPE security_role AS ENUM ('admin','analyst','junior_analyst','tprm_manager','read_only')")
    op.execute("CREATE TYPE scan_status AS ENUM ('pending','running','completed','failed','cancelled')")
    op.execute("CREATE TYPE scan_type AS ENUM ('nmap','nuclei','nikto','sslscan','subdomain','dns','headers','masscan','whatweb','wpscan','sqlmap','gobuster','wfuzz','zaproxy','hydra','hashcat','lynis','full','custom')")
    op.execute("CREATE TYPE severity_level AS ENUM ('critical','high','medium','low','info')")
    op.execute("CREATE TYPE finding_status AS ENUM ('open','in_remediation','resolved','accepted_risk','false_positive')")
    op.execute("CREATE TYPE risk_tier AS ENUM ('critical','high','medium','low')")

    # ── ORGANIZATIONS ────────────────────────────────────────────────────────
    op.create_table('organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False, unique=True),
        sa.Column('plan', sa.String(50), server_default='community'),
        sa.Column('stripe_customer_id', sa.String(255)),
        sa.Column('stripe_subscription_id', sa.String(255)),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── USERS ────────────────────────────────────────────────────────────────
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(500), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=False),
        sa.Column('role', sa.String(50), server_default='read_only'),
        sa.Column('is_active', sa.Boolean, server_default='TRUE'),
        sa.Column('last_login', sa.TIMESTAMP(timezone=True)),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── ASSETS ───────────────────────────────────────────────────────────────
    op.create_table('assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255)),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(500), nullable=False),
        sa.Column('os', sa.String(255)),
        sa.Column('os_version', sa.String(100)),
        sa.Column('tags', postgresql.ARRAY(sa.Text), server_default='{}'),
        sa.Column('is_active', sa.Boolean, server_default='TRUE'),
        sa.Column('metadata', postgresql.JSONB, server_default='{}'),
        sa.Column('last_scanned_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.UniqueConstraint('org_id', 'value', name='uq_assets_org_value'),
    )

    # ── SCAN JOBS ─────────────────────────────────────────────────────────────
    op.create_table('scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='SET NULL')),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), server_default='pending'),
        sa.Column('celery_task_id', sa.String(255)),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('options', postgresql.JSONB, server_default='{}'),
        sa.Column('initiated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('started_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('completed_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('error_message', sa.Text),
        sa.Column('raw_output', sa.Text),
        sa.Column('findings_count', sa.Integer, server_default='0'),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── FINDINGS ─────────────────────────────────────────────────────────────
    op.create_table('findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id', ondelete='SET NULL')),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('cvss_score', sa.Numeric(4, 1)),
        sa.Column('cve_id', sa.String(50)),
        sa.Column('cwe_id', sa.String(50)),
        sa.Column('affected_component', sa.String(500)),
        sa.Column('affected_port', sa.Integer),
        sa.Column('affected_service', sa.String(100)),
        sa.Column('remediation', sa.Text),
        sa.Column('references', postgresql.ARRAY(sa.Text), server_default='{}'),
        sa.Column('raw_output', sa.Text),
        sa.Column('status', sa.String(50), server_default='open'),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('first_seen_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('last_seen_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('resolved_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('sla_due_date', sa.TIMESTAMP(timezone=True)),
        sa.Column('is_known_exploited', sa.Boolean, server_default='FALSE'),
        sa.Column('exploit_available', sa.Boolean, server_default='FALSE'),
        sa.Column('mitre_technique', sa.String(50)),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── VENDORS (TPRM) ────────────────────────────────────────────────────────
    op.create_table('vendors',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('domain', sa.String(255)),
        sa.Column('contact_email', sa.String(255)),
        sa.Column('risk_tier', sa.String(50), server_default='medium'),
        sa.Column('technical_risk_score', sa.Numeric(5, 2)),
        sa.Column('last_assessed_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('metadata', postgresql.JSONB, server_default='{}'),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── REMEDIATION TASKS ─────────────────────────────────────────────────────
    op.create_table('remediation_tasks',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('due_date', sa.TIMESTAMP(timezone=True)),
        sa.Column('status', sa.String(50), server_default='open'),
        sa.Column('notes', sa.Text),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── WEBHOOKS ──────────────────────────────────────────────────────────────
    op.create_table('webhooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('secret', sa.String(255)),
        sa.Column('events', postgresql.ARRAY(sa.Text), server_default='{}'),
        sa.Column('is_active', sa.Boolean, server_default='TRUE'),
        sa.Column('last_triggered_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── API KEYS ──────────────────────────────────────────────────────────────
    op.create_table('api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_hash', sa.String(500), nullable=False),
        sa.Column('key_prefix', sa.String(20), nullable=False),
        sa.Column('permissions', postgresql.ARRAY(sa.Text), server_default='{}'),
        sa.Column('last_used_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('expires_at', sa.TIMESTAMP(timezone=True)),
        sa.Column('is_active', sa.Boolean, server_default='TRUE'),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('NOW()')),
    )

    # ── INDEXES ───────────────────────────────────────────────────────────────
    op.create_index('ix_assets_org_id', 'assets', ['org_id'])
    op.create_index('ix_assets_value', 'assets', ['value'])
    op.create_index('ix_scan_jobs_org_id', 'scan_jobs', ['org_id'])
    op.create_index('ix_scan_jobs_status', 'scan_jobs', ['status'])
    op.create_index('ix_scan_jobs_asset_id', 'scan_jobs', ['asset_id'])
    op.create_index('ix_findings_org_id', 'findings', ['org_id'])
    op.create_index('ix_findings_asset_id', 'findings', ['asset_id'])
    op.create_index('ix_findings_severity', 'findings', ['severity'])
    op.create_index('ix_findings_status', 'findings', ['status'])
    op.create_index('ix_findings_cve_id', 'findings', ['cve_id'])


def downgrade() -> None:
    op.drop_table('api_keys')
    op.drop_table('webhooks')
    op.drop_table('remediation_tasks')
    op.drop_table('vendors')
    op.drop_table('findings')
    op.drop_table('scan_jobs')
    op.drop_table('assets')
    op.drop_table('users')
    op.drop_table('organizations')
    op.execute("DROP TYPE IF EXISTS risk_tier")
    op.execute("DROP TYPE IF EXISTS finding_status")
    op.execute("DROP TYPE IF EXISTS severity_level")
    op.execute("DROP TYPE IF EXISTS scan_type")
    op.execute("DROP TYPE IF EXISTS scan_status")
    op.execute("DROP TYPE IF EXISTS security_role")
