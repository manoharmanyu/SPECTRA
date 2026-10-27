"""initial schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-27 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'device_sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('device_name', sa.String(length=255), nullable=True),
        sa.Column('device_fingerprint', sa.String(length=255), nullable=True),
        sa.Column('client_metadata', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'analysis_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('capture_session_id', sa.String(length=36), nullable=True),
        sa.Column('source_origin', sa.String(length=64), nullable=False),
        sa.Column('source_device_id', sa.String(length=255), nullable=True),
        sa.Column('client_captured_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('media_type', sa.String(length=32), nullable=False),
        sa.Column('detected_mime_type', sa.String(length=128), nullable=False),
        sa.Column('original_filename', sa.String(length=512), nullable=False),
        sa.Column('storage_key', sa.String(length=512), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('assessment_label', sa.String(length=64), nullable=True),
        sa.Column('assessment_score', sa.Float(), nullable=True),
        sa.Column('final_report', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['capture_session_id'], ['device_sessions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_analysis_jobs_sha256_hash', 'analysis_jobs', ['sha256_hash'])
    op.create_index('ix_analysis_jobs_status', 'analysis_jobs', ['status'])

    op.create_table(
        'analysis_stage_outputs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('stage_name', sa.String(length=64), nullable=False),
        sa.Column('output_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_analysis_stage_outputs_job_id', 'analysis_stage_outputs', ['job_id'])
    op.create_index('idx_job_stage', 'analysis_stage_outputs', ['job_id', 'stage_name'])

    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=True),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_events_job_id', 'audit_events', ['job_id'])


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('analysis_stage_outputs')
    op.drop_table('analysis_jobs')
    op.drop_table('device_sessions')
