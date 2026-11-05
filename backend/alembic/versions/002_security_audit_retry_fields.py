"""security audit retry fields

Revision ID: 002_security_audit_retry_fields
Revises: 001_initial_schema
Create Date: 2026-11-05 04:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '002_security_audit_retry_fields'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new fields to analysis_jobs
    with op.batch_alter_table('analysis_jobs') as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'))
        batch_op.add_column(sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('locked_by', sa.String(length=128), nullable=True))
        batch_op.create_index('ix_analysis_jobs_user_id', ['user_id'])

    # Add hash chain fields to audit_events
    with op.batch_alter_table('audit_events') as batch_op:
        batch_op.add_column(sa.Column('sequence_number', sa.Integer(), nullable=False, server_default='1'))
        batch_op.add_column(sa.Column('prev_hash', sa.String(length=64), nullable=False, server_default='0'*64))
        batch_op.add_column(sa.Column('entry_hash', sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('audit_events') as batch_op:
        batch_op.drop_column('entry_hash')
        batch_op.drop_column('prev_hash')
        batch_op.drop_column('sequence_number')

    with op.batch_alter_table('analysis_jobs') as batch_op:
        batch_op.drop_index('ix_analysis_jobs_user_id')
        batch_op.drop_column('locked_by')
        batch_op.drop_column('locked_at')
        batch_op.drop_column('max_retries')
        batch_op.drop_column('retry_count')
        batch_op.drop_column('user_id')
