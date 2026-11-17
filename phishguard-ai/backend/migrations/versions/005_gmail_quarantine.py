"""gmail quarantine tracking, labels, and consent settings

Revision ID: 005_gmail_quarantine
Revises: 004_gmail_realtime_watch
Create Date: 2026-11-17 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '005_gmail_quarantine'
down_revision: Union[str, None] = '004_gmail_realtime_watch'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'gmail_integrations' in tables:
        columns = [c['name'] for c in inspector.get_columns('gmail_integrations')]
        if 'auto_quarantine_enabled' not in columns:
            op.add_column(
                'gmail_integrations',
                sa.Column('auto_quarantine_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False)
            )
        if 'quarantine_consent_given_at' not in columns:
            op.add_column(
                'gmail_integrations',
                sa.Column('quarantine_consent_given_at', sa.DateTime(timezone=True), nullable=True)
            )
        if 'quarantine_threshold_score' not in columns:
            op.add_column(
                'gmail_integrations',
                sa.Column('quarantine_threshold_score', sa.Integer(), server_default='70', nullable=False)
            )
        if 'quarantine_label_name' not in columns:
            op.add_column(
                'gmail_integrations',
                sa.Column('quarantine_label_name', sa.String(length=100), server_default='PhishGuard-Quarantine', nullable=False)
            )
        if 'quarantine_label_id' not in columns:
            op.add_column(
                'gmail_integrations',
                sa.Column('quarantine_label_id', sa.String(length=100), nullable=True)
            )

    if 'gmail_messages' in tables:
        columns = [c['name'] for c in inspector.get_columns('gmail_messages')]
        if 'is_quarantined' not in columns:
            op.add_column(
                'gmail_messages',
                sa.Column('is_quarantined', sa.Boolean(), server_default=sa.text('false'), nullable=False)
            )
        if 'quarantined_at' not in columns:
            op.add_column(
                'gmail_messages',
                sa.Column('quarantined_at', sa.DateTime(timezone=True), nullable=True)
            )
        if 'quarantine_reason' not in columns:
            op.add_column(
                'gmail_messages',
                sa.Column('quarantine_reason', sa.Text(), nullable=True)
            )
        if 'original_labels' not in columns:
            json_type = postgresql.JSONB(astext_type=sa.Text()) if bind.dialect.name == 'postgresql' else sa.JSON()
            op.add_column(
                'gmail_messages',
                sa.Column('original_labels', json_type, nullable=True)
            )
        if 'restored_at' not in columns:
            op.add_column(
                'gmail_messages',
                sa.Column('restored_at', sa.DateTime(timezone=True), nullable=True)
            )
        if 'restored_by' not in columns:
            uuid_type = postgresql.UUID(as_uuid=True) if bind.dialect.name == 'postgresql' else sa.CHAR(36)
            op.add_column(
                'gmail_messages',
                sa.Column('restored_by', uuid_type, nullable=True)
            )
        if 'quarantine_action_status' not in columns:
            op.add_column(
                'gmail_messages',
                sa.Column('quarantine_action_status', sa.String(length=50), server_default='none', nullable=False)
            )
        if 'quarantine_error' not in columns:
            op.add_column(
                'gmail_messages',
                sa.Column('quarantine_error', sa.Text(), nullable=True)
            )


def downgrade() -> None:
    pass
