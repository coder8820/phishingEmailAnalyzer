"""gmail inbox retrieval, thread_id, label_ids and idempotency constraints

Revision ID: 003_gmail_inbox_retrieval
Revises: 002_google_oauth2_integration
Create Date: 2026-11-16 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '003_gmail_inbox_retrieval'
down_revision: Union[str, None] = '002_google_oauth2_integration'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'gmail_messages' in tables:
        columns = [c['name'] for c in inspector.get_columns('gmail_messages')]
        if 'thread_id' not in columns:
            op.add_column('gmail_messages', sa.Column('thread_id', sa.String(length=255), nullable=True))
        if 'label_ids' not in columns:
            op.add_column('gmail_messages', sa.Column('label_ids', postgresql.JSONB(), server_default='[]', nullable=True))
        if 'internal_date' not in columns:
            op.add_column('gmail_messages', sa.Column('internal_date', sa.DateTime(timezone=True), nullable=True))
        if 'error_message' not in columns:
            op.add_column('gmail_messages', sa.Column('error_message', sa.Text(), nullable=True))

        # Check existing constraints
        constraints = [c['name'] for c in inspector.get_unique_constraints('gmail_messages')]
        if 'uq_gmail_integration_msg' not in constraints:
            try:
                op.create_unique_constraint('uq_gmail_integration_msg', 'gmail_messages', ['integration_id', 'gmail_message_id'])
            except Exception:
                pass


def downgrade() -> None:
    pass
