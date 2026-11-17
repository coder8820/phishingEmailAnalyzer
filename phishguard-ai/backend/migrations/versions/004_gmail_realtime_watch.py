"""gmail realtime watch status and pubsub notification tracking

Revision ID: 004_gmail_realtime_watch
Revises: 003_gmail_inbox_retrieval
Create Date: 2026-11-17 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '004_gmail_realtime_watch'
down_revision: Union[str, None] = '003_gmail_inbox_retrieval'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'gmail_integrations' in tables:
        columns = [c['name'] for c in inspector.get_columns('gmail_integrations')]
        if 'watch_status' not in columns:
            op.add_column(
                'gmail_integrations',
                sa.Column('watch_status', sa.String(length=50), server_default='inactive', nullable=False)
            )


def downgrade() -> None:
    pass
