"""Add geo fields to access events

Revision ID: 4b7f2a1c0d8e
Revises: e3a1b7a2f1c0

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4b7f2a1c0d8e'
down_revision = 'e3a1b7a2f1c0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('access_events') as batch_op:
        batch_op.add_column(sa.Column('country', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('country_code', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('region', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('city', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('latitude', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('longitude', sa.Float(), nullable=True))


def downgrade():
    with op.batch_alter_table('access_events') as batch_op:
        batch_op.drop_column('longitude')
        batch_op.drop_column('latitude')
        batch_op.drop_column('city')
        batch_op.drop_column('region')
        batch_op.drop_column('country_code')
        batch_op.drop_column('country')
