"""Add client UID/login fields to user

Revision ID: 7b2a4d9e1f2c
Revises: 9f3a12c7b4d2

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7b2a4d9e1f2c'
down_revision = '9f3a12c7b4d2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.add_column(sa.Column('client_uid', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('last_login_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('last_login_ip', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('last_login_country', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('last_login_country_code', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_column('last_login_country_code')
        batch_op.drop_column('last_login_country')
        batch_op.drop_column('last_login_ip')
        batch_op.drop_column('last_login_at')
        batch_op.drop_column('client_uid')
