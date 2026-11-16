from alembic import context


connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Run migrations through the local CLI with an explicit database.")
context.configure(connection=connection, target_metadata=None, render_as_batch=True)
with context.begin_transaction():
    context.run_migrations()
