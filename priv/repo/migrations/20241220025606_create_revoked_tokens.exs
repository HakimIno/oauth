defmodule AuthApi.Repo.Migrations.CreateRevokedTokens do
  use Ecto.Migration

  def change do
    create table(:oauth_revoked_tokens) do
      add :token, :string, null: false
      add :revoked_at, :utc_datetime, null: false
      add :reason, :string
      add :revoked_by_user_id, references(:users)

      timestamps()
    end

    create unique_index(:oauth_revoked_tokens, [:token])
    create index(:oauth_revoked_tokens, [:revoked_at])
  end
end
