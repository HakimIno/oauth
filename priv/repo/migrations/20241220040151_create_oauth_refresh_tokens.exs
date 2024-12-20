defmodule AuthApi.Repo.Migrations.CreateOauthRefreshTokens do
  use Ecto.Migration

  def change do
    create table(:oauth_refresh_tokens) do
      add :token, :string, null: false
      add :access_token_id, references(:oauth_access_tokens, on_delete: :delete_all), null: false
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime

      timestamps()
    end

    create unique_index(:oauth_refresh_tokens, [:token])
    create index(:oauth_refresh_tokens, [:access_token_id])
  end
end
