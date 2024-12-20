defmodule AuthApi.Repo.Migrations.CreateOauthAccessTokens do
  use Ecto.Migration

  def change do
    create table(:oauth_access_tokens) do
      add :token, :string, null: false
      add :application_id, references(:oauth_applications, on_delete: :delete_all), null: false
      add :expires_at, :utc_datetime, null: false

      timestamps()
    end

    create unique_index(:oauth_access_tokens, [:token])
    create index(:oauth_access_tokens, [:application_id])
  end
end
