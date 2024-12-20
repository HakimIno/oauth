defmodule AuthApi.Repo.Migrations.AddScopesToAccessTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_access_tokens) do
      add :scopes, :string
    end
  end
end
