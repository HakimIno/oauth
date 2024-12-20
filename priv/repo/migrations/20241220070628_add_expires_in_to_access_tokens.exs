defmodule AuthApi.Repo.Migrations.AddExpiresInToAccessTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_access_tokens) do
      add :expires_in, :integer
    end
  end
end
