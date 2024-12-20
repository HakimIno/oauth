defmodule AuthApi.Repo.Migrations.CreateOAuthApplications do
  use Ecto.Migration

  def change do
    create table(:oauth_applications) do
      add :name, :string, null: false
      add :client_id, :string, null: false
      add :client_secret, :string, null: false
      add :redirect_uri, :string, null: false
      add :user_id, references(:users), null: false

      timestamps()
    end

    create unique_index(:oauth_applications, [:client_id])
    create index(:oauth_applications, [:user_id])
  end
end
