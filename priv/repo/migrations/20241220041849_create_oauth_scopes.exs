defmodule AuthApi.Repo.Migrations.CreateOauthScopes do
  use Ecto.Migration

  def change do
    # สร้างตาราง scopes
    create table(:oauth_scopes) do
      add :name, :string, null: false
      add :description, :string

      timestamps()
    end

    create unique_index(:oauth_scopes, [:name])

    # สร้างตาราง join สำหรับ many_to_many relationship
    create table(:oauth_access_token_scopes, primary_key: false) do
      add :access_token_id, references(:oauth_access_tokens, on_delete: :delete_all), null: false
      add :scope_id, references(:oauth_scopes, on_delete: :delete_all), null: false

      timestamps()
    end

    create unique_index(:oauth_access_token_scopes, [:access_token_id, :scope_id])
  end

  def down do
    drop table(:oauth_access_token_scopes)
    drop table(:oauth_scopes)
  end
end
