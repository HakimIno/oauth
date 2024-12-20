defmodule AuthApi.OAuth.AccessTokenScope do
  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_access_token_scopes" do
    belongs_to :access_token, AuthApi.OAuth.AccessToken
    belongs_to :scope, AuthApi.OAuth.Scope

    timestamps()
  end

  def changeset(access_token_scope, attrs) do
    access_token_scope
    |> cast(attrs, [:access_token_id, :scope_id])
    |> validate_required([:access_token_id, :scope_id])
    |> foreign_key_constraint(:access_token_id)
    |> foreign_key_constraint(:scope_id)
  end
end
