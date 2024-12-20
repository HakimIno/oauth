defmodule AuthApi.OAuth.AccessToken do
  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_access_tokens" do
    field :token, :string
    field :expires_at, :naive_datetime
    field :scopes, :string
    belongs_to :application, AuthApi.OAuth.Application

    timestamps()
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:token, :expires_at, :scopes, :application_id])
    |> validate_required([:token, :expires_at, :application_id])
  end
end
