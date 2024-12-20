defmodule AuthApi.OAuth.AccessToken do
  use Ecto.Schema
  import Ecto.Changeset

  @derive {Jason.Encoder, only: [:token, :expires_at]}
  schema "oauth_access_tokens" do
    field :token, :string
    field :expires_at, :naive_datetime
    field :scope_list, {:array, :string}, virtual: true
    belongs_to :application, AuthApi.OAuth.Application
    has_many :access_token_scopes, AuthApi.OAuth.AccessTokenScope
    has_many :scopes, through: [:access_token_scopes, :scope]

    timestamps()
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:token, :application_id, :expires_at, :scope_list])
    |> validate_required([:token, :application_id])
    |> foreign_key_constraint(:application_id)
    |> prepare_changes(fn changeset ->
      if get_change(changeset, :expires_at) do
        put_change(
          changeset,
          :expires_at,
          NaiveDateTime.truncate(get_change(changeset, :expires_at), :second)
        )
      else
        changeset
      end
    end)
  end

  defp put_expires_at(changeset) do
    case get_change(changeset, :expires_in) do
      nil ->
        changeset

      expires_in ->
        expires_at = NaiveDateTime.utc_now() |> NaiveDateTime.add(expires_in)
        put_change(changeset, :expires_at, expires_at)
    end
  end
end
