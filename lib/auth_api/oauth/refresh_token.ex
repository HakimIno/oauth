defmodule AuthApi.OAuth.RefreshToken do
  use Ecto.Schema
  import Ecto.Changeset

  @derive {Jason.Encoder, only: [:token, :expires_at]}
  schema "oauth_refresh_tokens" do
    field :token, :string
    field :expires_at, :naive_datetime
    belongs_to :access_token, AuthApi.OAuth.AccessToken

    timestamps()
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:token, :access_token_id, :expires_at])
    |> validate_required([:token, :access_token_id])
    |> foreign_key_constraint(:access_token_id)
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
end
