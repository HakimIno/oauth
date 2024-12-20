defmodule AuthApiWeb.Plugs.VerifyScopes do
  import Plug.Conn
  import Phoenix.Controller

  def init(scope), do: scope

  def call(conn, required_scope) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, access_token} <- AuthApi.OAuth.verify_access_token(token),
         {:ok, true} <- AuthApi.OAuth.verify_token_scope(access_token, required_scope) do
      assign(conn, :current_token, access_token)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_scope"})
        |> halt()
    end
  end
end
