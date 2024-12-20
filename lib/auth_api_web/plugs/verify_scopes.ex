defmodule AuthApiWeb.Plugs.VerifyScopes do
  import Plug.Conn
  alias AuthApi.OAuth

  def init(opts), do: opts

  def call(conn, required_scope) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, token_record} <- OAuth.get_token(token),
         true <- has_required_scope?(token_record, required_scope) do
      conn |> assign(:current_token, token_record)
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "invalid_token"})
        |> halt()
    end
  end

  defp has_required_scope?(token, required_scope) do
    case token.scopes do
      nil -> false
      scopes -> String.contains?(scopes, required_scope)
    end
  end
end
