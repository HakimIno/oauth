defmodule AuthApiWeb.PageController do
  use AuthApiWeb, :controller

  def oauth_test(conn, _params) do
    render(conn, :oauth_test)
  end

  def static_oauth_client(conn, _params) do
    conn
    |> put_resp_content_type("text/html")
    |> send_file(200, "priv/static/test/oauth_client.html")
  end
end
