defmodule AuthApiWeb.TestController do
  use AuthApiWeb, :controller

  def public(conn, _params) do
    json(conn, %{
      status: 200,
      scope: "public",
      data: %{message: "This is public endpoint"}
    })
  end

  def read_only(conn, _params) do
    json(conn, %{
      status: 200,
      scope: "read",
      data: %{
        message: "This is read only endpoint",
        token: conn.assigns.current_token.token
      }
    })
  end

  def write_access(conn, _params) do
    json(conn, %{
      status: 200,
      scope: "write",
      data: %{
        message: "This is write access endpoint",
        token: conn.assigns.current_token.token
      }
    })
  end
end
