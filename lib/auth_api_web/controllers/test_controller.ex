defmodule AuthApiWeb.TestController do
  use AuthApiWeb, :controller

  def public(conn, _params) do
    json(conn, %{message: "This is public endpoint"})
  end

  def read_only(conn, _params) do
    json(conn, %{
      message: "This is read-only endpoint",
      token: conn.assigns.current_token
    })
  end

  def write_access(conn, _params) do
    json(conn, %{
      message: "This is write-access endpoint",
      token: conn.assigns.current_token
    })
  end
end
