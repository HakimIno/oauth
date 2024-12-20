defmodule AuthApiWeb.Plugs.RateLimit do
  import Plug.Conn

  @max_requests 100
  @time_window 60

  def init(opts), do: opts

  def call(conn, _opts) do
    client_ip = get_client_ip(conn)
    key = "rate_limit:#{client_ip}"

    case check_rate(key) do
      :ok ->
        conn

      :error ->
        conn
        |> put_status(:too_many_requests)
        |> put_resp_header("retry-after", "#{@time_window}")
        |> put_resp_content_type("application/json")
        |> send_resp(
          429,
          Jason.encode!(%{
            error: "rate_limit_exceeded",
            message: "Too many requests. Please try again later.",
            retry_after: @time_window
          })
        )
        |> halt()
    end
  end

  defp check_rate(key) do
    case Redix.pipeline(:redix, [
           ["GET", key],
           ["INCR", key],
           ["EXPIRE", key, @time_window]
         ]) do
      {:ok, [count, _incr, _expire]} ->
        if count && String.to_integer("#{count}") > @max_requests do
          :error
        else
          :ok
        end

      _ ->
        :ok
    end
  end

  defp get_client_ip(conn) do
    forwarded_for = get_req_header(conn, "x-forwarded-for")
    if forwarded_for != [], do: hd(forwarded_for), else: to_string(:inet.ntoa(conn.remote_ip))
  end
end
