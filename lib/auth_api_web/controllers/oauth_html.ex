defmodule AuthApiWeb.OAuthHTML do
  use AuthApiWeb, :html
  require Logger

  def authorize(assigns) do
    session = assigns.conn.private.plug_session
    state = session["state"]
    code_challenge = session["code_challenge"]
    redirect_uri = session["redirect_uri"]

    Logger.info("""
    Template assigns:
      state: #{state}
      code_challenge: #{code_challenge}
      redirect_uri: #{redirect_uri}
    """)

    ~H"""
    <div class="auth-container">
      <div class="auth-card">
        <div class="app-logo">
          <!-- แทนที่ด้วย logo จริงของแอพ -->
          <svg class="logo-placeholder" viewBox="0 0 24 24">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
          </svg>
        </div>

        <h1 class="title">Sign in</h1>
        <p class="subtitle">to continue to <strong><%= @application.name %></strong></p>

        <div class="auth-content">
          <p class="permission-text">This application will be able to:</p>
          <ul class="permission-list">
            <%= for scope <- @scopes do %>
              <li><%= scope %></li>
            <% end %>
          </ul>
        </div>

        <form action="/oauth/authorize" method="post" id="auth-form">
          <input type="hidden" name="_csrf_token" value={get_csrf_token()}>
          <input type="hidden" name="client_id" value={@application.client_id}>
          <input type="hidden" name="state" value={state}>
          <input type="hidden" name="redirect_uri" value={@application.redirect_uri}>
          <input type="hidden" name="code_challenge" value={code_challenge}>
          <input type="hidden" name="scope" value={Enum.join(@scopes, " ")}>

          <div class="buttons">
            <button type="submit" name="action" value="deny" class="btn btn-cancel">
              Cancel
            </button>
            <button type="submit" name="action" value="authorize" class="btn btn-continue">
              Continue
            </button>
          </div>
        </form>

        <footer class="auth-footer">
          <p>This will redirect to <a href="#" class="link"><%= @application.redirect_uri %></a></p>
        </footer>
      </div>
    </div>
    """
  end
end
