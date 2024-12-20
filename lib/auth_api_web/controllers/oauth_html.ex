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
      <h2>Authorize Application</h2>

      <div class="app-info">
        <p>The application "<%= @application.name %>" would like to access your account.</p>
      </div>

      <div class="actions">
        <form action="/oauth/authorize" method="post" id="auth-form">
          <input type="hidden" name="_csrf_token" value={get_csrf_token()}>
          <input type="hidden" name="client_id" value={@application.client_id}>
          <input type="hidden" name="state" value={state}>
          <input type="hidden" name="redirect_uri" value={@application.redirect_uri}>
          <input type="hidden" name="code_challenge" value={code_challenge}>
          <input type="hidden" name="scope" value={Enum.join(@scopes, " ")}>

          <div class="buttons">
            <button type="submit" name="action" value="authorize" class="button primary">
              Authorize
            </button>
            <button type="submit" name="action" value="deny" class="button secondary">
              Deny
            </button>
          </div>
        </form>
      </div>

      <style>
        .auth-container {
          max-width: 600px;
          margin: 2rem auto;
          padding: 2rem;
          border: 1px solid #ddd;
          border-radius: 8px;
        }
        .app-info { margin: 1rem 0; }
        .buttons {
          display: flex;
          gap: 1rem;
          margin-top: 1rem;
        }
        .button {
          padding: 0.5rem 1rem;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        .primary {
          background: #4CAF50;
          color: white;
        }
        .secondary {
          background: #f44336;
          color: white;
        }
      </style>
    </div>
    """
  end
end
