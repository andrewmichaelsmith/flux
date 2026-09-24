

# --- Rails `config/initializers/<service>.rb` -------------------------
# A Rails app keeps one initializer per third-party integration, and the
# integration's API key is the thing the initializer exists to set. A
# harvester dictionary that walks this directory is therefore not asking
# "is this Rails?" — it already knows — it is asking *which vendor's key
# is in this app*, one filename per vendor.
#
# That makes the directory the one place where answering per-file, rather
# than per-family, buys a measurement nothing else gives: each initializer
# is its own result tag, so which services a source asks for, and which it
# takes and then stops at, is countable. A sweep that reads `stripe.rb`
# and leaves is shopping for payment keys; one that walks the whole
# directory is bulk-harvesting.
#
# Two legs carry a real Tracebit AWS canary, because those two are the
# ones where a real Rails app genuinely holds AWS keys: `aws.rb` (the SDK
# client) and `carrierwave.rb` (fog/S3 upload storage). The rest have no
# matching canary type, so they mint per-hit synthetics in the vendor's
# own key format — never a fixed literal, which would fingerprint the
# fleet and detect nothing on replay.

def _stripe_secret_key() -> str:
    return "sk_live_" + secrets.token_hex(12) + secrets.token_hex(12)[:8]


def _sendgrid_api_key() -> str:
    # SG.<22-char key id>.<43-char secret>
    return (
        "SG."
        + secrets.token_urlsafe(17)[:22]
        + "."
        + secrets.token_urlsafe(33)[:43]
    )


def _twilio_sid() -> str:
    return "AC" + secrets.token_hex(16)


def _rails_initializer_header(filename: str) -> str:
    return f"# config/initializers/{filename}\n# frozen_string_literal: true\n\n"


def render_rails_initializer_stripe(r: dict[str, object]) -> bytes:
    """`config/initializers/stripe.rb` — Stripe SDK bootstrap. The
    live secret key is the whole point of the file; the publishable
    key and webhook signing secret sit beside it in every real
    install. All three per-hit unique, in Stripe's own key formats,
    so a harvester that greps for `sk_live_` finds one."""
    del r
    return (
        _rails_initializer_header("stripe.rb")
        + "Rails.configuration.stripe = {\n"
        f"  publishable_key: '{'pk_live_' + secrets.token_hex(12)}',\n"
        f"  secret_key: '{_stripe_secret_key()}',\n"
        f"  signing_secret: '{'whsec_' + secrets.token_urlsafe(24)[:32]}'\n"
        "}\n"
        "\n"
        "Stripe.api_key = Rails.configuration.stripe[:secret_key]\n"
        "Stripe.api_version = '2023-10-16'\n"
    ).encode("utf-8")


def render_rails_initializer_sendgrid(r: dict[str, object]) -> bytes:
    """`config/initializers/sendgrid.rb` — ActionMailer SMTP via
    SendGrid. Real installs set `user_name: 'apikey'` and put the
    `SG.`-prefixed key in `password`, which is why a mail-credential
    harvester probes this filename specifically."""
    del r
    host = str(r.get("_requestHost") or "") if isinstance(r, dict) else ""
    domain = host.split(":")[0] or "example.com"
    return (
        _rails_initializer_header("sendgrid.rb")
        + "ActionMailer::Base.smtp_settings = {\n"
        "  address: 'smtp.sendgrid.net',\n"
        "  port: 587,\n"
        "  authentication: :plain,\n"
        "  user_name: 'apikey',\n"
        f"  password: '{_sendgrid_api_key()}',\n"
        f"  domain: '{domain}',\n"
        "  enable_starttls_auto: true\n"
        "}\n"
    ).encode("utf-8")


def render_rails_initializer_twilio(r: dict[str, object]) -> bytes:
    """`config/initializers/twilio.rb` — Twilio REST client. The
    account SID and auth token are a complete credential pair: they
    authenticate the REST API directly, which is why SMS-fraud
    tooling walks this file."""
    del r
    return (
        _rails_initializer_header("twilio.rb")
        + "Twilio.configure do |config|\n"
        f"  config.account_sid = '{_twilio_sid()}'\n"
        f"  config.auth_token = '{secrets.token_hex(16)}'\n"
        "end\n"
        "\n"
        "TWILIO_FROM_NUMBER = '+15005550006'\n"
    ).encode("utf-8")


def render_rails_initializer_aws(r: dict[str, object]) -> bytes:
    """`config/initializers/aws.rb` — Aws::Config bootstrap. This is
    one of the two initializers where a real Rails app genuinely holds
    AWS keys, so it carries a live Tracebit canary rather than a
    synthetic: a replay against STS is attributable back to this
    request."""
    aws = _aws(r)
    return (
        _rails_initializer_header("aws.rb")
        + "Aws.config.update(\n"
        "  region: 'us-east-1',\n"
        "  credentials: Aws::Credentials.new(\n"
        f"    '{aws.get('awsAccessKeyId', '')}',\n"
        f"    '{aws.get('awsSecretAccessKey', '')}',\n"
        f"    '{aws.get('awsSessionToken', '')}'\n"
        "  )\n"
        ")\n"
        "\n"
        "S3_BUCKET = Aws::S3::Resource.new.bucket('app-prod-uploads')\n"
    ).encode("utf-8")


def render_rails_initializer_carrierwave(r: dict[str, object]) -> bytes:
    """`config/initializers/carrierwave.rb` — CarrierWave fog/S3
    storage. The second initializer that legitimately holds AWS keys
    (`fog_credentials`), so it too carries a live canary."""
    aws = _aws(r)
    return (
        _rails_initializer_header("carrierwave.rb")
        + "CarrierWave.configure do |config|\n"
        "  config.fog_provider = 'fog/aws'\n"
        "  config.fog_credentials = {\n"
        "    provider: 'AWS',\n"
        f"    aws_access_key_id: '{aws.get('awsAccessKeyId', '')}',\n"
        f"    aws_secret_access_key: '{aws.get('awsSecretAccessKey', '')}',\n"
        f"    aws_session_token: '{aws.get('awsSessionToken', '')}',\n"
        "    region: 'us-east-1'\n"
        "  }\n"
        "  config.fog_directory = 'app-prod-uploads'\n"
        "  config.storage = :fog\n"
        "end\n"
    ).encode("utf-8")


def render_rails_initializer_devise(r: dict[str, object]) -> bytes:
    """`config/initializers/devise.rb` — Devise authentication. The
    `secret_key` and `pepper` are what sign Devise's reset/confirm
    tokens, so a leak is an account-takeover primitive rather than a
    third-party key. Per-hit unique 128-hex, the real shape."""
    del r
    return (
        _rails_initializer_header("devise.rb")
        + "Devise.setup do |config|\n"
        f"  config.secret_key = '{secrets.token_hex(64)}'\n"
        f"  config.pepper = '{secrets.token_hex(64)}'\n"
        "  config.mailer_sender = 'no-reply@example.com'\n"
        "  config.stretches = Rails.env.test? ? 1 : 12\n"
        "  config.reconfirmable = true\n"
        "  config.password_length = 8..128\n"
        "end\n"
    ).encode("utf-8")


def render_rails_initializer_omniauth(r: dict[str, object]) -> bytes:
    """`config/initializers/omniauth.rb` — OAuth provider client
    secrets. Checked-in secrets here are per-provider, so the file
    states which identity providers the app federates with as well
    as handing over the secrets themselves."""
    del r
    return (
        _rails_initializer_header("omniauth.rb")
        + "Rails.application.config.middleware.use OmniAuth::Builder do\n"
        "  provider :google_oauth2,\n"
        f"           '{secrets.token_hex(12)}.apps.googleusercontent.com',\n"
        f"           '{'GOCSPX-' + secrets.token_urlsafe(20)[:28]}',\n"
        "           { scope: 'email,profile', prompt: 'select_account' }\n"
        "\n"
        "  provider :github,\n"
        f"           '{'Iv1.' + secrets.token_hex(8)}',\n"
        f"           '{secrets.token_hex(20)}',\n"
        "           scope: 'user:email'\n"
        "end\n"
    ).encode("utf-8")


def render_rails_initializer_smtp(r: dict[str, object]) -> bytes:
    """`config/initializers/smtp_settings.rb` — generic ActionMailer
    SMTP block. Distinct from the SendGrid leg: this is the
    self-hosted / SES-relay spelling, so the credential is a plain
    user/password pair rather than a vendor API key."""
    host = str(r.get("_requestHost") or "") if isinstance(r, dict) else ""
    domain = host.split(":")[0] or "example.com"
    return (
        _rails_initializer_header("smtp_settings.rb")
        + "ActionMailer::Base.delivery_method = :smtp\n"
        "ActionMailer::Base.smtp_settings = {\n"
        "  address: 'email-smtp.us-east-1.amazonaws.com',\n"
        "  port: 587,\n"
        f"  domain: '{domain}',\n"
        f"  user_name: '{'AKIA' + secrets.token_hex(8).upper()}',\n"
        f"  password: '{_fake_db_password()}',\n"
        "  authentication: 'login',\n"
        "  enable_starttls_auto: true\n"
        "}\n"
    ).encode("utf-8")


def render_rails_initializer_secret_token(r: dict[str, object]) -> bytes:
    """`config/initializers/secret_token.rb` — the Rails 3 / early-4
    session signing key, superseded by `secrets.yml` and then by
    `credentials.yml.enc`. Still probed because the apps that leak it
    are the unmaintained ones, and on Rails 3 the same value is the
    published deserialisation-RCE primitive (CVE-2013-0156 family),
    not just cookie forgery."""
    del r
    return (
        _rails_initializer_header("secret_token.rb")
        + "# Your secret key for verifying the integrity of signed cookies.\n"
        "# If you change this key, all old signed cookies will become invalid!\n"
        "# Make sure the secret is at least 30 characters and all random,\n"
        "# no regular words or you'll be exposed to dictionary attacks.\n"
        f"AppName::Application.config.secret_token = '{secrets.token_hex(64)}'\n"
        f"AppName::Application.config.secret_key_base = '{secrets.token_hex(64)}'\n"
    ).encode("utf-8")


def render_airflow_cfg(r: dict[str, object]) -> bytes:
    """`airflow.cfg` — Apache Airflow's main config. Three separate
    credential slots in one file, which is why a config harvester
    keeps it in the dictionary: `sql_alchemy_conn` is a full DB URI
    with the password inline, `fernet_key` decrypts every stored
    Connection secret in that database, and the webserver
    `secret_key` signs the Flask session — forging one lands an
    authenticated Airflow UI, where a DAG is arbitrary code
    execution. AWS canary in the remote-logging block, which is
    where a real deployment puts its S3 credentials."""
    aws = _aws(r)
    db_password = _fake_db_password()
    return (
        "[core]\n"
        "dags_folder = /opt/airflow/dags\n"
        "executor = CeleryExecutor\n"
        "load_examples = False\n"
        f"fernet_key = {base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii')}\n"
        "\n"
        "[database]\n"
        f"sql_alchemy_conn = postgresql+psycopg2://airflow:{db_password}@db.internal:5432/airflow\n"
        "sql_alchemy_pool_size = 5\n"
        "\n"
        "[celery]\n"
        f"broker_url = redis://:{_fake_db_password()}@redis.internal:6379/0\n"
        f"result_backend = db+postgresql://airflow:{db_password}@db.internal:5432/airflow\n"
        "\n"
        "[webserver]\n"
        "base_url = http://localhost:8080\n"
        f"secret_key = {secrets.token_hex(16)}\n"
        "expose_config = True\n"
        "\n"
        "[logging]\n"
        "remote_logging = True\n"
        "remote_base_log_folder = s3://app-prod-airflow-logs/logs\n"
        "remote_log_conn_id = aws_default\n"
        "\n"
        "[aws]\n"
        f"aws_access_key_id = {aws.get('awsAccessKeyId', '')}\n"
        f"aws_secret_access_key = {aws.get('awsSecretAccessKey', '')}\n"
        f"aws_session_token = {aws.get('awsSessionToken', '')}\n"
        "region_name = us-east-1\n"
        "\n"
        "[smtp]\n"
        "smtp_host = email-smtp.us-east-1.amazonaws.com\n"
        "smtp_starttls = True\n"
        "smtp_port = 587\n"
        f"smtp_user = {'AKIA' + secrets.token_hex(8).upper()}\n"
        f"smtp_password = {_fake_db_password()}\n"
    ).encode("utf-8")
