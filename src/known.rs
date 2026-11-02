//! Where well-known API keys are allowed to go, so most of them work through the proxy with
//! no setup. A key missing from this table simply asks the person for its host.

const HOSTS: &[(&str, &str)] = &[
    ("OPENAI_API_KEY", "api.openai.com"),
    ("ANTHROPIC_API_KEY", "api.anthropic.com"),
    ("GEMINI_API_KEY", "generativelanguage.googleapis.com"),
    ("GOOGLE_API_KEY", "generativelanguage.googleapis.com"),
    ("GROQ_API_KEY", "api.groq.com"),
    ("MISTRAL_API_KEY", "api.mistral.ai"),
    ("COHERE_API_KEY", "api.cohere.com"),
    ("XAI_API_KEY", "api.x.ai"),
    ("OPENROUTER_API_KEY", "openrouter.ai"),
    ("HUGGING_FACE_HUB_TOKEN", "huggingface.co"),
    ("HF_TOKEN", "huggingface.co"),
    ("STRIPE_SECRET_KEY", "api.stripe.com"),
    ("STRIPE_API_KEY", "api.stripe.com"),
    ("GITHUB_TOKEN", "api.github.com"),
    ("GH_TOKEN", "api.github.com"),
    ("CLOUDFLARE_API_TOKEN", "api.cloudflare.com"),
    ("VERCEL_TOKEN", "api.vercel.com"),
    ("RESEND_API_KEY", "api.resend.com"),
    ("SENDGRID_API_KEY", "api.sendgrid.com"),
    ("LINEAR_API_KEY", "api.linear.app"),
    ("NOTION_API_KEY", "api.notion.com"),
    ("SLACK_BOT_TOKEN", "slack.com"),
    ("REPLICATE_API_TOKEN", "api.replicate.com"),
    ("ELEVENLABS_API_KEY", "api.elevenlabs.io"),
];

/// Hosts a well-known variable may be sent to.
pub fn known_hosts(name: &str) -> Vec<String> {
    HOSTS.iter().filter(|(key, _)| *key == name).map(|(_, host)| (*host).to_owned()).collect()
}
