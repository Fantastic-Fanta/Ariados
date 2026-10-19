//! Optional LLM backend for `solve`.
//!
//! Decompiled or disassembled code is hard for people to read but something
//! LLMs are surprisingly good at, so `solve` can hand a crackme's check
//! function to a model and ask for the logic (and the key). This is strictly
//! opt-in: nothing is sent anywhere unless the user configures a provider, and
//! configuration comes only from the environment, never baked into the binary.
//!
//! Config (env, or a `.env` the CLI loads):
//!   LLM_PROVIDER   deepseek | openai | ollama | anthropic   (default: deepseek)
//!   LLM_MODEL      model name (provider-specific default otherwise)
//!   LLM_API_KEY    api key (or DEEPSEEK_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY)
//!   LLM_BASE_URL   override the endpoint (e.g. a local gateway)

use serde_json::{Value, json};

pub struct Provider {
    pub name: String,
    pub model: String,
    base_url: String,
    api_key: Option<String>,
}

impl Provider {
    /// Reads provider settings from the environment. Returns an error only if
    /// the chosen provider needs a key and none is set — so a misconfigured
    /// run fails with a clear message instead of a network error.
    pub fn from_env() -> Result<Provider, String> {
        let name = std::env::var("LLM_PROVIDER").unwrap_or_else(|_| "deepseek".into());
        let key_from = |names: &[&str]| names.iter().find_map(|n| std::env::var(n).ok());

        let (default_model, default_url, key) = match name.as_str() {
            "deepseek" => (
                "deepseek-chat",
                "https://api.deepseek.com/chat/completions",
                key_from(&["LLM_API_KEY", "DEEPSEEK_API_KEY"]),
            ),
            "openai" => (
                "gpt-4o-mini",
                "https://api.openai.com/v1/chat/completions",
                key_from(&["LLM_API_KEY", "OPENAI_API_KEY"]),
            ),
            "anthropic" => (
                "claude-opus-5-5",
                "https://api.anthropic.com/v1/messages",
                key_from(&["LLM_API_KEY", "ANTHROPIC_API_KEY"]),
            ),
            "ollama" => ("llama3.1", "http://localhost:11434/api/chat", None),
            other => return Err(format!("unknown LLM_PROVIDER '{other}'")),
        };

        if name != "ollama" && key.is_none() {
            return Err(format!(
                "{name} needs an API key; set LLM_API_KEY (or the provider's own var) in your environment or ~/Ariados/.env"
            ));
        }

        Ok(Provider {
            model: std::env::var("LLM_MODEL").unwrap_or_else(|_| default_model.to_string()),
            base_url: std::env::var("LLM_BASE_URL").unwrap_or_else(|_| default_url.to_string()),
            api_key: key,
            name,
        })
    }

    /// Sends a system+user prompt and returns the assistant's text.
    pub fn complete(&self, system: &str, user: &str) -> Result<String, String> {
        match self.name.as_str() {
            "anthropic" => self.anthropic(system, user),
            "ollama" => self.ollama(system, user),
            _ => self.openai_style(system, user),
        }
    }

    /// DeepSeek and OpenAI share the chat-completions schema.
    fn openai_style(&self, system: &str, user: &str) -> Result<String, String> {
        let body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "temperature": 0.2,
            "stream": false
        });
        let resp = self.post(
            &body,
            &[("Authorization", &format!("Bearer {}", self.key()?))],
        )?;
        resp["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("unexpected response: {resp}"))
    }

    fn anthropic(&self, system: &str, user: &str) -> Result<String, String> {
        let body = json!({
            "model": self.model,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": "user", "content": user}]
        });
        let resp = self.post(
            &body,
            &[
                ("x-api-key", &self.key()?),
                ("anthropic-version", "2023-06-01"),
            ],
        )?;
        resp["content"][0]["text"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("unexpected response: {resp}"))
    }

    fn ollama(&self, system: &str, user: &str) -> Result<String, String> {
        let body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": false
        });
        let resp = self.post(&body, &[])?;
        resp["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("unexpected response: {resp}"))
    }

    fn key(&self) -> Result<String, String> {
        self.api_key
            .clone()
            .ok_or_else(|| "missing API key".to_string())
    }

    fn post(&self, body: &Value, headers: &[(&str, &str)]) -> Result<Value, String> {
        let mut req = ureq::post(&self.base_url).header("Content-Type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut resp = req
            .send_json(body)
            .map_err(|e| format!("request failed: {e}"))?;
        resp.body_mut()
            .read_json::<Value>()
            .map_err(|e| format!("bad response body: {e}"))
    }
}

/// Loads `KEY=value` lines from a `.env` file into the process environment if
/// the variable isn't already set. Minimal and tolerant; comments and blanks
/// are skipped. Never logs values.
pub fn load_dotenv(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if std::env::var(k).is_err() {
                // SAFETY: single-threaded startup, before any threads spawn.
                unsafe { std::env::set_var(k, v) };
            }
        }
    }
}
