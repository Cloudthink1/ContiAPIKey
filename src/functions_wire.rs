use serde_json::{Value, json};

/// Extract the standard function declarations understood by both upstream protocols.
pub fn definitions(request: &Value) -> impl Iterator<Item = Value> + '_ {
    request["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|tool| tool["type"] == "function" && tool["name"].as_str().is_some())
        .map(|tool| {
            json!({"type":"function", "name":tool["name"],
                "description":tool["description"].as_str().unwrap_or_default(),
                "parameters":tool["parameters"], "strict": false})
        })
}

pub fn output_text(output: &Value) -> Option<String> {
    if let Some(text) = output.as_str() {
        return Some(text.to_owned());
    }
    let parts: Option<Vec<_>> = output
        .as_array()?
        .iter()
        .map(|part| part["text"].as_str())
        .collect();
    Some(parts?.join("\n"))
}
