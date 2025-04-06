pub fn prompt_or_get(prompt: &str, arg: Option<&String>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(if let Some(val) = arg {
        val.clone()
    } else {
        inquire::Text::new(prompt).prompt()?
    })
}