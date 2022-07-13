pub fn ticker_validator(name: &str) -> Result<(), String> {
    if name.len() < 3 || name.len() > 8 || name.chars().any(|c| c < 'A' && c > 'Z') {
        Err(
            "Ticker name must be between 3 and 8 chars, contain no spaces and \
            consist only of capital letters\
            "
            .to_string(),
        )
    } else {
        Ok(())
    }
}
