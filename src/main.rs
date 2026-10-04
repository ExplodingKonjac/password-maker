mod crypto;
mod generator;
mod model;
mod storage;

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let window = AppWindow::new()?;
    window.run()?;
    Ok(())
}
