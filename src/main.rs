#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod controller;
mod power;
slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .select()?;
    let window = AppWindow::new()?;
    let controller = controller::Controller::new(&window)?;
    let result = window.run();
    controller.shutdown();
    result?;
    Ok(())
}

#[cfg(test)]
mod ui_tests {
    #[test]
    fn accessible_window_initializes_headlessly() {
        i_slint_backend_testing::init_no_event_loop();
        let window = super::AppWindow::new().expect("window should initialize");
        assert_eq!(window.get_page().as_str(), "locked");
        assert!(!window.get_busy());
    }
}
