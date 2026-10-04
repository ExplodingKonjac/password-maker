use std::path::PathBuf;

use i_slint_backend_testing::{TestingBackend, TestingBackendOptions};
use slint::{ComponentHandle, ModelRc, PhysicalSize, VecModel};

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/password-maker-ui"));
    std::fs::create_dir_all(&destination)?;

    slint::platform::set_platform(Box::new(TestingBackend::new(TestingBackendOptions {
        renderer_name: Some("software".into()),
        ..Default::default()
    })))?;

    for (width, height) in [(1100, 720), (840, 600)] {
        for page in ["generator", "vault", "settings"] {
            let window = AppWindow::new()?;
            window.set_page(page.into());
            window.set_status("".into());
            window.set_keyword("personal-email".into());
            window.set_entry_label("Personal email".into());
            window.set_entries(ModelRc::new(VecModel::from(vec![
                EntryView {
                    id: "1".into(),
                    label: "Personal email".into(),
                    updated: "2026-10-04 10:00 UTC".into(),
                },
                EntryView {
                    id: "2".into(),
                    label: "A longer account label for checking layout".into(),
                    updated: "2026-10-04 10:00 UTC".into(),
                },
            ])));
            window.show()?;
            window.window().set_size(PhysicalSize::new(width, height));

            let snapshot = window.window().take_snapshot()?;
            let path = destination.join(format!("{page}-{width}x{height}.png"));
            image::save_buffer(
                &path,
                snapshot.as_bytes(),
                snapshot.width(),
                snapshot.height(),
                image::ColorType::Rgba8,
            )?;
            println!("{}", path.display());
            window.hide()?;
        }
    }

    Ok(())
}
