use crate::ui::main_window::MainWindow;
use epaint::text::{FontData, FontDefinitions};
use std::sync::Arc;

mod ui;
mod utils;

fn load_fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "kaiti".to_owned(),
        Arc::from(FontData::from_owned(
            include_bytes!("assest/fonts/simkai.ttf").to_vec(),
        )),
    );
    fonts
        .families
        .get_mut(&epaint::text::FontFamily::Proportional)
        .unwrap()
        .push("kaiti".to_owned());
    fonts
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 450.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("assest/icons/icon.png"))
                    .expect("Failed to load icon"),
            ),
        ..Default::default()
    };
    eframe::run_native(
        "JWT Bruteforcer",
        options,
        Box::new(|cc| {
            let fonts = load_fonts();
            cc.egui_ctx.set_fonts(fonts);
            Ok(Box::<MainWindow>::new(MainWindow::default()))
        }),
    )
}
