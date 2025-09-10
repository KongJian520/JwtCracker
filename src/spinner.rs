// my_spinner.rs

use egui::{
    Color32, Pos2, Rect, Response, Sense, Shape, Stroke, Ui, Widget, WidgetInfo, WidgetType, lerp,
    vec2,
};

// 为 Spinner 添加可配置的字段
pub struct Spinner {
    size: Option<f32>,
    color: Option<Color32>,
    speed: f64,      // 旋转速度
    clockwise: bool, // 是否顺时针
}

impl Default for Spinner {
    fn default() -> Self {
        Self {
            size: None,
            color: None,
            speed: 1.0,      // 默认速度为 1.0
            clockwise: true, // 默认顺时针
        }
    }
}

impl Spinner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn size(mut self, size: f32) -> Self {
        self.size = Some(size);
        self
    }

    pub fn color(mut self, color: impl Into<Color32>) -> Self {
        self.color = Some(color.into());
        self
    }

    // 新增方法：设置旋转速度
    pub fn speed(mut self, speed: f64) -> Self {
        self.speed = speed;
        self
    }

    // 新增方法：设置旋转方向
    pub fn clockwise(mut self, clockwise: bool) -> Self {
        self.clockwise = clockwise;
        self
    }

    pub fn paint_at(&self, ui: &Ui, rect: Rect) {
        if ui.is_rect_visible(rect) {
            ui.ctx().request_repaint();

            let color = self
                .color
                .unwrap_or_else(|| ui.visuals().strong_text_color());
            let radius = (rect.height() / 2.0) - 2.0;
            let n_points = (radius.round() as u32).clamp(8, 128);

            let time = ui.input(|i| i.time);

            // 根据字段来计算旋转方向和速度
            let rotation_direction = if self.clockwise { 1.0 } else { -1.0 };
            let start_angle = time * self.speed * rotation_direction * std::f64::consts::TAU;

            let end_angle = start_angle + 240f64.to_radians() * time.sin();
            let points: Vec<Pos2> = (0..n_points)
                .map(|i| {
                    let angle = lerp(start_angle..=end_angle, i as f64 / n_points as f64);
                    let (sin, cos) = angle.sin_cos();
                    rect.center() + radius * vec2(cos as f32, sin as f32)
                })
                .collect();
            ui.painter()
                .add(Shape::line(points, Stroke::new(3.0, color)));
        }
    }
}

impl Widget for Spinner {
    fn ui(self, ui: &mut Ui) -> Response {
        let size = self
            .size
            .unwrap_or_else(|| ui.style().spacing.interact_size.y);
        let (rect, response) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
        response.widget_info(|| WidgetInfo::new(WidgetType::ProgressIndicator));
        self.paint_at(ui, rect);

        response
    }
}
