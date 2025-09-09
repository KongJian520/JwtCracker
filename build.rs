extern crate winres;

fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("src/assest/icons/icon.ico");
        res.set("ProductName", "JwtCracker");
        res.set("FileDescription", "破解JWT");
        res.set("FileVersion", "0.1.0.1");

        match res.compile() {
            Ok(_) => {}
            Err(e) => panic!("{}", e),
        }
    }
}
