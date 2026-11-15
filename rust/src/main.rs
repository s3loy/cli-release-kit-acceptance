fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => println!("sparrow 0.4.2"),
        Some("--json") => println!(r#"{{"message":"chirp","ok":true}}"#),
        _ => {
            eprintln!("usage: sparrow --version|--json");
            std::process::exit(2);
        }
    }
}
