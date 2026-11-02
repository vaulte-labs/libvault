//! The broker as its own process, so every interface can use it and none has to contain it.

fn main() -> std::process::ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--build") {
        println!("{}", libvault::broker::build());
        return std::process::ExitCode::SUCCESS;
    }
    match libvault::broker::run(&libvault::default_home()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lvd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
