//! `enclave-check`: verify a deployment's enclave as the researcher's
//! browser does, and seal research queries to it (`platform_api::checker`).

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match platform_api::checker::client() {
        Ok(http) => platform_api::checker::run(&args, &http).await,
        Err(err) => Err(err),
    };
    match result {
        Ok(out) => println!("{out}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
