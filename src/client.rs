pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use std::io::stdin;

use num_bigint::BigUint;
use zk::ZKP;
use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};

#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let (p, q, alpha, beta) = ZKP::get_constants();
    let zkp = ZKP::new(p.clone(), q.clone(), alpha.clone(), beta.clone());

    let mut client = AuthClient::connect("http://127.0.0.1:5051")
        .await
        .expect("could not connect to the server");

    println!("Connection was successful");
    println!("Please provide username: ");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get user from stdin");
    let username = buf.trim().to_string();

    println!("Please provide a password: ");
    buf.clear();
    stdin()
        .read_line(&mut buf)
        .expect("Could not get password from stdin");
    let password = buf.as_bytes();

    let y1 = ZKP::exponentiate(&alpha, &BigUint::from_bytes_be(password), &p);
    let y2 = ZKP::exponentiate(&beta, &BigUint::from_bytes_be(password), &p);

    let request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    client.register(request).await.expect("Could not register");

    let k = ZKP::generate_random_number_bellow(&q);
    let r1 = ZKP::exponentiate(&alpha, &k, &p);
    let r2 = ZKP::exponentiate(&beta, &k, &p);

    let request = AuthenticationChallengeRequest {
        user: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let challenge_response = client
        .create_authentication_challenge(request)
        .await
        .expect("could not request challenge")
        .into_inner();

    println!("Please provide a password to login: ");
    buf.clear();
    stdin()
        .read_line(&mut buf)
        .expect("Could not get password from stdin");
    let password = buf.as_bytes();

    let auth_id = challenge_response.auth_id;
    let c = challenge_response.c;

    let s = zkp.solve(
        &k,
        &BigUint::from_bytes_be(&c),
        &BigUint::from_bytes_be(password),
    );

    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    let response = client
        .verify_authentication(request)
        .await
        .expect("authentication request failed")
        .into_inner();

    println!("Logging done, session {}", response.session_id);
}
