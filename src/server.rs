use std::collections::HashMap;

use num_bigint::BigUint;
use std::sync::Mutex;
use tonic::{transport::Server, Code, Request, Response, Status};

use zk::ZKP;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

#[derive(Debug, Default)]
struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,

    // authorization
    pub r1: BigUint,
    pub r2: BigUint,

    // verification
    pub c: BigUint,
}

#[derive(Debug, Default)]
struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing register {:?}", request);
        let request = request.into_inner();

        // Inputs
        let mut user_info = UserInfo::default();
        user_info.user_name.clone_from(&request.user);
        user_info.y1 = BigUint::from_bytes_be(&request.y1);
        user_info.y2 = BigUint::from_bytes_be(&request.y2);

        // Lock the user info
        let user_info_hashmap = &mut self.user_info.lock().unwrap();
        user_info_hashmap.insert(request.user, user_info);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing authentication challenge {:?}", request);
        let request = request.into_inner();

        let user_info_hashmap = &mut self.user_info.lock().unwrap();

        if let Some(user_info) = user_info_hashmap.get_mut(&request.user) {
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let (_, q, _, _) = ZKP::get_constants();
            let c = ZKP::generate_random_number_bellow(&q);
            let auth_id = ZKP::generate_random_string(32);

            user_info.c.clone_from(&c);
            user_info.r1.clone_from(&BigUint::from_bytes_be(&request.r1));
            user_info.r2.clone_from(&BigUint::from_bytes_be(&request.r2));

            let auth_id_to_user = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_to_user.insert(auth_id.clone(), request.user);

            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("User: {} not found", request.user),
            ))
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing authentication answer {:?}", request);
        let request = request.into_inner();

        let auth_id_to_user = &mut self.auth_id_to_user.lock().unwrap();

        if let Some(user_name) = auth_id_to_user.get(&request.auth_id) {
            let user_info_hashmap = &mut self.user_info.lock().unwrap();
            let user_info = user_info_hashmap.get(user_name).expect("auth id not found");

            let (p, q, alpha, beta) = ZKP::get_constants();
            let zkp = ZKP::new(p, q, alpha, beta);

            let verification = zkp.verify(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &BigUint::from_bytes_be(&request.s),
            );

            if verification {
                let session_id = ZKP::generate_random_string(64);
                Ok(Response::new(AuthenticationAnswerResponse { session_id }))
            } else {
                Err(Status::new(
                    Code::PermissionDenied,
                    format!("AuthId: {} sent a bad solution", request.auth_id),
                ))
            }
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("AuthId: {} not found", request.auth_id),
            ))
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:5051".to_string();
    println!("Running the server in {}", addr);

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("could not convert addr"))
        .await
        .unwrap()
}
