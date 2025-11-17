use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{
    App, Error, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    get,
    middleware::{Next, from_fn},
    post,
    web::{self, Data},
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{self, SaltString, rand_core::OsRng},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, prelude::FromRow};

static SECRET: &str = "secret";

#[actix_web::main]
async fn main() {
    let pool = db().await;
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .service(index)
            .service(register)
            .service(login)
            .service(web::scope("/api").wrap(from_fn(auth)).service(protected))
    })
    .bind("0.0.0.0:3000")
    .unwrap()
    .run()
    .await
    .unwrap()
}

// 8
#[get("/")]
async fn index() -> impl Responder {
    "Hello World!"
}

// 9
#[post("/register")]
async fn register(user_req: web::Json<UserReq>, pool: web::Data<PgPool>) -> impl Responder {
    if user_req.username.trim() == "" || user_req.password == "" {
        HttpResponse::BadRequest().body("Username or Password must not be empty!")
    } else {
        let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM users WHERE username = $1")
            .bind(&user_req.username)
            .fetch_all(pool.get_ref())
            .await
            .unwrap();
        if rows.len() == 0 {
            let hashed_password = hash_password(&user_req.password);

            sqlx::query("INSERT INTO users (username, password) VALUES ($1, $2)")
                .bind(&user_req.username)
                .bind(&hashed_password)
                .execute(pool.get_ref())
                .await
                .unwrap();

            HttpResponse::Ok().body("Register Successful!")
        } else {
            HttpResponse::BadRequest().body("Username is already taken!")
        }
    }
}
// 10
#[post("/login")]
async fn login(user_req: web::Json<UserReq>, pool: web::Data<PgPool>) -> impl Responder {
    if user_req.username.trim() == "" || user_req.password == "" {
        HttpResponse::BadRequest().body("Username or Password must not be empty!")
    } else {
        let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM users WHERE username = $1")
            .bind(&user_req.username)
            .fetch_all(pool.get_ref())
            .await
            .unwrap();
        if rows.len() == 0 {
            HttpResponse::BadRequest().body("Username is not Registered!")
        } else {
            match verify_password(&user_req.password, &rows[0].password) {
                Ok(_) => {
                    let token = generate_token(rows[0].username.clone());
                    HttpResponse::Ok().body(token)
                }
                Err(_) => HttpResponse::Unauthorized().body("Password is Uncorrect!"),
            }
        }
    }
}
// 12
#[get("/protected")]
async fn protected(req: HttpRequest) -> impl Responder {
    match req.extensions().get::<String>().cloned() {
        Some(user) => HttpResponse::Ok().body(user),
        None => HttpResponse::NotFound().body("No user"),
    }
}
// 11
async fn auth(req: ServiceRequest, next: Next<BoxBody>) -> Result<ServiceResponse<BoxBody>, Error> {
    match req.headers().get("Authorization") {
        Some(header_value) => {
            let header_value = header_value.to_str().unwrap();
            if header_value.starts_with("Bearer ") {
                let token = header_value.split(" ").collect::<Vec<&str>>()[1];
                match verify_token(token) {
                    Ok(sub) => {
                        req.extensions_mut().insert(sub);
                        next.call(req).await
                    }
                    Err(e) => Ok(req.into_response(HttpResponse::Unauthorized().body(e))),
                }
            } else {
                Ok(req.into_response(HttpResponse::Unauthorized().body("Invalid Token")))
            }
        }
        None => Ok(req.into_response(HttpResponse::Unauthorized().body("No Token"))),
    }
}

// 7
async fn db() -> PgPool {
    let pool = sqlx::postgres::PgPool::connect("postgres://postgres:774623@localhost:5432/auth")
        .await
        .unwrap();

    pool
}

// 2
fn hash_password(password: &String) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let hashed_password = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    hashed_password
}

//3
fn verify_password(
    password: &String,
    hashed_password: &String,
) -> Result<(), password_hash::Error> {
    let argon2 = Argon2::default();

    let parsed_hash = PasswordHash::new(&hashed_password).unwrap();

    argon2.verify_password(password.as_bytes(), &parsed_hash)
}

//5
fn generate_token(username: String) -> String {
    let claims = Claims {
        sub: username,
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 60 * 60 * 24,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    token
}
//6
fn verify_token(token: &str) -> Result<String, String> {
    match decode(
        token,
        &DecodingKey::from_secret(SECRET.as_bytes()),
        &Validation::default(),
    ) {
        Err(e) => Err(e.to_string()),
        Ok(token_data) => {
            let claims: Claims = token_data.claims;
            Ok(claims.sub)
        }
    }
}

// 4
#[derive(Deserialize, Serialize)]
struct Claims {
    exp: usize,
    sub: String,
}

// 1
#[derive(Deserialize)]
struct UserReq {
    username: String,
    password: String,
}

#[derive(FromRow)]
struct UserSql {
    username: String,
    password: String,
}
