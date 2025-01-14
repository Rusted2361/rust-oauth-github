use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::sync::{Arc, Mutex};
use tokio;

#[derive(Deserialize, Serialize)]
struct OAuthCallback {
    code: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let client_id = env::var("clientID").expect("Missing clientID in .env");
    let client_secret = env::var("clientSecret").expect("Missing clientSecret in .env");
    let redirect_uri = env::var("redirectURI").expect("Missing redirectURI in .env");

    let access_token = Arc::new(Mutex::new(String::new()));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client_id.clone()))
            .app_data(web::Data::new(client_secret.clone()))
            .app_data(web::Data::new(redirect_uri.clone()))
            .app_data(web::Data::new(access_token.clone()))
            .route("/login/oauth", web::get().to(login_oauth))
            .route("/oauth-callback", web::get().to(oauth_callback))
            .route("/repos/{owner}/{repo}/tree-content", web::get().to(fetch_repo_tree))
    })
    .bind("127.0.0.1:3000")?
    .run()
    .await
}

async fn login_oauth(client_id: web::Data<String>, redirect_uri: web::Data<String>) -> impl Responder {
    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=repo",
        client_id.get_ref(),
        redirect_uri.get_ref()
    );
    HttpResponse::Found().header("Location", auth_url).finish()
}

async fn oauth_callback(
    query: web::Query<OAuthCallback>,
    client_id: web::Data<String>,
    client_secret: web::Data<String>,
    redirect_uri: web::Data<String>,
    access_token: web::Data<Arc<Mutex<String>>>,
) -> impl Responder {
    let token_url = "https://github.com/login/oauth/access_token";
    let params = [
        ("client_id", client_id.get_ref()),
        ("client_secret", client_secret.get_ref()),
        ("code", &query.code),
        ("redirect_uri", redirect_uri.get_ref()),
    ];

    let client = reqwest::Client::new();
    match client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(json) => {
                if let Some(token) = json.get("access_token").and_then(|v| v.as_str()) {
                    *access_token.lock().unwrap() = token.to_string();
                    HttpResponse::Ok().json("Authentication successful!")
                } else {
                    HttpResponse::InternalServerError().json("Failed to extract access token")
                }
            }
            Err(_) => HttpResponse::InternalServerError().json("Failed to parse JSON response"),
        },
        Err(_) => HttpResponse::InternalServerError().json("Failed to get access token"),
    }
}

async fn fetch_repo_tree(
    path: web::Path<(String, String)>,
    query: web::Query<Value>,
    access_token: web::Data<Arc<Mutex<String>>>,
) -> impl Responder {
    let (owner, repo) = path.into_inner();
    let branch = query.get("branch").and_then(|v| v.as_str()).unwrap_or("main");
    let api_url = format!(
        "https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1",
        owner, repo, branch
    );

    let client = reqwest::Client::new();
    let token = access_token.lock().unwrap().clone();

    match client
        .get(&api_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(json) => HttpResponse::Ok().json(json),
            Err(_) => HttpResponse::InternalServerError().json("Failed to parse JSON response"),
        },
        Err(_) => HttpResponse::InternalServerError().json("Failed to fetch repository tree"),
    }
}
