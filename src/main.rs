use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{sync,env};
use tokio;

#[derive(Deserialize, Serialize)]
struct OAuthCallback {
    code: String,
}

// Shared application state
#[derive(Clone)]
struct AppState {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    access_token: std::sync::Arc<tokio::sync::Mutex<String>>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let shared_state = AppState {
        client_id: env::var("clientID").expect("Missing clientID in .env"),
        client_secret: env::var("clientSecret").expect("Missing clientSecret in .env"),
        redirect_uri: env::var("redirectURI").expect("Missing redirectURI in .env"),
        access_token: sync::Arc::new(tokio::sync::Mutex::new(String::new())),
    };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(shared_state.clone()))
            .route("/login/oauth", web::get().to(login_oauth))
            .route("/oauth-callback", web::get().to(oauth_callback))
            .route("/repos/{owner}/{repo}/tree-content", web::get().to(fetch_repo_tree))
    })
    .bind("127.0.0.1:3000")?
    .run()
    .await
}

async fn login_oauth(
    data: web::Data<AppState>
) -> impl Responder {
    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=repo",
        data.client_id, data.redirect_uri
    );
    HttpResponse::Found().append_header(("Location", auth_url)).finish()
}

async fn oauth_callback(
    query: web::Query<OAuthCallback>,
    data: web::Data<AppState>,
) -> impl Responder {
    let token_url = "https://github.com/login/oauth/access_token";
    let params = [
        ("client_id", &data.client_id),
        ("client_secret", &data.client_secret),
        ("code", &query.code),
        ("redirect_uri", &data.redirect_uri),
    ];

    let client = reqwest::Client::new();
    let response = client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await;
    match response {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(json) => {
                if let Some(token) = json.get("access_token").and_then(|v| v.as_str()) {
                    let mut access_token = data.access_token.lock().await;
                    *access_token = token.to_string();
                    HttpResponse::Ok().json("Authentication successful!")
                } else {
                    HttpResponse::InternalServerError().json("Failed to extract access token")
                }
            }
            Err(_) => HttpResponse::InternalServerError().json("Failed to parse JSON response"),
        },
        Err(err) => {
            eprintln!("Error while requesting access token: {:?}", err);
            HttpResponse::InternalServerError().json("Failed to get access token")
        }
    }
}

async fn fetch_repo_tree(
    path: web::Path<(String, String)>,
    query: web::Query<Value>,
    data: web::Data<AppState>
) -> impl Responder {
    let (owner, repo) = path.into_inner();
    let branch = query.get("branch").and_then(|v| v.as_str()).unwrap_or("main");
    let api_url = format!(
        "https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1",
        owner, repo, branch
    );

    let client = reqwest::Client::new();
    let token = data.access_token.lock().await;

    // Log the API URL
    dbg!(&api_url);

    match client
        .get(&api_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "oauthapp-rust")
        .send()
        .await
    {
        Ok(resp) => {
            // Log the raw response body
            let body = resp.text().await.unwrap_or_else(|_| "Failed to read response body".to_string());

            match serde_json::from_str::<Value>(&body) {
                Ok(json) => HttpResponse::Ok().json(json),
                Err(_e) => {
                    // Log the JSON parsing error
                    HttpResponse::InternalServerError().json("Failed to parse JSON response")
                }
            }
        },
        Err(_e) => {
            // Log the request error
            HttpResponse::InternalServerError().json("Failed to fetch repository tree")
        }
    }
}
