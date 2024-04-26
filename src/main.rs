use anyhow::{anyhow, Context, Result};
use fastly::http::{header, Method, StatusCode};
use fastly::{KVStore, Request, Response, SecretStore};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

const CFG_KV_STORE: &str = "short-urls-store";
const CFG_SECRET_STORE: &str = "short-urls-secret";
const CFG_SHORT_ID_LEN: usize = 8;

/// Holds ID & URL mapping request: short ID (optional) and URL
#[derive(Serialize, Deserialize, Debug)]
struct MyRedirect {
    short: Option<String>,
    url: String,
}

/// Holds result of short ID creation
#[derive(serde::Serialize)]
struct CreationResult {
    short: String,
}

/// Generate a random short ID
fn generate_short_id() -> String {
    let mut rng = thread_rng();
    (0..CFG_SHORT_ID_LEN)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

/// Get passcode from request's cookie
fn get_req_passcode(req: &Request) -> Result<String> {
    let cookie_val: &str = req
        .get_header(header::COOKIE)
        .context("No cookie found")?
        .to_str()?;

    // we split at ";" not "; ", in case the cookie is ending with ";"
    cookie_val
        .split(';')
        .find_map(|kv| {
            let index = kv.find('=')?;
            let (key, value) = kv.split_at(index);
            if key.trim() != "passcode" {
                return None;
            }

            // remove the "="
            let value = value.trim_start_matches('=').to_string();
            Some(value)
        })
        .context("No passcode found in cookie")
}

/// Get passcode from the secret store
fn get_stored_passcode() -> Result<String> {
    let store = SecretStore::open(CFG_SECRET_STORE)?;
    let passcode_bytes = store
        .get("passcode")
        .context("Passcode not found")?
        .plaintext()
        .to_vec();

    Ok(String::from_utf8(passcode_bytes)?)
}

/// Get redirect URL from short ID
fn get_redirect_url(req: &Request) -> Result<Response> {
    // remove leading "/" in the path
    let short_id = req.get_path().get(1..).context("mal-formatted URL")?;

    if short_id == "api" {
        return Ok(
            Response::from_status(StatusCode::MOVED_PERMANENTLY).with_header(
                header::LOCATION,
                "https://developer.fastly.com/reference/api/",
            ),
        );
    }

    if short_id
        .as_bytes()
        .iter()
        .any(|s| !s.is_ascii_alphanumeric())
    {
        return Err(anyhow!("mal-formatted short id"));
    };

    let object_store = KVStore::open(CFG_KV_STORE)?.context("object store not exists")?;

    let redirect_location = object_store
        .lookup_str(short_id)?
        .context("redirect location not found")?;

    Ok(Response::from_status(StatusCode::MOVED_PERMANENTLY)
        .with_header(header::LOCATION, redirect_location)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
}

/// Create short ID of a URL
fn create_short_id(req: &mut Request) -> Result<Response> {
    // check passcode, to avoid being easily abused
    let req_passcode = get_req_passcode(req)?;
    let passcode = get_stored_passcode()?;
    if passcode != req_passcode {
        return Err(anyhow!("passcode not matching"));
    }

    let r = match req.get_content_type() {
        Some(mime) if fastly::mime::APPLICATION_WWW_FORM_URLENCODED == mime => {
            req.take_body_form::<MyRedirect>()?
        }
        _ => req.take_body_json::<MyRedirect>()?,
    };

    let short_id = r.short.map_or_else(generate_short_id, |short| {
        if short.is_empty() {
            generate_short_id()
        } else {
            short
        }
    });

    let mut object_store = KVStore::open(CFG_KV_STORE)?.context("object store not exists")?;

    object_store.insert(&short_id, r.url)?;

    Ok(Response::from_status(StatusCode::CREATED)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_body_json(&CreationResult { short: short_id })?)
}

fn handle_get(req: &Request) -> Response {
    // handle GET
    if req.get_path() == "/" {
        let Ok(passcode) = get_stored_passcode() else {
            return Response::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                .with_body_text_plain("Missing configuration");
        };

        Response::from_status(StatusCode::OK)
            .with_header(
                header::SET_COOKIE,
                format!("passcode={}; Secure; HttpOnly; SameSite=Strict", passcode),
            )
            .with_body_text_html(include_str!("editor.html"))
    } else {
        match get_redirect_url(req) {
            Ok(resp) => resp,
            Err(e) => {
                Response::from_status(StatusCode::NOT_FOUND).with_body_text_plain(&e.to_string())
            }
        }
    }
}

fn handle_post(req: &mut Request) -> Response {
    // handle POST
    match create_short_id(req) {
        Ok(resp) => resp,
        Err(e) => {
            Response::from_status(StatusCode::NOT_ACCEPTABLE).with_body_text_plain(&e.to_string())
        }
    }
}

fn handle_options() -> Response {
    // handle OPTIONS
    Response::from_status(StatusCode::NO_CONTENT)
        .with_header(header::ALLOW, "GET, POST, OPTIONS")
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_header(header::ACCESS_CONTROL_ALLOW_HEADERS, "*")
        .with_header(header::ACCESS_CONTROL_ALLOW_METHODS, "*")
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response> {
    let resp = match *req.get_method() {
        Method::GET => handle_get(&req),
        Method::POST => handle_post(&mut req),
        Method::OPTIONS => handle_options(),
        _ => Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, POST, OPTIONS")
            .with_body_text_plain("This method is not allowed\n"),
    };

    Ok(resp)
}
