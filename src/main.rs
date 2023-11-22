use anyhow::{anyhow, Result};
use fastly::http::{header, Method, StatusCode};
use fastly::{ConfigStore, ObjectStore, Request, Response};
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

const CFG_OBJ_STORE_RES: &str = "short-urls-store-resource";
const CFG_SHORT_ID_LEN: usize = 8;

static CONFIG_DIC: Lazy<ConfigStore> = Lazy::new(|| ConfigStore::open("config"));

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

// Get passcode from request's cookie
fn get_req_passcode(req: &Request) -> Result<String> {
    let cookie_val: &str = req
        .get_header(header::COOKIE)
        .ok_or_else(|| anyhow!("No cookie found"))?
        .to_str()?;

    // we split at ";" not "; ", in case the cookie is ending with ";"
    let passcode = cookie_val
        .split(';')
        .map(|kv| {
            let index = kv
                .find('=')
                .ok_or_else(|| anyhow!("Invalid key-value pair"))?;
            let (key, value) = kv.split_at(index);
            if key.trim() == "passcode" {
                Ok(value.trim_start_matches('=').to_string())
            } else {
                Err(anyhow!("No passcode found in cookie"))
            }
        })
        .find_map(Result::ok)
        .ok_or_else(|| anyhow!("No passcode found in cookie"))?;
    Ok(passcode)
}

/// Get redirect URL from short ID
fn get_redirect_url(req: &Request) -> Result<Response> {
    // remove leading "/" in the path
    let short_id = req
        .get_path()
        .get(1..)
        .ok_or_else(|| anyhow!("mal-formatted URL"))?;

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

    let object_store =
        ObjectStore::open(CFG_OBJ_STORE_RES)?.ok_or_else(|| anyhow!("object store not exists"))?;

    let redirect_location = object_store
        .lookup_str(short_id)?
        .ok_or_else(|| anyhow!("redirect location not found"))?;

    Ok(Response::from_status(StatusCode::MOVED_PERMANENTLY)
        .with_header(header::LOCATION, redirect_location)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
}

/// Create short ID of a URL
fn create_short_id(req: &mut Request) -> Result<Response> {
    // check passcode, to avoid being easily abused
    if let Ok(req_passcode) = get_req_passcode(req) {
        let passcode = CONFIG_DIC
            .get("passcode")
            .ok_or_else(|| anyhow!("No passcode in config store"))?;

        if passcode != req_passcode {
            return Err(anyhow!("passcode not matching"));
        }
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

    let mut object_store =
        ObjectStore::open(CFG_OBJ_STORE_RES)?.ok_or_else(|| anyhow!("object store not exists"))?;

    object_store.insert(&short_id, r.url)?;

    Ok(Response::from_status(StatusCode::CREATED)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_body_json(&CreationResult { short: short_id })?)
}

fn handle_get(req: &Request) -> Result<Response> {
    // handle GET
    if req.get_path() == "/" {
        Ok(Response::from_status(StatusCode::OK).with_header(
            header::SET_COOKIE,
            format!(
                "passcode={:?}; Secure; HttpOnly",
                CONFIG_DIC
                    .get("passcode")
                    .ok_or_else(|| anyhow!("No passcode in config store"))?
            ),
        ))
    } else {
        match get_redirect_url(req) {
            Ok(resp) => Ok(resp),
            Err(e) => {
                Ok(Response::from_status(StatusCode::NOT_FOUND)
                    .with_body_text_plain(&e.to_string()))
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
    match *req.get_method() {
        Method::GET => handle_get(&req),
        Method::POST => Ok(handle_post(&mut req)),
        Method::OPTIONS => Ok(handle_options()),
        _ => Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, POST, OPTIONS")
            .with_body_text_plain("This method is not allowed\n")),
    }
}
