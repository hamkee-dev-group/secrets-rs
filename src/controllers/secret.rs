#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unnecessary_struct_initialization)]
#![allow(clippy::unused_async)]
use axum::debug_handler;
use loco_rs::prelude::*;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::{Deserialize, Serialize};

use crate::models::{
    _entities::secrets::{ActiveModel, Column, Entity as Secret, Model},
    secrets::SecretApiModel,
};

use std::collections::HashMap;
use tera::{Context, Tera};

fn render_template(template_name: &str, context: &HashMap<&str, &str>) -> tera::Result<String> {
    let template_path = "templates/**/*";
    let tera = Tera::new(template_path)?;
    let mut tera_context = Context::new();
    for (key, value) in context {
        tera_context.insert(*key, *value);
    }
    tera.render(template_name, &tera_context)
}

#[debug_handler]
pub async fn hello() -> Result<Response> {
    let mut context = HashMap::new();
    context.insert("name", "World");
    let rendered = render_template("encrypt.html", &context)?;
    Ok(Response::new(rendered.into()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptParams {
    pub text: String,
    pub passphrase: String,
    pub maxviews: Option<u16>,
    pub expiration_days: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptParams {
    pub passphrase: String,
}

async fn load_item(ctx: &AppContext, uuid: Uuid) -> Result<Model> {
    // TODO: Move this to model
    let item = Secret::find()
        .filter(Column::Uuid.eq(uuid))
        .filter(Column::Maxviews.gt(0))
        .one(&ctx.db)
        .await?;

        // check expiration
        if let Some(item) = item {
            if let Some(exp_days) = item.exp {
                let created_at = item.created_at;
                let expiration_date = created_at + chrono::Duration::days(exp_days as i64);
                let now = chrono::Utc::now();
                
                if now > expiration_date {
                    return Err(Error::BadRequest("Secret has expired".to_string()));
                }
            }
            Ok(item)
        } else {
            Err(Error::NotFound)
        }
}

#[debug_handler]
pub async fn list(State(ctx): State<AppContext>) -> Result<Response> {
    // TODO: Move this to model
    let secrets = Secret::find()
        .order_by_desc(Column::CreatedAt)
        .all(&ctx.db)
        .await?;
    let secrets: Vec<SecretApiModel> = secrets.into_iter().map(|s| s.to_api()).collect();
    format::json(secrets)
}

#[debug_handler]
pub async fn add(
    State(ctx): State<AppContext>,
    Json(params): Json<EncryptParams>,
) -> Result<Response> {
    let passphrase = params.passphrase.as_bytes();
    let text = params.text.as_bytes();
    let item = ActiveModel::encrypt(text, passphrase, params.maxviews, params.expiration_days).unwrap();
    let item = item.insert(&ctx.db).await?;
    format::json(item.to_api())
}

#[debug_handler]
pub async fn get_one(Path(id): Path<Uuid>, State(ctx): State<AppContext>) -> Result<Response> {
    let item = load_item(&ctx, id).await?;
    format::json(item.to_api())
}

#[debug_handler]
pub async fn decrypt(
    Path(id): Path<Uuid>,
    State(ctx): State<AppContext>,
    Json(params): Json<DecryptParams>,
) -> Result<Response> {
    let passphrase = params.passphrase.as_bytes();
    let item = load_item(&ctx, id).await?;
    let decrypted_item = item
        .decrypt(passphrase)
        .or(Err(Error::BadRequest("Decryption failed".to_string())))?;
    let maxviews = item.maxviews.unwrap_or(0);

    let mut item: ActiveModel = item.clone().into();
    if maxviews > 0 {
        item.maxviews = Set(Some(maxviews - 1));
    }
    item.updated_at = Set(chrono::Utc::now().into());
    item.update(&ctx.db).await?;
    format::json(decrypted_item)
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("api/secrets")
        .add("/hello", get(hello))
        .add("/encrypt/", post(add))
        .add("/decrypt/{id}", post(decrypt))
}
