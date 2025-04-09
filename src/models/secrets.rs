use sea_orm::entity::prelude::*;
use sea_orm::Set;
use serde::Serialize;
pub use super::_entities::secrets::{ActiveModel, Model, Entity};
pub type Secrets = Entity;
use crate::cryptography::encryption::{AES256Cypher, CryptoError, Cypher};

#[derive(Serialize, Default)]
pub struct SecretApiModel {
    pub uuid: Uuid,
    pub created_at: DateTimeWithTimeZone,
    maxviews: Option<u16>,
    expiration_days: Option<u8>, 
    length: usize,
    secret: Option<String>,
}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(self, _db: &C, insert: bool) -> std::result::Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if !insert && self.updated_at.is_unchanged() {
            let mut this = self;
            this.updated_at = sea_orm::ActiveValue::Set(chrono::Utc::now().into());
            Ok(this)
        } else {
            Ok(self)
        }
    }
}

impl Model {
    pub fn to_api(&self) -> SecretApiModel {
        SecretApiModel {
            uuid: self.uuid,
            created_at: self.created_at,
            maxviews: self.maxviews,
            expiration_days: self.exp,
            length: self.ciphertext.len(), 
            ..Default::default()
        }
    }
    pub fn decrypt(
        &self,
        passphrase: &[u8],
    ) -> Result<SecretApiModel, CryptoError> {
        let plaintext = Cypher::new(&AES256Cypher)
            .with_passphrase(passphrase.into())
            .decrypt(&self.ciphertext)?;
        let secret = String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidData)?;
        return Ok(SecretApiModel {
            uuid: self.uuid,
            created_at: self.created_at,
            maxviews: self.maxviews,
            expiration_days: self.exp,
            length: self.ciphertext.len(),
            secret: Some(secret),
        })
    }
}

impl ActiveModel {
    pub fn new(ciphertext: Vec<u8>, maxviews: Option<u16>, expiration_days: Option<u8>) -> Self {
        let maxviews = maxviews.unwrap_or(1);
        let expiration_days = expiration_days.unwrap_or(1);
        Self {
            uuid: Set(Uuid::new_v4()),
            ciphertext: Set(ciphertext),
            maxviews: Set(Some(maxviews)),
            exp: Set(Some(expiration_days)),
            ..Default::default()
        }
    }
    pub fn encrypt(
        text: &[u8],
        passphrase: &[u8],
        maxviews: Option<u16>,
        expiration_days: Option<u8>,
    ) -> Result<Self, CryptoError> {
        let cipher = Cypher::new(&AES256Cypher)
            .with_data(text.to_vec())
            .with_passphrase(passphrase.to_vec());
        let ciphertext = cipher.encrypt()?;
        return Ok(Self::new(ciphertext, maxviews, expiration_days));
    }
}

impl Entity {}
