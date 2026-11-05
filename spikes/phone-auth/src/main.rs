//! Spike: can a phone passkey, reached over the FIDO hybrid transport (the
//! "use a phone" QR flow browsers have), authenticate a local Omarchy action?
//!
//!   enroll   show a QR, the phone creates a passkey, store its public key
//!   verify   ask the phone for an assertion and check it locally
//!            exit 0 = verified, 1 = refused/invalid, 2 = error
//!
//! Not a PAM module yet. `verify` has the exit-code contract a PAM helper
//! (pam_exec) would need, so the answer to "does the phone cooperate?" carries
//! over directly.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, OriginValidation, RequestOrigin, RequestSettings,
    WebAuthnIDLResponse as _,
};
use libwebauthn::transport::hybrid::channel::{HybridChannel, HybridUxUpdate, PxpUpdate};
use libwebauthn::transport::hybrid::is_available;
use libwebauthn::transport::hybrid::known_devices::{
    ClientPayloadHint, PxpKnownDevice, PxpKnownDeviceId, PxpKnownDeviceInfo,
    PxpKnownDeviceInfoStore,
};
use libwebauthn::transport::hybrid::qr_code_device::{
    PxpQrCodeDevice, PxpTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use libwebauthn::webauthn::{WebAuthn, WebAuthnError};
use libwebauthn::UvUpdate;

const DEFAULT_RP_ID: &str = "omarchy.localhost";
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);
const ES256: i64 = -7;

type AnyResult<T> = Result<T, Box<dyn Error>>;

// ---------------------------------------------------------------- storage

fn state_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    base.join("omarchy-phone-auth-spike")
}

fn write_private(path: &Path, data: &[u8]) -> AnyResult<()> {
    let dir = path.parent().ok_or("no parent directory")?;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Credential {
    rp_id: String,
    credential_id: String, // base64url
    public_key_spki: String, // base64url DER
    user: String,
    enrolled_unix: u64,
}

impl Credential {
    fn path() -> PathBuf {
        state_dir().join("credential.json")
    }
    fn load() -> AnyResult<Self> {
        let data = fs::read(Self::path()).map_err(|_| "no phone enrolled yet: run `enroll` first")?;
        Ok(serde_json::from_slice(&data)?)
    }
    fn save(&self) -> AnyResult<()> {
        write_private(&Self::path(), &serde_json::to_vec_pretty(self)?)
    }
}

/// Linking data a phone may hand out so later ceremonies can skip the QR
/// ("state-assisted": the phone gets a notification instead). Contains a link
/// secret, hence 0600.
#[derive(Serialize, Deserialize, Clone)]
struct StoredDevice {
    contact_id: String,
    link_id: String,
    link_secret: String,
    public_key: String,
    name: String,
    tunnel_domain: String,
}

impl From<&PxpKnownDeviceInfo> for StoredDevice {
    fn from(d: &PxpKnownDeviceInfo) -> Self {
        Self {
            contact_id: hex::encode(&d.contact_id),
            link_id: hex::encode(d.link_id),
            link_secret: hex::encode(d.link_secret),
            public_key: hex::encode(d.public_key),
            name: d.name.clone(),
            tunnel_domain: d.tunnel_domain.clone(),
        }
    }
}

impl TryFrom<&StoredDevice> for PxpKnownDeviceInfo {
    type Error = Box<dyn Error>;
    fn try_from(s: &StoredDevice) -> AnyResult<Self> {
        fn arr<const N: usize>(h: &str) -> AnyResult<[u8; N]> {
            hex::decode(h)?.try_into().map_err(|_| "bad length in linked-phones.json".into())
        }
        Ok(Self {
            contact_id: hex::decode(&s.contact_id)?,
            link_id: arr(&s.link_id)?,
            link_secret: arr(&s.link_secret)?,
            public_key: arr(&s.public_key)?,
            name: s.name.clone(),
            tunnel_domain: s.tunnel_domain.clone(),
        })
    }
}

#[derive(Debug)]
struct FileDeviceStore {
    path: PathBuf,
    devices: Mutex<HashMap<PxpKnownDeviceId, StoredDevice>>,
}

impl std::fmt::Debug for StoredDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredDevice").field("name", &self.name).finish_non_exhaustive()
    }
}

impl FileDeviceStore {
    fn open() -> Arc<Self> {
        let path = state_dir().join("linked-phones.json");
        let devices = fs::read(&path)
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        Arc::new(Self { path, devices: Mutex::new(devices) })
    }
    fn first(&self) -> Option<StoredDevice> {
        self.devices.lock().unwrap().values().next().cloned()
    }
    fn persist(&self) {
        let snapshot = serde_json::to_vec_pretty(&*self.devices.lock().unwrap()).unwrap();
        if let Err(e) = write_private(&self.path, &snapshot) {
            eprintln!("warning: could not save linked phone: {e}");
        }
    }
}

#[async_trait]
impl PxpKnownDeviceInfoStore for FileDeviceStore {
    async fn put_known_device(&self, id: &PxpKnownDeviceId, device: &PxpKnownDeviceInfo) {
        println!("  phone \"{}\" offered linking: next time it can be reached without a QR", device.name);
        self.devices.lock().unwrap().insert(id.clone(), device.into());
        self.persist();
    }
    async fn delete_known_device(&self, id: &PxpKnownDeviceId) {
        self.devices.lock().unwrap().remove(id);
        self.persist();
    }
}

// ---------------------------------------------------------------- hybrid

fn print_qr(device: &PxpQrCodeDevice) -> AnyResult<()> {
    let image = QrCode::new(device.qr_code.to_string())?
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    println!("\nScan with the phone camera (Android: camera or Google Lens; iPhone: Camera):\n");
    println!("{image}");
    Ok(())
}

async fn report_updates(mut rx: tokio::sync::broadcast::Receiver<HybridUxUpdate>) {
    while let Ok(update) = rx.recv().await {
        match update {
            HybridUxUpdate::PxpUpdate(PxpUpdate::ProximityCheck) => {
                println!("  waiting for the phone over Bluetooth (proximity check)...")
            }
            HybridUxUpdate::PxpUpdate(PxpUpdate::Connecting) => println!("  connecting to the tunnel..."),
            HybridUxUpdate::PxpUpdate(PxpUpdate::Authenticating) => println!("  handshake..."),
            HybridUxUpdate::PxpUpdate(PxpUpdate::Connected) => {
                println!("  connected: confirm on the phone (fingerprint / face / screen lock)")
            }
            HybridUxUpdate::PxpUpdate(PxpUpdate::Error(e)) => println!("  transport error: {e}"),
            // A phone verifies the user itself; a PIN request here would be a
            // roaming key, which this spike does not handle.
            HybridUxUpdate::UvUpdate(UvUpdate::PinRequired(u)) => {
                println!("  authenticator asked for a PIN: not supported, cancelling");
                u.cancel();
            }
            HybridUxUpdate::UvUpdate(UvUpdate::PinNotSet(u)) => {
                println!("  authenticator wants a PIN set: not supported, cancelling");
                u.cancel();
            }
            HybridUxUpdate::UvUpdate(UvUpdate::PresenceRequired) => println!("  confirm on the phone"),
            HybridUxUpdate::UvUpdate(other) => println!("  {other:?}"),
        }
    }
}

async fn qr_channel(hint: QrCodeOperationHint, store: Arc<FileDeviceStore>) -> AnyResult<HybridChannel> {
    let mut device = PxpQrCodeDevice::new_persistent(hint, store, PxpTransports::CloudAssistedOnly)?;
    print_qr(&device)?;
    let channel = device.channel(ChannelSettings::default()).await?;
    Ok(channel)
}

async fn linked_channel(info: &PxpKnownDeviceInfo, store: Arc<FileDeviceStore>) -> AnyResult<HybridChannel> {
    println!("Asking linked phone \"{}\" (check its notifications)...", info.name);
    let mut device = PxpKnownDevice::new(ClientPayloadHint::GetAssertion, info, store).await?;
    let channel = device.channel(ChannelSettings::default()).await?;
    Ok(channel)
}

fn is_retryable<E>(err: &WebAuthnError<E>) -> bool {
    matches!(err, WebAuthnError::Ctap(c) if c.is_retryable_user_error())
}

// ---------------------------------------------------------------- crypto

fn random_b64(n: usize) -> String {
    let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
    B64.encode(bytes)
}

fn json_b64(v: &serde_json::Value, pointer: &str) -> AnyResult<Vec<u8>> {
    let s = v.pointer(pointer).and_then(|x| x.as_str()).ok_or_else(|| format!("response lacks {pointer}"))?;
    Ok(B64.decode(s.trim_end_matches('='))?)
}

/// Checks the assertion exactly as a relying party would. Returns the
/// failure reason so the spike tells us *why* a phone's answer is rejected.
fn check_assertion(
    cred: &Credential,
    origin: &str,
    challenge_b64: &str,
    response: &serde_json::Value,
) -> Result<(), String> {
    let raw_id = json_b64(response, "/rawId").map_err(|e| e.to_string())?;
    if B64.encode(&raw_id) != cred.credential_id {
        return Err("phone answered with a different credential".into());
    }
    let client_data = json_b64(response, "/response/clientDataJSON").map_err(|e| e.to_string())?;
    let auth_data = json_b64(response, "/response/authenticatorData").map_err(|e| e.to_string())?;
    let signature = json_b64(response, "/response/signature").map_err(|e| e.to_string())?;

    let cd: serde_json::Value = serde_json::from_slice(&client_data).map_err(|e| e.to_string())?;
    if cd["type"] != "webauthn.get" {
        return Err(format!("clientData.type is {}", cd["type"]));
    }
    if cd["challenge"].as_str().map(|c| c.trim_end_matches('=')) != Some(challenge_b64) {
        return Err("challenge mismatch".into());
    }
    if cd["origin"] != origin {
        return Err(format!("origin mismatch: {}", cd["origin"]));
    }

    if auth_data.len() < 37 {
        return Err("authenticatorData too short".into());
    }
    if auth_data[..32] != Sha256::digest(cred.rp_id.as_bytes())[..] {
        return Err("rpIdHash mismatch".into());
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err("user presence flag not set".into());
    }
    if flags & 0x04 == 0 {
        return Err("user verification flag not set (phone did not check fingerprint/lock)".into());
    }

    let spki = B64.decode(&cred.public_key_spki).map_err(|e| e.to_string())?;
    let key = VerifyingKey::from_public_key_der(&spki).map_err(|e| e.to_string())?;
    let sig = Signature::from_der(&signature).map_err(|e| e.to_string())?;
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    key.verify(&signed, &sig).map_err(|_| "signature does not verify".to_string())
}

// ---------------------------------------------------------------- commands

fn user_label() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let host = fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_default();
    if host.is_empty() { user } else { format!("{user}@{host}") }
}

async fn require_bluetooth() -> AnyResult<()> {
    if is_available().await {
        Ok(())
    } else {
        Err("no Bluetooth adapter available (is it powered on? `omarchy-bluetooth-power`)".into())
    }
}

async fn enroll(rp_id: &str) -> AnyResult<()> {
    require_bluetooth().await?;
    let origin = format!("https://{rp_id}");
    let user = user_label();
    let request_json = serde_json::json!({
        "rp": { "id": rp_id, "name": "Omarchy" },
        "user": { "id": random_b64(16), "name": user, "displayName": user },
        "challenge": random_b64(32),
        "pubKeyCredParams": [{ "type": "public-key", "alg": ES256 }],
        "timeout": CEREMONY_TIMEOUT.as_millis() as u64,
        "authenticatorSelection": { "residentKey": "preferred", "userVerification": "required" },
        "attestation": "none"
    })
    .to_string();

    // The origin is ours to vouch for: this program is the client, and the
    // rp id is a local name, not a website anyone else can serve.
    let settings = RequestSettings { origin: OriginValidation::Trust };
    let request_origin: RequestOrigin = origin.as_str().try_into()?;
    let request = MakeCredentialRequest::prepare(&request_origin, &request_json, &settings).await?;

    println!("Enrolling a phone for {user} (rp id \"{rp_id}\").");
    let store = FileDeviceStore::open();
    let mut channel = qr_channel(QrCodeOperationHint::MakeCredential, store.clone()).await?;
    tokio::spawn(report_updates(channel.get_ux_update_receiver()));

    let started = Instant::now();
    let response = loop {
        match tokio::time::timeout(CEREMONY_TIMEOUT, channel.webauthn_make_credential(&request)).await {
            Err(_) => return Err("timed out waiting for the phone".into()),
            Ok(Ok(r)) => break r,
            Ok(Err(e)) if is_retryable(&e) => continue,
            Ok(Err(e)) => return Err(format!("phone refused or failed: {e:?}").into()),
        }
    };
    let json = response.to_json_value(&request)?;
    // Give the phone a moment to send linking info before closing.
    tokio::time::sleep(Duration::from_secs(2)).await;
    channel.close().await;

    let alg = json.pointer("/response/publicKeyAlgorithm").and_then(|v| v.as_i64());
    if alg != Some(ES256) {
        return Err(format!("phone created an unsupported key type (COSE alg {alg:?})").into());
    }
    let spki = json_b64(&json, "/response/publicKey")?;
    let cred = Credential {
        rp_id: rp_id.to_string(),
        credential_id: B64.encode(json_b64(&json, "/rawId")?),
        public_key_spki: B64.encode(spki),
        user,
        enrolled_unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    };
    cred.save()?;

    println!("\nENROLLED in {:.1}s. Passkey stored on the phone; public key saved to {}", started.elapsed().as_secs_f32(), Credential::path().display());
    match store.first() {
        Some(d) => println!("Linked phone: \"{}\" (verify will try it without a QR first)", d.name),
        None => println!("The phone did not offer linking: every verify will show a QR."),
    }
    Ok(())
}

/// Returns Ok(true) when verified, Ok(false) when the phone answered but the
/// answer is not acceptable.
async fn verify(force_qr: bool) -> AnyResult<bool> {
    require_bluetooth().await?;
    let cred = Credential::load()?;
    let origin = format!("https://{}", cred.rp_id);
    let challenge = random_b64(32);
    let request_json = serde_json::json!({
        "challenge": challenge,
        "timeout": CEREMONY_TIMEOUT.as_millis() as u64,
        "rpId": cred.rp_id,
        "allowCredentials": [{ "type": "public-key", "id": cred.credential_id, "transports": ["hybrid"] }],
        "userVerification": "required"
    })
    .to_string();
    let settings = RequestSettings { origin: OriginValidation::Trust };
    let request_origin: RequestOrigin = origin.as_str().try_into()?;
    let request = GetAssertionRequest::prepare(&request_origin, &request_json, &settings).await?;

    let store = FileDeviceStore::open();
    let started = Instant::now();
    let linked = if force_qr { None } else { store.first() };
    let mut channel = match linked {
        Some(stored) => {
            let info = PxpKnownDeviceInfo::try_from(&stored)?;
            match tokio::time::timeout(Duration::from_secs(45), linked_channel(&info, store.clone())).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    println!("  linked phone unavailable ({e}); falling back to QR");
                    qr_channel(QrCodeOperationHint::GetAssertionRequest, store.clone()).await?
                }
                Err(_) => {
                    println!("  linked phone did not answer; falling back to QR");
                    qr_channel(QrCodeOperationHint::GetAssertionRequest, store.clone()).await?
                }
            }
        }
        None => qr_channel(QrCodeOperationHint::GetAssertionRequest, store.clone()).await?,
    };
    tokio::spawn(report_updates(channel.get_ux_update_receiver()));

    let response = loop {
        match tokio::time::timeout(CEREMONY_TIMEOUT, channel.webauthn_get_assertion(&request)).await {
            Err(_) => return Err("timed out waiting for the phone".into()),
            Ok(Ok(r)) => break r,
            Ok(Err(e)) if is_retryable(&e) => continue,
            Ok(Err(e)) => {
                println!("\nREFUSED: {e:?}");
                channel.close().await;
                return Ok(false);
            }
        }
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    channel.close().await;

    let assertion = response.assertions.first().ok_or("phone returned no assertion")?;
    let json = assertion.to_json_value(&request)?;
    match check_assertion(&cred, &origin, &challenge, &json) {
        Ok(()) => {
            println!("\nOK: verified {} via phone in {:.1}s", cred.user, started.elapsed().as_secs_f32());
            Ok(true)
        }
        Err(reason) => {
            println!("\nFAILED: {reason}");
            Ok(false)
        }
    }
}

fn status() -> AnyResult<()> {
    match Credential::load() {
        Ok(c) => println!("Enrolled: {} (rp id \"{}\")", c.user, c.rp_id),
        Err(_) => println!("No phone enrolled."),
    }
    match FileDeviceStore::open().first() {
        Some(d) => println!("Linked phone: \"{}\" via {}", d.name, d.tunnel_domain),
        None => println!("No linked phone (verify shows a QR)."),
    }
    println!("State: {}", state_dir().display());
    Ok(())
}

fn forget() -> AnyResult<()> {
    let dir = state_dir();
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    println!("Removed {}. Also delete the \"Omarchy\" passkey from the phone's password manager.", dir.display());
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage: omarchy-phone-auth-spike <command>\n\n  \
         enroll [--rp-id ID]  register a phone passkey (default rp id: {DEFAULT_RP_ID})\n  \
         verify [--qr]        authenticate with the phone; exit 0 ok, 1 refused, 2 error\n  \
         status               show what is enrolled\n  \
         forget               delete local enrollment data\n\n\
         RUST_LOG=debug for transport details."
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["enroll"] => enroll(DEFAULT_RP_ID).await.map(|_| true),
        ["enroll", "--rp-id", id] => enroll(id).await.map(|_| true),
        ["verify"] => verify(false).await,
        ["verify", "--qr"] => verify(true).await,
        ["status"] => status().map(|_| true),
        ["forget"] => forget().map(|_| true),
        _ => usage(),
    };
    match result {
        Ok(true) => std::process::exit(0),
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey as _;

    const ORIGIN: &str = "https://omarchy.localhost";
    const CHALLENGE: &str = "Y2hhbGxlbmdl";

    /// A software stand-in for the phone: signs the way a WebAuthn
    /// authenticator does, so check_assertion is exercised end to end.
    fn fixture(flags: u8) -> (Credential, serde_json::Value, SigningKey) {
        let key = SigningKey::random(&mut rand::thread_rng());
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let cred_id = vec![7u8; 16];
        let cred = Credential {
            rp_id: "omarchy.localhost".into(),
            credential_id: B64.encode(&cred_id),
            public_key_spki: B64.encode(spki.as_bytes()),
            user: "test".into(),
            enrolled_unix: 0,
        };
        let response = sign(&key, &cred_id, flags, "webauthn.get", CHALLENGE, ORIGIN, "omarchy.localhost");
        (cred, response, key)
    }

    fn sign(key: &SigningKey, cred_id: &[u8], flags: u8, ty: &str, challenge: &str, origin: &str, rp_id: &str) -> serde_json::Value {
        let client_data = serde_json::json!({ "type": ty, "challenge": challenge, "origin": origin }).to_string();
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 0]);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let sig: Signature = key.sign(&signed);
        serde_json::json!({
            "rawId": B64.encode(cred_id),
            "response": {
                "clientDataJSON": B64.encode(client_data),
                "authenticatorData": B64.encode(auth_data),
                "signature": B64.encode(sig.to_der().as_bytes()),
            }
        })
    }

    #[test]
    fn accepts_valid_assertion() {
        let (cred, resp, _) = fixture(0x05);
        assert_eq!(check_assertion(&cred, ORIGIN, CHALLENGE, &resp), Ok(()));
    }

    #[test]
    fn rejects_missing_user_verification() {
        let (cred, resp, _) = fixture(0x01);
        assert!(check_assertion(&cred, ORIGIN, CHALLENGE, &resp).unwrap_err().contains("verification"));
    }

    #[test]
    fn rejects_replayed_challenge() {
        let (cred, resp, _) = fixture(0x05);
        assert_eq!(check_assertion(&cred, ORIGIN, "b3RoZXI", &resp), Err("challenge mismatch".into()));
    }

    #[test]
    fn rejects_other_key() {
        let (cred, _, _) = fixture(0x05);
        let other = SigningKey::random(&mut rand::thread_rng());
        let resp = sign(&other, &[7u8; 16], 0x05, "webauthn.get", CHALLENGE, ORIGIN, "omarchy.localhost");
        assert_eq!(check_assertion(&cred, ORIGIN, CHALLENGE, &resp), Err("signature does not verify".into()));
    }

    #[test]
    fn rejects_other_rp_and_type() {
        let (cred, _, key) = fixture(0x05);
        let resp = sign(&key, &[7u8; 16], 0x05, "webauthn.get", CHALLENGE, ORIGIN, "example.org");
        assert_eq!(check_assertion(&cred, ORIGIN, CHALLENGE, &resp), Err("rpIdHash mismatch".into()));
        let resp = sign(&key, &[7u8; 16], 0x05, "webauthn.create", CHALLENGE, ORIGIN, "omarchy.localhost");
        assert!(check_assertion(&cred, ORIGIN, CHALLENGE, &resp).is_err());
    }

    #[test]
    fn rejects_other_credential() {
        let (cred, _, key) = fixture(0x05);
        let resp = sign(&key, &[9u8; 16], 0x05, "webauthn.get", CHALLENGE, ORIGIN, "omarchy.localhost");
        assert!(check_assertion(&cred, ORIGIN, CHALLENGE, &resp).unwrap_err().contains("different credential"));
    }
}
