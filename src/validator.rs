use time::now_utc;

pub struct Validator {
    claims: &Claims,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<Tm>,
    pub nbf: Option<Tm>,
    pub iat: Option<Tm>,
    pub jti: Option<String>,
}

impl Validator {
    fn new(claims: &Claims) -> Self {
        Validator { claims: claims, ..Default::default() }
    }

    fn validate(&self) -> bool {
        const FIELDS: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

        for field in FIELDS {

        }

        false
    }
}

impl Default for Validator {
    fn default() -> Validator {
        Validator {
            iss: None,
            sub: None,
            aud: None,
            exp: now_utc(),
            nbf: now_utc(),
            iat: now_utc(),
            jti: None,
        }
    }
}
