//! Small, strict JSON reader for Wazuh API responses (RFC 8259).
//! Read-only on purpose: harrier never needs to emit JSON.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

static NULL: Json = Json::Null;
const MAX_DEPTH: usize = 64;

impl Json {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut p = Parser {
            b: text.as_bytes(),
            i: 0,
        };
        let v = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            return Err(p.err("trailing data"));
        }
        Ok(v)
    }

    /// Object member, or `Null` when missing / not an object.
    pub fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map_or(&NULL, |(_, v)| v),
            _ => &NULL,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            _ => &[],
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 && *n <= 9_007_199_254_740_992.0 => {
                Some(*n as u64)
            }
            _ => None,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, what: &str) -> String {
        format!("invalid JSON at byte {}: {what}", self.i)
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.ws();
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err("unknown literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.err("expected a value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1;
        let mut members = Vec::new();
        if self.eat(b'}') {
            return Ok(Json::Obj(members));
        }
        loop {
            self.ws();
            if self.b.get(self.i) != Some(&b'"') {
                return Err(self.err("expected a key"));
            }
            let key = self.string()?;
            if !self.eat(b':') {
                return Err(self.err("expected ':'"));
            }
            members.push((key, self.value(depth + 1)?));
            if self.eat(b'}') {
                return Ok(Json::Obj(members));
            }
            if !self.eat(b',') {
                return Err(self.err("expected ',' or '}'"));
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1;
        let mut items = Vec::new();
        if self.eat(b']') {
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            if self.eat(b']') {
                return Ok(Json::Arr(items));
            }
            if !self.eat(b',') {
                return Err(self.err("expected ',' or ']'"));
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while matches!(
            self.b.get(self.i),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.i += 1;
        }
        std::str::from_utf8(&self.b[start..self.i])
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .map(Json::Num)
            .ok_or_else(|| self.err("bad number"))
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(&c) = self.b.get(self.i) {
                if c == b'"' || c == b'\\' {
                    break;
                }
                if c < 0x20 {
                    return Err(self.err("control character in string"));
                }
                self.i += 1;
            }
            // Splitting only at ASCII bytes keeps the slice valid UTF-8.
            out.push_str(
                std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("bad UTF-8"))?,
            );
            match self.b.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    self.escape(&mut out)?;
                }
                _ => return Err(self.err("unterminated string")),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), String> {
        let c = *self.b.get(self.i).ok_or_else(|| self.err("bad escape"))?;
        self.i += 1;
        match c {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let hi = self.hex4()?;
                let code = if (0xD800..0xDC00).contains(&hi) && self.b[self.i..].starts_with(b"\\u")
                {
                    self.i += 2;
                    let lo = self.hex4()?;
                    if (0xDC00..0xE000).contains(&lo) {
                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    } else {
                        0xFFFD
                    }
                } else {
                    hi
                };
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            _ => return Err(self.err("bad escape")),
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .b
            .get(self.i..self.i + 4)
            .filter(|d| d.iter().all(u8::is_ascii_hexdigit))
            .ok_or_else(|| self.err("bad \\u escape"))?;
        self.i += 4;
        digits.iter().try_fold(0u32, |acc, &d| {
            char::from(d)
                .to_digit(16)
                .map(|v| acc * 16 + v)
                .ok_or_else(|| self.err("bad \\u escape"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Json;

    #[test]
    fn parses_wazuh_shape() {
        let j = Json::parse(
            r#"{"data":{"affected_items":[{"id":"001","name":"PC-1\u00e9\ud83d\ude00","status":"active"}],
               "total_affected_items":1,"failed_items":[]},"error":0,"ok":true,"x":null,"f":-1.5e2}"#,
        )
        .unwrap();
        let item = &j.get("data").get("affected_items").as_array()[0];
        assert_eq!(item.get("name").as_str(), Some("PC-1é😀"));
        assert_eq!(j.get("data").get("total_affected_items").as_u64(), Some(1));
        assert_eq!(j.get("f"), &Json::Num(-150.0));
        assert_eq!(j.get("missing").get("deeper"), &Json::Null);
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\" 1}",
            "\"\\x\"",
            "tru",
            "1 2",
            "\"a\nb\"",
            "\"\\u12\"",
        ] {
            assert!(Json::parse(bad).is_err(), "accepted {bad:?}");
        }
        assert!(Json::parse(&"[".repeat(100)).is_err());
    }
}
