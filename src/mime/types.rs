//! Go's extension-to-type registry: the built-in table, the unix system
//! database and [`add_extension_type`], with Go's lookup order.
//!
//! The built-in table is Go's `builtinTypesLower`. On unix the registry is
//! augmented once, on first use, from `/usr/local/share/mime/globs2` or
//! `/usr/share/mime/globs2` if one can be opened, and otherwise from the first
//! of `/etc/mime.types`, `/etc/apache2/mime.types`, `/etc/apache/mime.types`
//! and `/etc/httpd/conf/mime.types` that exist. On other platforms only the
//! built-in table is used; Go reads the Windows registry there.
use super::mediatype::{format_media_type, parse_media_type};
use super::Error;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

/// Go's `builtinTypesLower`: a type is listed if both Firefox and Chrome list it.
const BUILTIN_TYPES: [(&str, &str); 65] = [
    (".ai", "application/postscript"),
    (".apk", "application/vnd.android.package-archive"),
    (".apng", "image/apng"),
    (".avif", "image/avif"),
    (".bin", "application/octet-stream"),
    (".bmp", "image/bmp"),
    (".com", "application/octet-stream"),
    (".css", "text/css; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".doc", "application/msword"),
    (
        ".docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (".ehtml", "text/html; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".eps", "application/postscript"),
    (".exe", "application/octet-stream"),
    (".flac", "audio/flac"),
    (".gif", "image/gif"),
    (".gz", "application/gzip"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ics", "text/calendar; charset=utf-8"),
    (".jfif", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".m4a", "audio/mp4"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".oga", "audio/ogg"),
    (".ogg", "audio/ogg"),
    (".ogv", "video/ogg"),
    (".opus", "audio/ogg"),
    (".pdf", "application/pdf"),
    (".pjp", "image/jpeg"),
    (".pjpeg", "image/jpeg"),
    (".png", "image/png"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (
        ".pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    (".ps", "application/postscript"),
    (".rdf", "application/rdf+xml"),
    (".rtf", "application/rtf"),
    (".shtml", "text/html; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".text", "text/plain; charset=utf-8"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".txt", "text/plain; charset=utf-8"),
    (".vtt", "text/vtt; charset=utf-8"),
    (".wasm", "application/wasm"),
    (".wav", "audio/wav"),
    (".weba", "audio/webm"),
    (".webm", "video/webm"),
    (".webp", "image/webp"),
    (".xbl", "text/xml; charset=utf-8"),
    (".xbm", "image/x-xbitmap"),
    (".xht", "application/xhtml+xml"),
    (".xhtml", "application/xhtml+xml"),
    (".xls", "application/vnd.ms-excel"),
    (
        ".xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (".xml", "text/xml; charset=utf-8"),
    (".xsl", "text/xml; charset=utf-8"),
    (".zip", "application/zip"),
];

#[cfg(unix)]
const MIME_GLOBS: [&str; 2] = ["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"];
#[cfg(unix)]
const TYPE_FILES: [&str; 4] = [
    "/etc/mime.types",
    "/etc/apache2/mime.types",
    "/etc/apache/mime.types",
    "/etc/httpd/conf/mime.types",
];

#[derive(Default)]
struct Registry {
    /// Go's `mimeTypes`: keys as registered, matched case-sensitively first.
    by_extension: HashMap<String, String>,
    /// Go's `mimeTypesLower`: keys lower-cased.
    by_lower_extension: HashMap<String, String>,
    /// Go's `extensions`: lower-case extensions by media type, unsorted.
    by_type: HashMap<String, Vec<String>>,
}

impl Registry {
    fn set_extension_type(&mut self, extension: &str, mime_type: &str) -> Result<(), Error> {
        let (just_type, params) = parse_media_type(mime_type);
        let mut params = params?;
        let mut mime_type = mime_type.to_owned();
        if mime_type.starts_with("text/") && params.get("charset").is_none_or(String::is_empty) {
            params.insert("charset".to_owned(), "utf-8".to_owned());
            mime_type = format_media_type(&just_type, &params).unwrap_or_default();
        }
        let lower = extension.to_lowercase();
        self.by_extension
            .insert(extension.to_owned(), mime_type.clone());
        self.by_lower_extension.insert(lower.clone(), mime_type);
        let extensions = self.by_type.entry(just_type).or_default();
        if !extensions.contains(&lower) {
            extensions.push(lower);
        }
        Ok(())
    }

    /// Go's `loadMimeGlobsFile`; returns false when the file cannot be opened.
    #[cfg(unix)]
    fn load_globs(&mut self, path: &str) -> bool {
        use std::io::BufRead;
        let Ok(file) = std::fs::File::open(path) else {
            return false;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            // Each line is weight:mimetype:glob[:morefields...].
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 3 || fields[0].is_empty() || fields[2].len() < 3 {
                continue;
            }
            if fields[0].starts_with('#') || !fields[2].starts_with("*.") {
                continue;
            }
            let extension = &fields[2][1..];
            if extension.contains(['?', '*', '[']) || self.by_extension.contains_key(extension) {
                continue;
            }
            let _ = self.set_extension_type(extension, fields[1]);
        }
        true
    }

    /// Go's `loadMimeFile`: `type ext ext ...` lines, with `#` comments.
    #[cfg(unix)]
    fn load_type_file(&mut self, path: &str) {
        use std::io::BufRead;
        let Ok(file) = std::fs::File::open(path) else {
            return;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() <= 1 || fields[0].starts_with('#') {
                continue;
            }
            for ext in &fields[1..] {
                if ext.starts_with('#') {
                    break;
                }
                let _ = self.set_extension_type(&format!(".{ext}"), fields[0]);
            }
        }
    }
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = Registry::default();
        for (extension, mime_type) in BUILTIN_TYPES {
            // The built-in table is valid by construction.
            let _ = registry.set_extension_type(extension, mime_type);
        }
        #[cfg(unix)]
        {
            if !MIME_GLOBS.iter().any(|path| registry.load_globs(path)) {
                for path in TYPE_FILES {
                    registry.load_type_file(path);
                }
            }
        }
        Mutex::new(registry)
    })
}

fn lock() -> MutexGuard<'static, Registry> {
    registry().lock().unwrap_or_else(PoisonError::into_inner)
}

/// Returns the media type for a file extension, with a leading dot as in
/// ".html", or `None` where Go returns "". Lookup is case-sensitive first,
/// then case-insensitive.
pub fn type_by_extension(extension: &str) -> Option<String> {
    let registry = lock();
    registry
        .by_extension
        .get(extension)
        .or_else(|| registry.by_lower_extension.get(&extension.to_lowercase()))
        .cloned()
}

/// Returns the lower-case extensions registered for a media type, sorted.
/// Go returns a nil slice where this returns an empty `Vec`.
pub fn extensions_by_type(media_type: &str) -> Result<Vec<String>, Error> {
    let (just_type, params) = parse_media_type(media_type);
    params?;
    let registry = lock();
    let mut extensions = registry
        .by_type
        .get(&just_type)
        .cloned()
        .unwrap_or_default();
    extensions.sort();
    Ok(extensions)
}

/// Sets the media type for `extension`, which must begin with a dot.
/// `mime_type` is validated as a media type and, for `text/` types, gets
/// `charset=utf-8` when it has no charset.
pub fn add_extension_type(extension: &str, mime_type: &str) -> Result<(), Error> {
    if !extension.starts_with('.') {
        return Err(Error(
            format!(
                "mime: extension {} missing leading dot",
                crate::strconv::quote(extension)
            )
            .into(),
        ));
    }
    lock().set_extension_type(extension, mime_type)
}
