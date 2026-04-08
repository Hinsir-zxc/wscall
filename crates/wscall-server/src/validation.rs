#![allow(dead_code)]

use serde_json::{Map, Value, json};
use validator::{ValidationError, ValidationErrors, ValidationErrorsKind};

pub use validator::Validate;

pub fn required<T>(value: &Option<T>) -> Result<(), ValidationError> {
    if value.is_none() {
        return Err(simple_error("required", "value is required"));
    }
    Ok(())
}

pub fn assert_true(value: &bool) -> Result<(), ValidationError> {
    if !*value {
        return Err(simple_error("assert_true", "value must be true"));
    }
    Ok(())
}

pub fn assert_false(value: &bool) -> Result<(), ValidationError> {
    if *value {
        return Err(simple_error("assert_false", "value must be false"));
    }
    Ok(())
}

pub fn not_empty(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(simple_error("not_empty", "value cannot be empty"));
    }
    Ok(())
}

pub fn not_blank(value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(simple_error("not_blank", "value cannot be blank"));
    }
    Ok(())
}

pub fn no_whitespace(value: &str) -> Result<(), ValidationError> {
    if value.chars().any(char::is_whitespace) {
        return Err(simple_error(
            "no_whitespace",
            "value cannot contain whitespace",
        ));
    }
    Ok(())
}

pub fn alphabetic(value: &str) -> Result<(), ValidationError> {
    if !value.chars().all(char::is_alphabetic) {
        return Err(simple_error(
            "alphabetic",
            "value must contain only letters",
        ));
    }
    Ok(())
}

pub fn alphanumeric(value: &str) -> Result<(), ValidationError> {
    if !value.chars().all(char::is_alphanumeric) {
        return Err(simple_error(
            "alphanumeric",
            "value must contain only letters or digits",
        ));
    }
    Ok(())
}

pub fn ascii_alphanumeric(value: &str) -> Result<(), ValidationError> {
    if !value.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return Err(simple_error(
            "ascii_alphanumeric",
            "value must contain only ASCII letters or digits",
        ));
    }
    Ok(())
}

pub fn numeric_text(value: &str) -> Result<(), ValidationError> {
    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(simple_error(
            "numeric_text",
            "value must contain only digits",
        ));
    }
    Ok(())
}

pub fn lowercase(value: &str) -> Result<(), ValidationError> {
    if value
        .chars()
        .any(|ch| ch.is_alphabetic() && !ch.is_lowercase())
    {
        return Err(simple_error("lowercase", "value must be lowercase"));
    }
    Ok(())
}

pub fn uppercase(value: &str) -> Result<(), ValidationError> {
    if value
        .chars()
        .any(|ch| ch.is_alphabetic() && !ch.is_uppercase())
    {
        return Err(simple_error("uppercase", "value must be uppercase"));
    }
    Ok(())
}

pub fn non_empty_vec<T>(value: &[T]) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(simple_error("not_empty", "collection cannot be empty"));
    }
    Ok(())
}

pub fn non_empty_map<K, V, S>(
    value: &std::collections::HashMap<K, V, S>,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(simple_error("not_empty", "map cannot be empty"));
    }
    Ok(())
}

pub fn positive_i32(value: i32) -> Result<(), ValidationError> {
    if value <= 0 {
        return Err(simple_error("positive", "value must be greater than 0"));
    }
    Ok(())
}

pub fn non_negative_i32(value: i32) -> Result<(), ValidationError> {
    if value < 0 {
        return Err(simple_error(
            "non_negative",
            "value must be greater than or equal to 0",
        ));
    }
    Ok(())
}

pub fn positive_i64(value: i64) -> Result<(), ValidationError> {
    if value <= 0 {
        return Err(simple_error("positive", "value must be greater than 0"));
    }
    Ok(())
}

pub fn non_negative_i64(value: i64) -> Result<(), ValidationError> {
    if value < 0 {
        return Err(simple_error(
            "non_negative",
            "value must be greater than or equal to 0",
        ));
    }
    Ok(())
}

pub fn positive_f64(value: f64) -> Result<(), ValidationError> {
    if value <= 0.0 {
        return Err(simple_error("positive", "value must be greater than 0"));
    }
    Ok(())
}

pub fn non_negative_f64(value: f64) -> Result<(), ValidationError> {
    if value < 0.0 {
        return Err(simple_error(
            "non_negative",
            "value must be greater than or equal to 0",
        ));
    }
    Ok(())
}

pub fn percentage(value: f64) -> Result<(), ValidationError> {
    if !(0.0..=100.0).contains(&value) {
        return Err(simple_error(
            "percentage",
            "value must be between 0 and 100",
        ));
    }
    Ok(())
}

pub fn errors_to_details(errors: &ValidationErrors) -> Value {
    let mut fields = Map::new();

    for (field, kind) in errors.errors() {
        fields.insert(field.to_string(), error_kind_to_value(kind));
    }

    Value::Object(fields)
}

fn error_kind_to_value(kind: &ValidationErrorsKind) -> Value {
    match kind {
        ValidationErrorsKind::Field(errors) => Value::Array(
            errors
                .iter()
                .map(|error| {
                    json!({
                        "code": error.code,
                        "message": error.message.as_ref().map(|message| message.to_string()),
                        "params": error.params,
                    })
                })
                .collect(),
        ),
        ValidationErrorsKind::List(items) => {
            let mut list = Map::new();
            for (index, nested) in items {
                list.insert(index.to_string(), errors_to_details(nested));
            }
            Value::Object(list)
        }
        ValidationErrorsKind::Struct(nested) => errors_to_details(nested),
    }
}

fn simple_error(code: &'static str, message: &'static str) -> ValidationError {
    let mut error = ValidationError::new(code);
    error.message = Some(message.into());
    error
}

#[macro_export]
macro_rules! wscall_regex_validator {
    ($name:ident, $pattern:literal, $code:literal) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            static REGEX: ::std::sync::OnceLock<::regex::Regex> = ::std::sync::OnceLock::new();
            let regex = REGEX.get_or_init(|| {
                ::regex::Regex::new($pattern)
                    .expect("invalid regex pattern in wscall_regex_validator!")
            });

            if regex.is_match(value) {
                Ok(())
            } else {
                let mut error = ::validator::ValidationError::new($code);
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value does not match pattern {}",
                    $pattern
                )));
                Err(error)
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_min_length_validator {
    ($name:ident, $min:expr) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            let len = value.chars().count();
            if len < $min {
                let mut error = ::validator::ValidationError::new("min_length");
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "length must be at least {}",
                    $min
                )));
                error.add_param(::std::borrow::Cow::Borrowed("min"), &$min);
                error.add_param(::std::borrow::Cow::Borrowed("actual"), &len);
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_max_length_validator {
    ($name:ident, $max:expr) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            let len = value.chars().count();
            if len > $max {
                let mut error = ::validator::ValidationError::new("max_length");
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "length must be at most {}",
                    $max
                )));
                error.add_param(::std::borrow::Cow::Borrowed("max"), &$max);
                error.add_param(::std::borrow::Cow::Borrowed("actual"), &len);
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_length_range_validator {
    ($name:ident, $min:expr, $max:expr) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            let len = value.chars().count();
            if !($min..=$max).contains(&len) {
                let mut error = ::validator::ValidationError::new("length_range");
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "length must be between {} and {}",
                    $min, $max
                )));
                error.add_param(::std::borrow::Cow::Borrowed("min"), &$min);
                error.add_param(::std::borrow::Cow::Borrowed("max"), &$max);
                error.add_param(::std::borrow::Cow::Borrowed("actual"), &len);
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_contains_validator {
    ($name:ident, $needle:literal, $code:literal) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            if value.contains($needle) {
                Ok(())
            } else {
                let mut error = ::validator::ValidationError::new($code);
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value must contain {}",
                    $needle
                )));
                Err(error)
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_not_contains_validator {
    ($name:ident, $needle:literal, $code:literal) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            if value.contains($needle) {
                let mut error = ::validator::ValidationError::new($code);
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value cannot contain {}",
                    $needle
                )));
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_one_of_validator {
    ($name:ident, [$($value:expr),+ $(,)?], $code:literal) => {
        fn $name(value: &str) -> Result<(), ::validator::ValidationError> {
            const ALLOWED: &[&str] = &[$($value),+];
            if ALLOWED.contains(&value) {
                Ok(())
            } else {
                let mut error = ::validator::ValidationError::new($code);
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value must be one of {:?}",
                    ALLOWED
                )));
                Err(error)
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_numeric_min_validator {
    ($name:ident, $ty:ty, $min:expr) => {
        fn $name(value: $ty) -> Result<(), ::validator::ValidationError> {
            if value < $min {
                let mut error = ::validator::ValidationError::new("min");
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value must be greater than or equal to {}",
                    $min
                )));
                error.add_param(::std::borrow::Cow::Borrowed("min"), &$min);
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_numeric_max_validator {
    ($name:ident, $ty:ty, $max:expr) => {
        fn $name(value: $ty) -> Result<(), ::validator::ValidationError> {
            if value > $max {
                let mut error = ::validator::ValidationError::new("max");
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value must be less than or equal to {}",
                    $max
                )));
                error.add_param(::std::borrow::Cow::Borrowed("max"), &$max);
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! wscall_numeric_range_validator {
    ($name:ident, $ty:ty, $min:expr, $max:expr) => {
        fn $name(value: $ty) -> Result<(), ::validator::ValidationError> {
            if !($min..=$max).contains(&value) {
                let mut error = ::validator::ValidationError::new("range");
                error.message = Some(::std::borrow::Cow::Owned(format!(
                    "value must be between {} and {}",
                    $min, $max
                )));
                error.add_param(::std::borrow::Cow::Borrowed("min"), &$min);
                error.add_param(::std::borrow::Cow::Borrowed("max"), &$max);
                Err(error)
            } else {
                Ok(())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    wscall_min_length_validator!(validate_min_len_3, 3);
    wscall_max_length_validator!(validate_max_len_5, 5);
    wscall_length_range_validator!(validate_len_2_to_4, 2, 4);
    wscall_numeric_range_validator!(validate_age_range, i32, 1, 150);
    wscall_one_of_validator!(validate_env, ["dev", "test", "prod"], "invalid_env");

    #[test]
    fn built_in_string_validators_work() {
        assert!(not_blank("hello").is_ok());
        assert!(not_blank("   ").is_err());
        assert!(ascii_alphanumeric("abc123").is_ok());
        assert!(ascii_alphanumeric("abc-123").is_err());
        assert!(numeric_text("123456").is_ok());
        assert!(numeric_text("12a456").is_err());
    }

    #[test]
    fn macro_validators_work() {
        assert!(validate_min_len_3("abc").is_ok());
        assert!(validate_min_len_3("ab").is_err());
        assert!(validate_max_len_5("abcde").is_ok());
        assert!(validate_max_len_5("abcdef").is_err());
        assert!(validate_len_2_to_4("abc").is_ok());
        assert!(validate_len_2_to_4("a").is_err());
        assert!(validate_age_range(42).is_ok());
        assert!(validate_age_range(151).is_err());
        assert!(validate_env("prod").is_ok());
        assert!(validate_env("stage").is_err());
    }
}
