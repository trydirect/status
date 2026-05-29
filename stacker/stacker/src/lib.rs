#![allow(
    dead_code,
    unused_imports,
    clippy::bool_comparison,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::collapsible_str_replace,
    clippy::comparison_to_empty,
    clippy::complexity,
    clippy::cmp_owned,
    clippy::derivable_impls,
    clippy::double_ended_iterator_last,
    clippy::field_reassign_with_default,
    clippy::filter_map_bool_then,
    clippy::format_in_format_args,
    clippy::from_over_into,
    clippy::get_last_with_len,
    clippy::if_same_then_else,
    clippy::inherent_to_string,
    clippy::inefficient_to_string,
    clippy::into_iter_on_ref,
    clippy::io_other_error,
    clippy::iter_kv_map,
    clippy::items_after_test_module,
    clippy::len_zero,
    clippy::let_underscore_future,
    clippy::manual_clamp,
    clippy::manual_contains,
    clippy::manual_pattern_char_comparison,
    clippy::manual_range_contains,
    clippy::manual_split_once,
    clippy::manual_strip,
    clippy::map_identity,
    clippy::match_like_matches_macro,
    clippy::match_single_binding,
    clippy::needless_borrow,
    clippy::needless_return,
    clippy::new_without_default,
    clippy::nonminimal_bool,
    clippy::option_map_unit_fn,
    clippy::ptr_arg,
    clippy::print_literal,
    clippy::redundant_closure,
    clippy::redundant_field_names,
    clippy::single_char_add_str,
    clippy::single_match,
    clippy::should_implement_trait,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_cast,
    clippy::unnecessary_map_or,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_lazy_evaluations,
    clippy::unused_unit,
    clippy::unwrap_or_default,
    clippy::useless_conversion,
    clippy::useless_format,
    clippy::useless_vec,
    clippy::write_literal,
    clippy::wrong_self_convention,
    clippy::for_kv_map
)]

pub mod banner;
pub mod cli;
pub mod configuration;
pub mod connectors;
pub mod console;
pub mod db;
pub mod forms;
pub mod handoff;
pub mod health;
pub mod helpers;
pub mod mcp;
pub mod metrics;
mod middleware;
pub mod models;
pub mod project_app;
pub mod routes;
pub mod services;
pub mod startup;
pub mod telemetry;
pub mod version;
pub mod views;
