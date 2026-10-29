use clap::{Arg, ArgAction};

pub(super) fn capability_arg() -> Arg {
    Arg::new("capability")
        .required(true)
        .value_name("PLUGIN.CAPABILITY")
        .help("Qualified capability ref, for example sqlite.query or redis.get")
}

pub(super) fn format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json", "table"])
        .default_value("json")
        .help("Output format; json is stable for agents, table is human-readable")
}

pub(super) fn execution_mode_arg() -> Arg {
    Arg::new("execution-mode")
        .long("execution-mode")
        .value_name("MODE")
        .value_parser(["stateless", "session_only", "both"])
        .action(ArgAction::Append)
        .help("Filter by supported execution mode; repeat to select multiple modes")
}

pub(super) fn run_format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json", "ndjson"])
        .default_value("json")
        .help("Output format: legacy json or versioned streaming ndjson")
}
