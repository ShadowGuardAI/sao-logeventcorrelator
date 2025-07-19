# sao-LogEventCorrelator
Listens to system logs (e.g., syslog) and correlates events based on defined patterns to trigger alerts or actions. Uses `watchdog` for file system monitoring and regular expressions for pattern matching. Supports configurable aggregation windows and alert destinations. - Focused on Enables automated execution of simple security tasks based on predefined schedules and events. Examples include regular log analysis, automated vulnerability scanning initiation, and response actions to common security alerts using existing command-line tools.

## Install
`git clone https://github.com/ShadowGuardAI/sao-logeventcorrelator`

## Usage
`./sao-logeventcorrelator [params]`

## Parameters
- `-h`: Show help message and exit
- `--config`: No description provided
- `--oneshot`: Run the correlation once and exit. Useful for testing.

## License
Copyright (c) ShadowGuardAI
