#!/usr/bin/env zsh
########################
# NoMAD Removal Script #
########################
# This script removes NoMAD from the system. It will stop the NoMAD process, unload the LaunchAgents,
# remove the application specific files, and remove the user-specific files.
#
# Author: Patrick Doyle (pdoyle@glaciermedia.ca)
# Version: v0.202601.09
#
# [Jamf Policy Usage]
# 	Intended for use in a Jamf Policy to remove NoMAD from the system.
# 	It can also be used manually if needed.
#
# [Manual Usage]
# - Login as a user with admin privileges... You can do this from the user's terminal by running
#	the following command:
#	> sudo su jamfadmin
# - Run the script:
#	> curl -sS https://raw.githubusercontent.com/pcdoyle/jamf-scripts/refs/heads/main/remove-nomad.sh | sudo zsh

# Process termination settings
readonly TERMINATE_TIMEOUT=120        # Maximum seconds to wait for termination
readonly TERMINATE_CHECK_INTERVAL=10  # Seconds between termination checks
# Exit codes (for Jamf logging)
readonly EXIT_SUCCESS=0
readonly EXIT_NOT_ROOT=1
readonly EXIT_NO_USER=2
readonly EXIT_REMOVAL_FAILED=3
readonly EXIT_TERMINATION_FAILED=4
readonly EXIT_INTERRUPTED=130 # SIGINT Code

trap 'error "Script interrupted"; exit $EXIT_INTERRUPTED' INT TERM

# For Jamf logging
function log {
	local level=$1
	shift
	local message="$@"
	local timestamp=$(date -u "+%Y-%m-%d %H:%M:%S")
	
	echo "$timestamp [$level] $message"
}

function info { log "INFO" "$@"; }
function skip { log "SKIP" "$@"; }
function error { log "ERROR" "$@"; }

function remove_file {
	if [[ -f "$1" ]]; then
		info "Removing $1"
		if rm "$1" 2>/dev/null; then
			info "Successfully removed $1"
		else
			error "Failed to remove $1"
			return $EXIT_REMOVAL_FAILED
		fi
	else
		skip "$1 not present"
	fi
}

function remove_dir {
	if [[ -d "$1" ]]; then
		info "Removing $1"
		if rm -fr "$1" 2>/dev/null; then
			info "Successfully removed $1"
		else
			error "Failed to remove $1"
			return $EXIT_REMOVAL_FAILED
		fi
	else
		skip "$1 not present"
	fi
}

function unload_launchagent {
	if [[ -f "$1" ]]; then
		info "Unloading LaunchAgent: $1"
		if launchctl unload "$1" 2>/dev/null; then
			info "Successfully unloaded $1"
		else
			skip "$1 not loaded (may not be running)"
		fi
	else
		skip "$1 not present"
	fi
}

function wait_for_process_termination {
	local process_name=$1
	local timeout=$2
	local check_interval=$3
	local elapsed=0
	
	while [[ $elapsed -lt $timeout ]]; do
		if ! pgrep "$process_name" >/dev/null 2>&1; then
			info "Process $process_name terminated successfully (checked at ${elapsed}s)"
			return 0
		fi
		
		info "Checking if $process_name is still running... (${elapsed}s/${timeout}s)"
		sleep "$check_interval"
		elapsed=$((elapsed + check_interval))
	done
	
	if ! pgrep "$process_name" >/dev/null 2>&1; then
		info "Process $process_name terminated successfully (checked at ${elapsed}s)"
		return 0
	fi
	
	info "Timeout reached: $process_name still running after ${timeout}s"
	return 1
}

readonly CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')

# Blank line for Jamf log formatting
echo ""
info "Starting NoMAD removal"

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root. Please run with sudo."
    exit $EXIT_NOT_ROOT
fi

if [[ -z "$CURRENT_USER" ]] || [[ "$CURRENT_USER" == "root" ]]; then
	error "Could not determine logged-in user or user is root."
	error "Cannot proceed with user-specific cleanup."
	exit $EXIT_NO_USER
fi

info "Detected user: $CURRENT_USER"

# Unload LaunchAgents
unload_launchagent "/Library/LaunchAgents/com.trusourcelabs.NoMAD.plist"
unload_launchagent "/Users/$CURRENT_USER/Library/LaunchAgents/com.trusourcelabs.NoMAD.plist"

# Remove LaunchAgents
remove_file "/Library/LaunchAgents/com.trusourcelabs.NoMAD.plist"
remove_file "/Users/$CURRENT_USER/Library/LaunchAgents/com.trusourcelabs.NoMAD.plist"

info "Attempting to kill NoMAD process"

NOMAD_PIDS=$(pgrep "NoMAD" 2>/dev/null)
if [[ -n "$NOMAD_PIDS" ]]; then
	info "Found NoMAD process(es) with PID(s): $(echo $NOMAD_PIDS | tr '\n' ' ')"
	
	# Send SIGTERM
	info "Sending termination signal to NoMAD process"
	if pkill "NoMAD" 2>/dev/null; then
		info "Termination signal sent, waiting for process to exit"
		
		# Wait for termination
		if wait_for_process_termination "NoMAD" "$TERMINATE_TIMEOUT" "$TERMINATE_CHECK_INTERVAL"; then
			info "NoMAD process terminated successfully"
		else
			# Force SIGTERM
			info "NoMAD process did not terminate after ${TERMINATE_TIMEOUT}s, attempting force kill"
			if pkill -9 "NoMAD" 2>/dev/null; then
				info "Force kill signal sent, waiting for process to exit"
				
				# Wait for termination
				if wait_for_process_termination "NoMAD" "$TERMINATE_TIMEOUT" "$TERMINATE_CHECK_INTERVAL"; then
					info "NoMAD process terminated after force kill"
				else
					error "NoMAD process failed to terminate after force kill (waited ${TERMINATE_TIMEOUT}s)"
					exit $EXIT_TERMINATION_FAILED
				fi
			else
				error "Failed to send force kill signal to NoMAD process"
				exit $EXIT_TERMINATION_FAILED
			fi
		fi
	else
		error "Failed to send termination signal to NoMAD process"
		exit $EXIT_TERMINATION_FAILED
	fi
else
	skip "NoMAD process not running"
fi

# Note by Patrick:
# 	I made a mistake with an earlier script so I need to reset the login window for JamfConnect.
# 	This should only execute on the handful of machines that I turned the login window off for.
if [[ -d "/Applications/Jamf Connect.app" ]]; then
	info "JamfConnect is installed"
	if [[ -f "/usr/local/bin/authchanger" ]]; then
		if /usr/local/bin/authchanger -print 2>/dev/null | grep -q "JamfConnectLogin"; then
			skip "Login window already configured for JamfConnect"
		else
			info "Resetting login window to JamfConnect (authchanger -reset -jamfconnect)"
			if /usr/local/bin/authchanger -reset -jamfconnect 2>/dev/null; then
				info "Successfully reset login window to JamfConnect"
			else
				error "Failed to reset login window to JamfConnect"
			fi
		fi
	else
		skip "authchanger not found (cannot reset login window)"
	fi
else
	skip "JamfConnect not installed (no login window changes needed)"
fi

remove_dir "/Applications/NoMAD.app"
remove_dir "/Users/$CURRENT_USER/Library/Caches/com.trusourcelabs.NoMAD"
remove_dir "/Users/$CURRENT_USER/Library/HTTPStorages/com.trusourcelabs.NoMAD"
remove_file "/Users/$CURRENT_USER/Library/Preferences/com.trusourcelabs.NoMAD.plist"

# Sometimes the managed preferences are left over even when removed in Jamf...
remove_file "/Library/Managed Preferences/com.trusourcelabs.NoMAD.plist"
remove_file "/Library/Managed Preferences/$CURRENT_USER/com.trusourcelabs.NoMAD.plist"

info "Script completed successfully"
exit $EXIT_SUCCESS
