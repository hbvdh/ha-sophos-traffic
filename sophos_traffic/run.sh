#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -e

if ! bashio::services.available "mqtt"; then
    bashio::exit.nok "Geen MQTT-service gevonden. Is de Mosquitto broker add-on gestart?"
fi

export MQTT_HOST="$(bashio::services mqtt 'host')"
export MQTT_PORT="$(bashio::services mqtt 'port')"
export MQTT_USER="$(bashio::services mqtt 'username')"
export MQTT_PASS="$(bashio::services mqtt 'password')"

export FIREWALL_IP="$(bashio::config 'firewall_ip')"
export FLUSH_INTERVAL="$(bashio::config 'flush_interval')"
export MAX_CATEGORIES="$(bashio::config 'max_categories')"
export LOG_LEVEL="$(bashio::config 'log_level')"
export LISTEN_PORT="5514"
export STATE_FILE="/data/state.json"

bashio::log.info "Sophos Traffic Collector start op UDP ${LISTEN_PORT}, MQTT ${MQTT_HOST}:${MQTT_PORT}"
exec python3 -u /collector.py
