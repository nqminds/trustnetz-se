#!/bin/bash -e
#exit immediately if a command fails

# Retrieve settings from config file 
source ./config.cfg

PRODUCT=${PRODUCT//$'\r'} # remove CR if present
if [ "${PRODUCT}" == "" ]; then 
		echo '***' ERROR missing PRODUCT definition in config.cfg
		exit
fi
echo PRODUCT = ${PRODUCT}

FAMILY=${PRODUCT:0:1}
FAMILY=${FAMILY}"xx"

if([ ! -z ${VAULTIC_COMM} ] ); then 
    vaultic_comm=${VAULTIC_COMM//$'\r'} # remove CR if present
    INTERFACE="${vaultic_comm^^}" # convert to upper case
    if [ "${INTERFACE}" != "I2C" -a "${INTERFACE}" != "SPI" ]; then 
            echo '***' ERROR unexpected value VAULTIC_COMM=${VAULTIC_COMM} in config.cfg
            exit
    fi
    echo INTERFACE = ${INTERFACE}
fi

log_level=${LOG_LEVEL//$'\r'} # remove CR if present
LOG_LEVEL="${log_level^^}" # convert to upper case

echo LOG_LEVEL = ${LOG_LEVEL}

change_i2c_bitrate=${FORCE_I2C_BITRATE//$'\r'} # remove CR if present
CHANGE_I2C_BIT_RATE="${change_i2c_bitrate^^}" # convert to upper case
if [ "${INTERFACE}" != "SPI" -a "${CHANGE_I2C_BIT_RATE}" == "YES" ]; then
    RUN_MODE=sudo
    echo "Running app in sudo mode to force I2C bitrate"
fi

