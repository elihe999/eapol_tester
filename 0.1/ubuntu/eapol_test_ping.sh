#!/bin/bash
#########################################################
# Umbrella script for eapol_test package from freeradius
# Provides simpler usage and a continuous eapol ping for
# redundancy, convergence and availability tests
#########################################################
# Version 1.2 by Johannes Luther
VERSION="1.2"
SCRIPT_NAME="eapol_test_ping"
# 2017/04/25
#########################################################
# Usage
USAGE_SHORT="$SCRIPT_NAME (version $VERSION)\n\
Usage: $0\n\
\t	-m EAP-METHOD -r RADIUS-SERVER -s SHARED-SECRET \n\
\t	[-u USERNAME] [-p PASSWORD] [-a IDENTITY] \n\
\t	[-c SUPPLICANT-CERT] [-k SUPPL-PRIV-KEY] [-kp PRIV-KEY-PASS] \n\
\t	-ca SERVER-CA \n\
\t	[-r6 RADIUS-ATTR-SERVICE-TYPE] [-r7 RADIUS-FRAMED-PROTOCOL] \n\
\t      [-r30 RADIUS-ATTR-CALLED-STATION-ID] [-r31 CALLING-STATION-ID] \n\
\t      [-r32 RADIUS-ATTR-NAS-ID] [-r61 RADIUS-ATTR-NAS-PORT-TYPE] \n\
\t      [-v] [-i DELAY] [-rnd] [-?]\
"

USAGE_HELP="\
\n\n\t 	Options:\n\
\t	-m   EAP-METHOD \t\t	     IANA assigned EAP method type code. Currently implemented is \n\
\t\t\t\t			     13\t	EAP-TLS\n\
\t\t\t\t			     25\t	PEAP\n\
\t      -r   RADIUS-SERVER \t	     RADIUS server IPv4 or resolvable hostname \n\
\t      -s   SHARED-SECRET \t	     RADIUS shared secret \n\
\t      -u   USERNAME \t\t	     Mandatory with PEAP (m 25). Inner username \n\
\t      -p   PASSWORD \t\t           Mandatory with PEAP (m 25). Inner user password \n\
\t      -a   IDENTITY \t\t           Mandatory with PEAP (m 25). Anonymous outer username (default: anonymous) \n\
\t      -c   SUPPLICANT-CERT \t      Mandatory with EAP-TLS (m 13). Filename / supplicant certificate (BASE64 encoded file) \n\
\t      -k   SUPPL-PRIV-KEY \t	     Mandatory with EAP-TLS (m 13). Filename / supplicant private key (BASE64 encoded file) \n\
\t      -kp  PRIV-KEY-PASS \t        Optional with EAP-TLS (m 13). Passphrase for supplicant private key file \n\
\t      -ca  SERVER-CA \t\t	     Filename / CA chain for authentication server (BASE64 encoded file) \n\
\t      -r6  SERVICE-TYPE \t       Optional. RADIUS service type attribute [integer] (default: 2 - framed) \n\
\t      -r7  FRAMED-PROTOCOL \t    Optional. RADIUS framed protocol attribute [integer] (no default) \n\
\t      -r30 CALLED-STATION-ID\t     Optional. RADIUS called-station-id attribute [string] (no default) \n\
\t      -r31 CALLING-STATION-ID    Optional. RADIUS calling-station-id attribute [string] (no default) \n\
\t      -r32 NAS-ID \t\t             Optional. RADIUS NAS-id attribute [string] (default: eapol_test_ping) \n\
\t      -r61 NAS-PORT-TYPE \t        Optional. RADIUS NAS port type attribute [integer] (default: 15 - Ethernet) \n\
\t      -v \t\t\t		Optional. Verbose output (native eapol_test output) \n\
\t      -i DELAY \t\t           Optional. Interval testing with a delay in seconds between the single pings (0-120 seconds)\n\
\t      -rnd \t\t\t             Optional. Use random MAC addresses\n\
\t	-port RADIUS-PORT \t	Optional. RADIUS UDP server port (default: 1812)\n\
\t	-? \t\t\t		Optional. Show detailed help
"
#########################################################
# debug output is disabled (0) per default. Enable debug by set it to 1
DEBUG=0

# Verify certificates with openssl in this script
# In case the files contains no certificates, the script is stoppen (USE_OPENSSL=1)
# If USE_OPENSSL is set to 0, the certs are not checked and directly passed to eapol_test
USE_OPENSSL=1

EAPOL_TEST_BINARY="/usr/local/bin/eapol_test"

# Temporary file for eapol_test configuration
TEMP_FILE=$(mktemp /tmp/eapol_tester_tmp.XXXXXX)

# Additional eapol_test RADIUS attributes (optional) / ARRAY
# deprecated in version 1.2
#EAPOL_RAD_ATTRS=('6:d:2' '61:d:19')

# Some needed functions for the script
function show_debug {
  if [[ $DEBUG -eq 1 ]]; then
    tput setaf 5; echo -n "[debug] "; tput sgr0; echo "$1"
  fi
}
# end of function "show_debug"

function bye {
  if [ -f "$TEMP_FILE" ]; then
    show_debug "deleting temporaty file $TEMP_FILE"
    rm $TEMP_FILE
  fi
  show_debug "exit script...bye"
  exit
}
# end of function "bye"

function show_error {
  tput setaf 1; echo -n "error! "; tput sgr0; echo "$1"
  bye
}
# end of function "show_error"

function show_warn {
  tput setaf 3; echo -n "warning! "; tput sgr0; echo "$1"
}
# end of function "show_warning"

function cert_in_file {
# checks if the file contains a certificate (serial must be present)
# returns 0 if no certificate
# returns 1 if certificate
  if [ -f "$1" ]; then
    show_debug "cert_in_file_check: checking if certificate is in file $1 using openSSL"
    local openssl_output="$(openssl x509 -noout -serial -in $1 | grep serial)"
    show_debug "cert_in_file_check: openssl output: $openssl_output"
    if [ ${#openssl_output} -eq 0 ]; then
      show_error "no valid certificate in file $1"
      bye
    else
      show_debug "valid certificate in file $1"
    fi
  else
    show_error "no valid certificate in file $1"
  fi
}

show_debug "created TEMP_FILE: $TEMP_FILE"

### PARSE COMMAND-LINE PARAMETERS #########################
## set defaults
# verbose output is disabled (0) per default
VERBOSE_OUTPUT=0
# interval testing is not enabled (-1) per default
INTERVAL=-1
# random MAC addresses are disabled (0) per default
RAND_MAC=0
# PEAP anonymous identity is anonymous per default
PEAP_ANON_ID="anonymous"
# EAP-TLS private key is not secured by a passphrase per default (empty string)
EAP_TLS_PRIVPASS=""

# Some needed defaults
ARG_ERROR="0"
NUM_ARGS=$#

while [[ $# > 0 ]]
do
key="$1"

case $key in
    -m|--method)
      ARG_EAP_METHOD="$2"
      show_debug "CMD arg -m / value: $ARG_EAP_METHOD"
      shift # past argument
    ;;
    -r|--radius-server)
      ARG_RAD_SRV="$2"
      show_debug "CMD arg -r / value: $ARG_RAD_SRV"
      shift # past argument
    ;;
    -s|--radius-secret)
      ARG_RAD_SEC="$2"
      show_debug "CMD arg -s / value: $ARG_RAD_SEC"
      shift # past argument
    ;;
    -u|--peap-inner-user)
      ARG_PEAP_USER="$2"
      show_debug "CMD arg -u / value: $ARG_PEAP_USER"
      shift # past argument
    ;;
    -p|--peap-inner-password)
      ARG_PEAP_PW="$2"
      show_debug "CMD arg -p / value: $ARG_PEAP_PW"
      shift # past argument
    ;;
    -a|--peap-outer-id)
      ARG_PEAP_ID="$2"
      show_debug "CMD arg -a / value: $ARG_PEAP_ID"
      shift # past argument
    ;;
    -c|--supp-cert-file)
      ARG_TLS_SUPLCERT="$2"
      show_debug "CMD arg -c / value: $ARG_TLS_SUPLCERT"
      shift # past argument
    ;;
    -k|--supp-privkey-file)
      ARG_TLS_SUPLPRIVKEY="$2"
      show_debug "CMD arg -k / value: $ARG_TLS_SUPLPRIVKEY"
      shift # past argument
    ;;
    -kp|--supp-privkey-pass)
      ARG_TLS_SUPLPRIVPASS="$2"
      show_debug "CMD arg -kp / value: $ARG_TLS_SUPLPRIVPASS"
      shift # past argument
    ;;
    -ca|--radius-ca)
      ARG_RAD_CA="$2"
      show_debug "CMD arg -ca / value: $ARG_RAD_CA"
      shift # past argument
    ;;
    -v|--verbose)
      VERBOSE_OUTPUT=1
      show_debug "CMD arg -v / Verbose output enabled"
    ;;
    -i|--interval)
      ARG_INTERVAL="$2"
      show_debug "CMD arg -i / value: $ARG_INTERVAL"
      if [[ $ARG_INTERVAL -lt 0 || $ARG_INTERVAL -gt 120 ]] ; then
        show_error "invalid test interval is used ($ARG_INTERVAL)"
      fi
      shift # past argument
    ;;
    -rnd|--random-mac)
      RAND_MAC=1
      show_debug "CMD arg -rnd / Random MACs are enabled"
    ;;
    -port)
      ARG_RAD_PORT="$2"
      show_debug "CMD arg -port / value: $ARG_RAD_PORT"
      if [[ $ARG_RAD_PORT -le 1 || $ARG_RAD_PORT -gt 65535 ]] ; then
        show_error "invalid RADIUS port is used ($ARG_RAD_PORT)"
      fi
      shift # past argument
    ;;
    -r6)
      ARG_RAD_ATTR6="$2"
      show_debug "CMD arg -r6 / value: $ARG_RAD_ATTR6"
      if [[ ARG_RAD_ATTR6 -le 0 || $ARG_RAD_ATTR6 -gt 11 ]] ; then
        show_error "invalid RADIUS service-type attribute value ($ARG_RAD_ATTR6)"
      fi
      shift # past argument
    ;;
    -r7)
      ARG_RAD_ATTR7="$2"
      show_debug "CMD arg -r7 / value: $ARG_RAD_ATTR7"
      if [[ ARG_RAD_ATTR7 -le 0 || $ARG_RAD_ATTR7 -gt 6 ]] ; then
        show_error "invalid RADIUS framed-protocol attribute value ($ARG_RAD_ATTR7)"
      fi
      shift # past argument
    ;;
    -r61)
      ARG_RAD_ATTR61="$2"
      show_debug "CMD arg -r61 / value: $ARG_RAD_ATTR61"
      if [[ ARG_RAD_ATTR61 -le -1 || $ARG_RAD_ATTR7 -gt 19 ]] ; then
        show_error "invalid NAS port-type attribute value ($ARG_RAD_ATTR61)"
      fi
      shift # past argument
    ;;
    -r30)
      ARG_RAD_ATTR30="$2"
      show_debug "CMD arg -r30 / value: $ARG_RAD_ATTR30"
      shift # past argument
    ;;
	-r31)
      ARG_RAD_ATTR31="$2"
      show_debug "CMD arg -r31 / value: $ARG_RAD_ATTR31"
      shift # past argument
    ;;
	-r32)
      ARG_RAD_ATTR32="$2"
      show_debug "CMD arg -r32 / value: $ARG_RAD_ATTR32"
      shift # past argument
    ;;
    -?|--help)
      echo -e $USAGE_SHORT
      echo -e $USAGE_HELP
      bye
    ;;
    *)
    ARG_ERROR="$1"
            # unknown option
    ;;
esac
shift # past argument or value
done

########################################################
# Some command line parameters are not known
if [[ ($ARG_ERROR != "0") ]]; then
  echo "Unknown argument $ARG_ERROR"
  echo -e $USAGE_SHORT
  bye
fi

# No command line parameters
if [[ ($NUM_ARGS -eq 0) ]]; then
  echo -e $USAGE_SHORT
  bye
fi

# Testing sanity of arguments #########################
## Mandatory arguments
# RADIUS server (arg r)
if [ -z "$ARG_RAD_SRV" ]; then
  show_error "RADIUS server is missing (-r)"
fi

# RADIUS shared secret (arg s)
if [ -z "$ARG_RAD_SEC" ]; then
  show_error "RADIUS shared secret is missing (-s)"
fi

## EAP method (arg m)
EAP_METHOD_NAME=""
case $ARG_EAP_METHOD in
    13) # EAP-TLS
      show_debug "EAP method is $ARG_EAP_METHOD (EAP-TLS)"
      EAP_METHOD_NAME="EAP-TLS"
      ##  checking of mandatory arguments for EAP-TLS
      # -c SUPPLICANT-CERT
      if [ ! -f "$ARG_TLS_SUPLCERT" ]; then
        show_error "supplicant certificate file does not exist ($ARG_TLS_SUPLCERT)"
      elif [[ $USE_OPENSSL -eq 1 ]]; then
      # checking if the file contains a certificate
        cert_in_file $ARG_TLS_SUPLCERT
      fi
      # -k SUPPL-PRIV-KEY
      if [ ! -f "$ARG_TLS_SUPLPRIVKEY" ]; then
        show_error "supplicant private key file does not exist ($ARG_TLS_SUPLPRIVKEY)"
      fi
      # -ca SERVER-CA
      if [ ! -f "$ARG_RAD_CA" ]; then
        show_error "server ca file does not exist ($ARG_RAD_CA)"
      elif [[ $USE_OPENSSL -eq 1 ]]; then
      # checking if the file contains a certificate
        cert_in_file $ARG_RAD_CA
      fi
      ## Omitting other not compatible variables
      # -u USERNAME
      if [ -n "$ARG_PEAP_USER" ]; then
        show_warn "ignoring incompatible argument -u ($ARG_PEAP_USER)"
      fi 
      # -p PASSWORD
      if [ -n "$ARG_PEAP_PW" ]; then
       show_warn "ignoring incompatible argument -p ($ARG_PEAP_PW)"
      fi
      # -a IDENTITY
      if [ -n "$ARG_PEAP_ID" ]; then
       show_warn "ignoring incompatible argument -a ($ARG_PEAP_ID)"
      fi
    ;;
    25) # PEAP
      show_debug "EAP method is $ARG_EAP_METHOD (PEAP)"
      EAP_METHOD_NAME="PEAP"
      ##  checking of mandatory arguments for PEAP
      # -u USERNAME
      if [ -z "$ARG_PEAP_USER" ]; then
        show_error "PEAP inner username missing (-u)"
      fi
      # -p PASSWORD
      if [ -z "$ARG_PEAP_PW" ]; then
        show_error "PEAP inner user password missing (-p)"
      fi
      # -ca SERVER-CA
      if [ ! -f "$ARG_RAD_CA" ]; then
        show_error "server ca file does not exist ($ARG_RAD_CA)"
      elif [[ $USE_OPENSSL -eq 1 ]]; then
      # checking if the file contains a certificate
        cert_in_file $ARG_RAD_CA
      fi
      ##  checking of optional arguments for PEAP
      # -a IDENTITY
      if [ -n "$ARG_PEAP_ID" ]; then
        show_debug "PEAP inner username set to $ARG_PEAP_ID overwriting default ($PEAP_ANON_ID)"
        PEAP_ANON_ID=$ARG_PEAP_ID
      fi
      ## Omitting other not compatible variables
      # -c SUPPLICANT-CERT
      if [ -n "$ARG_TLS_SUPLCERT" ]; then
        show_warn "ignoring incompatible argument -c ($ARG_TLS_SUPLCERT)"
      fi
      # -k SUPPL-PRIV-KEY
      if [ -n "$ARG_TLS_SUPLPRIVKEY" ]; then
        show_warn "ignoring incompatible argument -k ($ARG_TLS_SUPLPRIVKEY)"
      fi
      # -kp PRIV-KEY-PASS
      if [ -n "$ARG_TLS_SUPLPRIVPASS" ]; then
        show_warn "ignoring incompatible argument -kp ($ARG_TLS_SUPLPRIVPASS)"
      fi
    ;;
    *) # other or no method (error)
      show_debug "EAP method is $ARG_EAP_METHOD (unknown / unsupported) ... exit"
      show_error "EAP-METHOD argument missing or wrong ($ARG_EAP_METHOD)"
    ;;
esac

#######################################################
### Finally, let's start

## Some needed functions for the script
function random_mac {
  local hexchars="0123456789ABCDEF"
  local mac_OUI="42:60:2F"
  local mac=$( for i in {1..6} ; do echo -n ${hexchars:$(( $RANDOM % 16 )):1} ; done | sed -e 's/\(..\)/:\1/g' )
  echo $mac_OUI$mac
  # usage: result=$(random_mac)
}

## Generation of the eapol_test configuration files
echo "network={" >> $TEMP_FILE
echo "eapol_flags=0" >> $TEMP_FILE
echo "key_mgmt=IEEE8021X" >> $TEMP_FILE

# EAP-TLS specific content
if [[ $ARG_EAP_METHOD -eq 13 ]]; then
  echo "eap=TLS" >> $TEMP_FILE
  echo "identity=\"anonymous\"" >> $TEMP_FILE
  echo "ca_cert=\"$ARG_RAD_CA\"" >> $TEMP_FILE
  echo "client_cert=\"$ARG_TLS_SUPLCERT\"" >> $TEMP_FILE
  echo "private_key=\"$ARG_TLS_SUPLPRIVKEY\"" >> $TEMP_FILE
  if [[ -n $ARG_TLS_SUPLPRIVPASS ]]; then
    echo "private_key_passwd=\"$ARG_TLS_SUPLPRIVPASS\"" >> $TEMP_FILE
  fi
fi

# PEAP specific content
if [[ $ARG_EAP_METHOD -eq 25 ]]; then
  echo "eap=PEAP" >> $TEMP_FILE
  echo "ca_cert=\"$ARG_RAD_CA\"" >> $TEMP_FILE
  echo "identity=\"$ARG_PEAP_USER\"" >> $TEMP_FILE
  echo "password=\"$ARG_PEAP_PW\"" >> $TEMP_FILE
  echo "phase2=\"MSCHAPV2\"" >> $TEMP_FILE
  echo "anonymous_identity=\"$PEAP_ANON_ID\"" >> $TEMP_FILE
fi

echo "}" >> $TEMP_FILE

show_debug "Content of eapol_test config file $TEMP_FILE"
if [[ $DEBUG -eq 1 ]]; then
  cat $TEMP_FILE
fi

EAPOL_PARAMS="-c $TEMP_FILE -a $ARG_RAD_SRV -t 1 -s $ARG_RAD_SEC"
# Random MAC addresses enabled?
if [ $RAND_MAC -eq 1 ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -M$(random_mac)"
fi

# Custom RADIUS port
if [ -n "$ARG_RAD_PORT" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -p $ARG_RAD_PORT"
fi

# RADIUS attribute 6 (service-type)
if [ -n "$ARG_RAD_ATTR6" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -N6:d:$ARG_RAD_ATTR6"
else
  # Default to service-type 2 (frames) if not set
  EAPOL_PARAMS="$EAPOL_PARAMS -N6:d:2"
fi

# RADIUS attribute 7 (framed-protocol)
if [ -n "$ARG_RAD_ATTR7" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -N7:d:$ARG_RAD_ATTR7"
fi

# RADIUS attribute 61 (NAS port-type)
if [ -n "$ARG_RAD_ATTR61" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -N61:d:$ARG_RAD_ATTR61"
else
  # Default to NAS port-type 15 (Ethernet) if not set
  EAPOL_PARAMS="$EAPOL_PARAMS -N61:d:15"
fi

# RADIUS attribute 30 (Called-Station-ID)
if [ -n "$ARG_RAD_ATTR30" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -N30:s:$ARG_RAD_ATTR30"
fi

# RADIUS attribute 31 (Calling-Station-ID)
if [ -n "$ARG_RAD_ATTR31" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -N31:s:$ARG_RAD_ATTR31"
fi

# RADIUS attribute 32 (NAS-ID)
if [ -n "$ARG_RAD_ATTR32" ]; then
  EAPOL_PARAMS="$EAPOL_PARAMS -N32:s:$ARG_RAD_ATTR32"
else
  EAPOL_PARAMS="$EAPOL_PARAMS -N32:s:eapol_test_ping"
fi

show_debug "eapol_test CLI parameters: $EAPOL_PARAMS"

COUNT=0
COUNT_SUCESS=0
COUNT_FAIL_TIMEOUT=0
COUNT_FAIL_REJECT=0

show_debug "Interval $ARG_INTERVAL"
show_debug "Verbose output: var VERBOSE_OUTPUT: $VERBOSE_OUTPUT"

# -z $ARG_INTERVAL is FALSE if interval is set
# -z $ARG_INTERVAL is TRUE  if interval not is set
# ! -z $ARG_INTERVAL is TRUE if interval is set
# ! -z $ARG_INTERVAL is FALSE  if interval not is set



while [[ true ]] && ([[ ! -z $ARG_INTERVAL ]] || [[ $COUNT -eq 0 ]]);
do
  show_debug "current round is $COUNT"

  # Random MAC addresses enabled?
  if [ $RAND_MAC -eq 1 ]; then
    CUR_MAC=$(random_mac)
    show_debug "used MAC is: $CUR_MAC"
    TEST_RESULT="$($EAPOL_TEST_BINARY $EAPOL_PARAMS -M$CUR_MAC)"
  else
  # Random MAC not enabled
    TEST_RESULT="$($EAPOL_TEST_BINARY $EAPOL_PARAMS)"
  fi

  TEST_RESULT="$($EAPOL_TEST_BINARY $EAPOL_PARAMS)"

  if [[ $VERBOSE_OUTPUT -eq 0 ]]; then
    echo -n "$(date +"%x")" "$(date +"%T")"":""$(date +"%N") $ARG_RAD_SRV $EAP_METHOD_NAME "
  fi

  if echo $TEST_RESULT | grep -q 'SUCCESS'; then
    ((COUNT_SUCESS++))
    if [[ $VERBOSE_OUTPUT -eq 0 ]]; then
      tput setaf 2; echo -n "SUCCESS"
    fi
  fi

  if echo $TEST_RESULT | grep -q 'EAPOL test timed out'; then
    ((COUNT_FAIL_TIMEOUT++))
    if [[ $VERBOSE_OUTPUT -eq 0 ]]; then
      tput setaf 1; echo -n "FAIL (TIMEOUT)"
    fi
  fi

  if echo $TEST_RESULT | grep -q '(Access-Reject)'; then
    ((COUNT_FAIL_REJECT++))
    if [[ $VERBOSE_OUTPUT -eq 0 ]]; then
      tput setaf 1; echo -n "FAIL (REJECT)"
    fi
  fi
  if [[ $VERBOSE_OUTPUT -eq 0 ]]; then
    tput sgr0; echo " (s:$COUNT_SUCESS / reject:$COUNT_FAIL_REJECT / timeout:$COUNT_FAIL_TIMEOUT)"
  fi
   
  if [[ $VERBOSE_OUTPUT -eq 1 ]]; then
    echo "$TEST_RESULT"
  fi

  show_debug "success count: $COUNT_SUCESS"
  show_debug "reject count: $COUNT_FAIL_REJECT"
  show_debug "timeout count: $COUNT_FAIL_TIMEOUT"

  
  ((COUNT++))
  if [[ $ARG_INTERVAL -gt 0 ]]; then
    sleep $ARG_INTERVAL
  fi
done

echo -e "total success count: \t$COUNT_SUCESS"
echo -e "total reject count: \t$COUNT_FAIL_REJECT"
echo -e "total timeout count: \t$COUNT_FAIL_TIMEOUT"

#######################################################

bye

