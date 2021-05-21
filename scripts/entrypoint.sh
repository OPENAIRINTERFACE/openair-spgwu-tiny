#!/bin/bash

set -uo pipefail

CONFIG_DIR="/openair-spgwu-tiny/etc"
# Default value for "Natting" option
NETWORK_UE_NAT_OPTION=${NETWORK_UE_NAT_OPTION:-no}
# Default values for the performance management
THREAD_S1U_PRIO=${THREAD_S1U_PRIO:-80}
S1U_THREADS=${S1U_THREADS:-8}
THREAD_SX_PRIO=${THREAD_SX_PRIO:-81}
SX_THREADS=${SX_THREADS:-1}
THREAD_SGI_PRIO=${THREAD_SGI_PRIO:-80}
SGI_THREADS=${SGI_THREADS:-8}
BYPASS_UL_PFCP_RULES=${BYPASS_UL_PFCP_RULES:-no}
GTP_EXTENSION_HEADER_PRESENT=${GTP_EXTENSION_HEADER_PRESENT:-no}

for c in ${CONFIG_DIR}/*.conf; do
    # grep variable names (format: ${VAR}) from template to be rendered
    VARS=$(grep -oP '@[a-zA-Z0-9_]+@' ${c} | sort | uniq | xargs)

    # create sed expressions for substituting each occurrence of ${VAR}
    # with the value of the environment variable "VAR"
    EXPRESSIONS=""
    for v in ${VARS}; do
        NEW_VAR=`echo $v | sed -e "s#@##g"`
        if [[ "${!NEW_VAR}x" == "x" ]]; then
            echo "Error: Environment variable '${NEW_VAR}' is not set." \
                "Config file '$(basename $c)' requires all of $VARS."
            exit 1
        fi
        EXPRESSIONS="${EXPRESSIONS};s|${v}|${!NEW_VAR}|g"
    done
    EXPRESSIONS="${EXPRESSIONS#';'}"

    # render template and inline replace config file
    sed -i "${EXPRESSIONS}" ${c}
done

exec "$@"
