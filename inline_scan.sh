#!/usr/bin/env bash

set -eo pipefail

if [[ "${VERBOSE}" ]]; then
    set -x
fi

########################
### GLOBAL VARIABLES ###
########################

export TIMEOUT=${TIMEOUT:=300}
# defaults for variables set by script options
ANALYZE_CMD=()
DOCKERFILE="/anchore-engine/Dockerfile"
MANIFEST_FILE="/anchore-engine/manifest.json"
# sysdig option variables
SYSDIG_BASE_SCANNING_URL="https://secure.sysdig.com"
SYSDIG_SCANNING_URL="http://localhost:9040/api/scanning"
SYSDIG_ANCHORE_URL="http://localhost:9040/api/scanning/v1/anchore"
SYSDIG_ANNOTATIONS="foo=bar"
SYSDIG_IMAGE_DIGEST_SHA="sha256:123456890abcdefg"
SYSDIG_IMAGE_ID="123456890abcdefg"
SCAN_IMAGE=()
FAILED_IMAGE=()
PDF_DIRECTORY=$(echo $PWD)
GET_CALL_STATUS=""
GET_CALL_RETRIES=300
DETAIL=false
TMP_PATH="/tmp/sysdig"

if command -v sha256sum >/dev/null 2>&1; then
    SHASUM_COMMAND="sha256sum"
else
    if command -v shasum >/dev/null 2>&1; then
        SHASUM_COMMAND="shasum -a 256"
    else
        printf "ERROR: sha256sum or shasum command is required but missing\n"
        exit 1
    fi
fi

display_usage() {
cat << EOF
Anchore Engine Inline Analyzer --
  Script for performing analysis on local docker images, utilizing Anchore Engine analyzer subsystem.
  After image is analyzed, the resulting Anchore image archive is sent to a remote Anchore Engine installation
  using the -r <URL> option. This allows inline_analysis data to be persisted & utilized for reporting.
  Images should be built & tagged locally.
    Usage: ${0##*/} [ OPTIONS ] <FULL_IMAGE_TAG>
      -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
      -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                 If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
      -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
      -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
      -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
      -i <TEXT>  [optional] Specify image ID used within Anchore Engine (ex: -i '<64 hex characters>')
      -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
      -t <TEXT>  [optional] Specify timeout for image analysis in seconds. Defaults to 300s. (ex: -t 500)
      -g  [optional] Generate an image digest from docker save tarball
EOF
}

main() {
    trap 'cleanup' EXIT ERR SIGTERM
    trap 'interupt' SIGINT

    get_and_validate_options "$@"
    get_and_validate_image "${VALIDATED_OPTIONS}"
    start_image_analysis
}

get_and_validate_options() {
    # parse options
    while getopts ':k:s:a:d:i:f:m:t:gh' option; do
        case "${option}" in
            k  ) k_flag=true; SYSDIG_API_TOKEN="${OPTARG}";;
            s  ) s_flag=true; SYSDIG_BASE_SCANNING_URL="${OPTARG%%}";;
            a  ) a_flag=true; SYSDIG_ANNOTATIONS="${OPTARG}";;
            d  ) d_flag=true; SYSDIG_IMAGE_DIGEST_SHA="${OPTARG}";;
            i  ) i_flag=true; SYSDIG_IMAGE_ID="${OPTARG}";;
            f  ) f_flag=true; DOCKERFILE="/anchore-engine/$(basename ${OPTARG})";;
            m  ) m_flag=true; MANIFEST_FILE="/anchore-engine/$(basename ${OPTARG})";;
            t  ) t_flag=true; TIMEOUT="${OPTARG}";;
            g  ) g_flag=true;;
            h  ) display_usage; exit;;
            \? ) printf "\n\t%s\n\n" "  Invalid option: -${OPTARG}" >&2; display_usage >&2; exit 1;;
            :  ) printf "\n\t%s\n\n%s\n\n" "  Option -${OPTARG} requires an argument." >&2; display_usage >&2; exit 1;;
        esac
    done
    shift "$((OPTIND - 1))"

    # set SYSDIG_API_TOKEN and IMAGE_TO_SCAN from ENV if required
    if [[ ! "${k_flag:-}" ]]; then
      SYSDIG_API_TOKEN="${SYSDIG_SECURE_TOKEN}"
      IMAGE_TAG="${IMAGE_TAG}"
    else
     IMAGE_TAG="$@"
    fi

    SYSDIG_SCANNING_URL="${SYSDIG_BASE_SCANNING_URL}"/api/scanning/v1
    SYSDIG_ANCHORE_URL="${SYSDIG_SCANNING_URL}"/anchore

    # Check for invalid options
    if [[ ! $(which buildah) ]]; then
        printf '\n\t%s\n\n' 'ERROR - buildah is not installed or cannot be found in $PATH' >&2
        display_usage >&2
        exit 1
    elif [[ "${#@}" -gt 1 ]]; then
        printf '\n\t%s\n\n' "ERROR - only 1 image can be analyzed at a time" >&2
        display_usage >&2
        exit 1
    elif [[ "${#@}" -lt 1 ]] && [[ -z "${IMAGE_TAG}" ]]; then
          printf '\n\t%s\n\n' "ERROR - must specify an image to analyze" >&2
          display_usage >&2
          exit 1
    elif [[ ! "${k_flag}" ]]; then
        printf '\n\t%s\n\n' "ERROR - must provide the Sysdig Secure API token" >&2
        display_usage >&2
        exit 1
    elif [[ "${SYSDIG_BASE_SCANNING_URL: -1}" == '/' ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify Sysdig url - ${SYSDIG_BASE_SCANNING_URL} without trailing slash" >&2
        display_usage >&2
        exit 1
    elif ! curl -k -s --fail -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images" > /dev/null; then
        printf '\n\t%s\n\n' "ERROR - invalid combination of Sysdig secure endpoint : token provided - ${SYSDIG_SCANNING_URL} : ${SYSDIG_API_TOKEN}" >&2
        display_usage >&2
        exit 1
    elif [[ "${g_flag}" ]] && ([[ "${m_flag}" ]] || [[ "${d_flag}" ]]); then
        printf '\n\t%s\n\n' "ERROR - cannot specify manifest file or digest when using the -g option" >&2
        display_usage >&2
        exit 1
    fi
}

get_and_validate_image() {
  # Make sure all images are available locally, add to FAILED_IMAGES array if not
  echo "Pulling image -- ${IMAGE_TAG}"
  buildah pull ${IMAGE_TAG} || true

  buildah inspect --type image ${IMAGE_TAG} &> /dev/null || FAILED_IMAGE+=(${IMAGE_TAG})

  if [[ ! "${FAILED_IMAGE[@]:-}" =~ ${IMAGE_TAG} ]]; then
      SCAN_IMAGE=${IMAGE_TAG}
  else
    # Give error message on any invalid image names
    printf '\n\t%s\n\n' "ERROR - issue with pulling image for analysis - ${IMAGE_TAG}" >&2
    display_usage >&2
    exit 1
  fi
}

start_image_analysis() {
    if [[ ! "${i_flag-""}" ]]; then
        SYSDIG_IMAGE_ID=$(buildah inspect --format '{{.FromImageID}}' "$SCAN_IMAGE")
        printf '%s\n\n' "Image ID: ${SYSDIG_IMAGE_ID}"
    fi

    if [[ ! "${d_flag-""}" ]]; then
        SYSDIG_IMAGE_DIGEST_SHA=$(buildah inspect --format '{{.FromImageDigest}}' "$SCAN_IMAGE")
        printf '%s\n\n' "Image Digest SHA: ${SYSDIG_IMAGE_DIGEST_SHA}"
    fi

    # switch docker.io vs rest-of-the-world registries
    # using (light) docker rule for naming: if it has a "." or a ":" we assume the image is from some specific registry
    # see: https://github.com/docker/distribution/blob/master/reference/normalize.go#L91
    SYSDIG_FULL_IMAGE_TAG=$(buildah inspect --type image --format '{{.FromImage}}' "${SCAN_IMAGE}")

    IS_DOCKER_IO=$(echo ${SCAN_IMAGE} | grep 'docker.io/library' || echo "")
    if [[ ! ${IS_DOCKER_IO} ]] && [[ ! "${SYSDIG_FULL_IMAGE_TAG}" =~ ^docker.io/library* ]]; then
        # ensure we are setting the correct full image tag
        SYSDIG_FULL_IMAGE_TAG=${SYSDIG_FULL_IMAGE_TAG}
    else
        SYSDIG_FULL_IMAGE_TAG="docker.io/$(echo ${SYSDIG_FULL_IMAGE_TAG} | rev |  cut -d / -f 1 | rev)"
    fi
    printf '%s\n\n' "Full Image Name: ${SYSDIG_FULL_IMAGE_TAG}"

    get_scan_result_code
    if [[ "${GET_CALL_STATUS}" != 200 ]]; then
        prepare_image_analysis
        save_image_archive
        run_image_analysis

        if [[ -f "/anchore-engine/image-analysis-archive.tgz" ]]; then
            printf '%s\n' " Analysis complete!"
            printf '\n%s\n' "Sending analysis archive to ${SYSDIG_SCANNING_URL%%/}"
            submit_image_analysis
        else
            printf '\n\t%s\n\n' "ERROR Cannot find image analysis archive. An error occured during analysis."  >&2
            display_usage >&2
            exit 1
        fi
    else
        echo "Image digest found on Sysdig Secure, skipping analysis."
    fi
    get_scan_result_with_retries
}

prepare_image_analysis() {
    # finally, get the account from Sysdig for the input username
    mkdir -p /tmp/sysdig
    HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/account")
    if [[ "${HCODE}" == 404 ]]; then
        HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL%%/}/account")
    fi

    if [[ "${HCODE}" == 200 ]] && [[ -f "/tmp/sysdig/sysdig_output.log" ]]; then
        SYSDIG_ACCOUNT=$(cat /tmp/sysdig/sysdig_output.log | grep '"name"' | awk -F'"' '{print $4}')
    else
        printf '\n\t%s\n\n' "ERROR - unable to fetch account information from anchore-engine for specified user"
        if [[ -f /tmp/sysdig/sysdig_output.log ]]; then
            printf '%s\n\n' "***SERVICE RESPONSE****">&2
            cat /tmp/sysdig/sysdig_output.log >&2
            printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
        fi
    exit 1
    fi
}

run_image_analysis() {
    printf '\n%s\n' "Starting Analysis for ${base_image_name}..."

    local base_image_name=$(echo "${SYSDIG_FULL_IMAGE_TAG}" | rev | cut -d '/' -f 1 | rev)

    # if filename has a : in it, replace it with _ to avoid skopeo errors
    if [[ "${base_image_name}" =~ [:] ]]; then
        local base_image_name="${base_image_name/:/-}"
    fi

    local image_file_path="/anchore-engine/${base_image_name}.tar"

    if [[ ! -f "${image_file_path}" ]]; then
        printf '\n\t%s\n\n' "ERROR - Could not find file: ${image_file_path}" >&2
        display_usage >&2
        exit 1
    fi

    if [[ "${g_flag}" ]]; then
        SYSDIG_IMAGE_DIGEST_SHA=$(skopeo inspect --raw "docker-archive:///${image_file_path}" | jq -r .config.digest)
    fi

    # analyze image with anchore-engine
    ANALYZE_CMD=('anchore-manager analyzers exec')
    ANALYZE_CMD+=('--tag "${SYSDIG_FULL_IMAGE_TAG}"')
    ANALYZE_CMD+=('--digest "${SYSDIG_IMAGE_DIGEST_SHA}"')
    ANALYZE_CMD+=('--image-id "${SYSDIG_IMAGE_ID}"')
    ANALYZE_CMD+=('--account-id "${SYSDIG_ACCOUNT}"')

    if [[ "${a_flag-""}" ]]; then
        ANALYZE_CMD+=('--annotation "${SYSDIG_ANNOTATIONS},added-by=sysdig-aio-inline-scanner"')
    else
        ANALYZE_CMD+=('--annotation "added-by=sysdig-aio-inline-scanner"')
    fi

    ANALYZE_CMD+=('"$image_file_path" /anchore-engine/image-analysis-archive.tgz > /dev/null')

    echo ${ANALYZE_CMD}

    printf '\n%s\n' "Analyzing ${IMAGE_TAG}..."
    eval "${ANALYZE_CMD[*]}"
}

submit_image_analysis() {
    # Posting the archive to the secure backend
    HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST_SHA}" -H "imageName: ${SYSDIG_FULL_IMAGE_TAG}" -F "archive_file=@/anchore-engine/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/import/images")

    if [[ "${HCODE}" != 200 ]]; then
        printf '\n\t%s\n\n' "ERROR - unable to POST ${analysis_archive_name} to ${SYSDIG_SCANNING_URL%%/}/import/images" >&2
        if [ -f /tmp/sysdig/sysdig_output.log ]; then
            printf '%s\n\n' "***SERVICE RESPONSE****">&2
            cat /tmp/sysdig/sysdig_output.log >&2
            printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
        fi
        exit 1
    fi
    get_scan_result_with_retries
}

get_scan_result_code() {
  GET_CALL_STATUS=$(curl -sk -o /dev/null --write-out "%{http_code}" --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=${DETAIL}")
}

get_scan_result_with_retries() {
    # Fetching the result of scanned digest
    for ((i=0;  i<${GET_CALL_RETRIES}; i++)); do
        get_scan_result_code
        if [[ "${GET_CALL_STATUS}" == 200 ]]; then
            status=$(curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=${DETAIL}" | grep "status" | cut -d : -f 2 | awk -F\" '{ print $2 }')
            break
        fi
        echo -n "." && sleep 1
    done

    printf "Scan Report - \n"
    curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=${DETAIL}"

    if [[ "${R_flag-""}" ]]; then
        printf "\nDownloading PDF Scan result for image id: ${SYSDIG_IMAGE_ID} / digest: ${SYSDIG_IMAGE_DIGEST_SHA}"
        get_scan_result_pdf_by_digest
    fi

    if [[ "${status}" = "pass" ]]; then
        printf "\nStatus is pass\n"
        print_scan_result_summary_message
        exit 0
    else
        printf "\nStatus is fail\n"
        print_scan_result_summary_message
        if [[ "${clean_flag:-}" ]]; then
            echo "Cleaning image from Anchore"
            curl -X DELETE -s -k -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}?force=true"
        fi
        exit 1
    fi
}

save_image_archive() {
    local base_image_name=$(echo "${SYSDIG_FULL_IMAGE_TAG}" | rev | cut -d '/' -f 1 | rev)

    # if filename has a : in it, replace it with _ to avoid skopeo errors
    if [[ "${base_image_name}" =~ [:] ]]; then
        local save_file_name="${base_image_name/:/-}"
    fi

    echo "Saving ${base_image_name} for local analysis"
    save_file_name="${save_file_name}.tar"
    local save_file_path="/anchore-engine/${save_file_name}"

    if [[ ! "${base_image_name}" =~ [:]+ ]]; then
        buildah push "${base_image_name}:latest" "docker-archive:${save_file_path}"
    else
        buildah push "${base_image_name}" "docker-archive:${save_file_path}"
    fi
    chmod 777 "${save_file_path}"

    if [[ -f "${save_file_path}" ]]; then
        chmod +r "${save_file_path}"
        printf '%s' "Successfully prepared image archive -- ${save_file_path}"
    else
        printf '\n\t%s\n\n' "ERROR - unable to save image to ${save_file_path}." >&2
        display_usage >&2
        exit 1
    fi
}

print_scan_result_summary_message() {
  if [[ ! "${V_flag-""}"  && ! "${R_flag-""}" ]]; then
      if [[ ! "${status}" = "pass" ]]; then
          echo "Result Details: "
          curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/check?tag=${SYSDIG_FULL_IMAGE_TAG}&detail=true"
      fi
  fi

  if [[ -z "${clean_flag:-}" ]]; then
      ENCODED_TAG=$(urlencode ${SYSDIG_FULL_IMAGE_TAG})
      if [[ "${o_flag:-}" ]]; then
          echo "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/secure/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST_SHA}/summaries"
      else
          echo "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST_SHA}/summaries"
      fi
  fi
  printf "PDF report of the scan results can be generated with -R option.\n"
}

get_scan_result_pdf_by_digest() {
  date_format=$(date +'%Y-%m-%d')
  curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -o "${PDF_DIRECTORY}/${date_format}-${SYSDIG_FULL_IMAGE_TAG##*/}-scan-result.pdf" "${SYSDIG_SCANNING_URL}/images/${SYSDIG_IMAGE_DIGEST_SHA}/report?tag=${SYSDIG_FULL_IMAGE_TAG}"
}

urlencode() {
  # urlencode <string>
  local length="${#1}"
  for (( i = 0; i < length; i++ )); do
      local c="${1:i:1}"
      case $c in
          [a-zA-Z0-9.~_-]) printf "$c" ;;
          *) printf '%%%02X' "'$c"
      esac
  done
}

interupt() {
  cleanup 130
}

cleanup() {
  local ret="$?"
  if [[ "${#@}" -ge 1 ]]; then
      local ret="$1"
  fi
  set +e

  buildah rmi "${SYSDIG_FULL_IMAGE_TAG}" &> /dev/null
  printf '\n%s\n' "Cleaning up buildah image: ${SYSDIG_FULL_IMAGE_TAG}"

  echo "Removing temporary folder created ${TMP_PATH}"
  rm -rf "${TMP_PATH}"

  exit "${ret}"
}

main "$@"
