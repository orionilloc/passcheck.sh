#!/usr/bin/env bash

# Section declaring positive traits for password complexity
uppercase_letters="([A-Z])"
lowercase_letters="([a-z])"
numbers="([0-9])"
special_characters="([!@#$%^&*(),.?\":{}|<>])"

# Section defining color codes to add visual interest to the generated password report
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

# Section defining how to use this script and its limited functions
usage() {
    printf '%b\n' "Usage: ${0##*/} [OPTION]"
    printf '%b\n' ""
    printf '%b\n' "Options:"
    printf '%b\n' "  --check       Assess a password against compliance frameworks and known breaches"
    printf '%b\n' "  --generate    Generate a secure password"
    printf '%b\n' "  --help        Display this help message"
    printf '%b\n' ""
    printf '%b\n' "Examples:"
    printf '%b\n' "  ${0##*/} --check"
    printf '%b\n' "  ${0##*/} --generate"
    printf '%b\n' "  ${0##*/} --generate 32"
    exit 0
}

# Section to define columnar output
print_row() {
    printf '    %-32s' "$1"
    printf '%b\n' "${2}${3}${NC}"
}

# Section prompting user to provide a password for validation
password_checker_prompt() {
    read -r -s -p "Please enter a hypothetical, non-production password to assess: " password_checker_input
    printf '%b\n'
}

# Section generating a random password using the Linux environment's builtin entropy pool; defaults to 16 characters for relative security
password_generate() {
    local length="${2:-16}"
    local special_charset='!"#$%&'"'"'()*+,-./:;<=>?@[\]^_{|}~`'
    local full_charset="A-Za-z0-9${special_charset}"
    local upper lower digit special remainder

    if (( length < 4 )); then
        printf '%b\n' "${YELLOW}Length must be at least 4 characters.${NC}"
        exit 1
    fi

    upper=$(tr -dc 'A-Z' < /dev/urandom | head -c 1)
    lower=$(tr -dc 'a-z' < /dev/urandom | head -c 1)
    digit=$(tr -dc '0-9' < /dev/urandom | head -c 1)
    special=$(tr -dc "$special_charset" < /dev/urandom | head -c 1)
    remainder=$(tr -dc "$full_charset" < /dev/urandom | head -c $(( length - 4 )))

    password_checker_input=$(printf '%s' "${upper}${lower}${digit}${special}${remainder}" \
        | fold -w1 | shuf | tr -d '\n')

    printf '%s\n' "$password_checker_input"
    assess_password_compliance_and_breaches
}

# Declare regex patterns validation array for positive password traits
declare -A positive_password_traits=(
    ["Has uppercase letters:"]="$uppercase_letters"
    ["Has lowercase letters:"]="$lowercase_letters"
    ["Has numbers:"]="$numbers"
    ["Has special characters:"]="$special_characters"
)

# Define compliance framework rules
declare -A compliance_frameworks=(
    ["HIPAA"]="8 uppercase_letters lowercase_letters numbers special_characters"
    ["SOC 2"]="8 uppercase_letters lowercase_letters numbers special_characters"
    ["SOX"]="8 uppercase_letters lowercase_letters numbers special_characters"
    ["ISO 27001"]="8 uppercase_letters lowercase_letters numbers special_characters"
    ["FedRAMP"]="12 uppercase_letters lowercase_letters numbers special_characters"
    ["PCI DSS"]="12 uppercase_letters lowercase_letters numbers special_characters"
    ["NIST SP 800-63B"]="8 none"
)

# Function to check compliance for each framework
check_compliance() {
    local framework=$1
    local rules=(${2// / })
    local min_length=${rules[0]}
    local complexity_checks=("${rules[@]:1}")
    local pass_length=${#password_checker_input}

    if (( pass_length < min_length )); then
        print_row "$framework" "$RED" "NO"
        return
    fi

    for check in "${complexity_checks[@]}"; do
        [[ "$check" == "none" ]] && continue
        if ! [[ "$password_checker_input" =~ ${!check} ]]; then
            print_row "$framework" "$RED" "NO"
            return
        fi
    done

        print_row "$framework" "$GREEN" "YES"
}

# Ordered positive checks for displaying
ordered_positive_checks=(
    "Has uppercase letters:"
    "Has lowercase letters:"
    "Has numbers:"
    "Has special characters:"
)

# Main function for password assessment against compliance frameworks and breach database
assess_password_compliance_and_breaches() {
        password_checker_input_length=${#password_checker_input}

        if [[ -z "$password_checker_input" ]]; then
            printf '%b\n' "${YELLOW}No user input detected. Please try again.${NC}"
        elif [[ "$password_checker_input" =~ [[:space:]] ]]; then
            printf '%b\n' "${YELLOW}Whitespace character(s) detected in user input. Please try again.${NC}"
        else
            printf '%b\n' ""
            printf '%b\n' "${BLUE}Checking password length:${NC}"
            printf '%b\n' ""
            printf '%b\n' "Provided password is ${password_checker_input_length} character(s) long."
            printf '%b\n' ""
            printf '%b\n' "${BLUE}Strong password traits:${NC}\n"
            for check in "${ordered_positive_checks[@]}"; do
                if [[ "$password_checker_input" =~ ${positive_password_traits[$check]} ]]; then
                    print_row "$check" "$GREEN" "YES"
                else
                    print_row "$check" "$RED" "NO"
                fi
            done

            printf '%b\n' "${BLUE}\nDisplaying compliance criteria met:${NC}\n"
            for framework in "${!compliance_frameworks[@]}"; do
                check_compliance "$framework" "${compliance_frameworks[$framework]}"
            done

            # Subsection for checking haveibeenpwned's free passwords database
            hashed_password_checker_input=$(printf '%s' "$password_checker_input" | openssl sha1 | awk '{print $NF}')
            hash_prefix=$(printf '%s' "$hashed_password_checker_input" | awk '{print substr($0, 1, 5)}')
            haveibeenpwned_response=$(curl -s --max-time 5 "https://api.pwnedpasswords.com/range/${hash_prefix}")
            hash_suffix=$(printf '%s' "$hashed_password_checker_input" | awk '{print substr($0, 6)}')

            printf '%b\n' "${BLUE}\nChecking for known data breaches:${NC}\n"
            if [[ -z $haveibeenpwned_response ]]; then
                printf '%b\n' "${YELLOW}Breach check unavailable. Check for network error or timeout.${NC}"
                printf '%b\n' ""
            elif printf '%s' "$haveibeenpwned_response" | grep -i "$hash_suffix" > /dev/null; then
                printf '%b\n' "${RED}This password has been found in a known data breach!${NC}"
                printf '%b\n' ""
            else
                printf '%b\n' "${GREEN}This password has not been found in any known data breaches.${NC}"
                printf '%b\n' ""
            fi
        fi
}

case "$1" in
    --check)    password_checker_prompt && assess_password_compliance_and_breaches ;;
    --generate) password_generate "$@";;
    --help)     usage ;;
    *)          usage ;;
esac
