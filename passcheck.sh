#!/usr/bin/env bash

# Section declaring regex patterns for validating user-provided password
illegal_characters="[\x00-\x1F\x7F\s\x80-\xFF]|[^\x00-\x7F]"
repeating_characters="(.)\\1{2,}"
numerical_sequences="(012|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)"
alphabetical_sequences="(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|mlk|lkj|kji|jih|ihg|hgf|gfe|fed|edc|dcb|cba)"
keyboard_patterns="(qwerty|asdfgh|zxcvbn|ytrewq|hgfdsa|nbvcxz)"

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
    exit 0
}

# Section prompting user to provide a password for validation
password_checker_prompt() {
    read -r -s -p "Please enter a hypothetical, non-production password to assess: " password_checker_input
    printf '%b\n'
}

# Section generating a random password using the Linux environment's builtin entropy pool; defaults to 16 characters for relative security
password_generate() {
    local generated_password_length="${2:-16}"
    password_checker_input=$(tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_{|}~`' < /dev/urandom | head -c "$generated_password_length")
    printf '%s\n' "$password_checker_input"
    assess_password_compliance_and_breaches
}

# Declare regex patterns validation array for positive password traits
declare -A positive_password_traits=(
    ["Password contains uppercase letters:"]="$uppercase_letters"
    ["Password contains lowercase letters:"]="$lowercase_letters"
    ["Password contains numbers:"]="$numbers"
    ["Password contains special characters:"]="$special_characters"
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
        printf '%b\n' "$framework: ${RED}NO${NC}"
        return
    fi

    for check in "${complexity_checks[@]}"; do
        [[ "$check" == "none" ]] && continue
        if ! [[ "$password_checker_input" =~ ${!check} ]]; then
            printf '%b\n' "$framework: ${RED}NO${NC}"
            return
        fi
    done

    printf '%b\n' "$framework: ${GREEN}YES${NC}"
}

# Ordered positive checks for displaying
ordered_positive_checks=(
    "Password contains uppercase letters:"
    "Password contains lowercase letters:"
    "Password contains numbers:"
    "Password contains special characters:"
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
            printf '%b\n' "${BLUE}Checking for user-provided password length:${NC}"
            printf '%b\n' ""
            printf '%b\n' "The password you have provided is ${password_checker_input_length} character(s) long."
            printf '%b\n' "${BLUE}\nChecking positive traits required for a strong password:${NC}\n"
            for check in "${ordered_positive_checks[@]}"; do
                if [[ "$password_checker_input" =~ ${positive_password_traits[$check]} ]]; then
                    printf '%b\n' "$check ${GREEN}YES${NC}"
                else
                    printf '%b\n' "$check ${RED}NO${NC}"
                fi
            done

            printf '%b\n' "${BLUE}\nDisplaying compliance criteria met:${NC}\n"
            for framework in "${!compliance_frameworks[@]}"; do
                check_compliance "$framework" "${compliance_frameworks[$framework]}"
            done

            # Subsection for checking haveibeenpwned's free passwords database
            hashed_password_checker_input=$(printf '%s' "$password_checker_input" | openssl sha1 | awk '{print $2}')
            hash_prefix=$(printf '%s' "$hashed_password_checker_input" | awk '{print substr($0, 1, 5)}')
            haveibeenpwned_response=$(curl -s "https://api.pwnedpasswords.com/range/${hash_prefix}")
            hash_suffix=$(printf '%s' "$hashed_password_checker_input" | awk '{print substr($0, 6)}')

            printf '%b\n' "${BLUE}\nChecking for the hashed password in any known data breaches:${NC}\n"
            if printf '%s' "$haveibeenpwned_response" | grep -i "$hash_suffix" > /dev/null; then
                printf '%b\n' "${RED}This password has been found in a known data breach!${NC}"
            else
                printf '%b\n' "${GREEN}This password has not been found in any known data breaches.${NC}"
            fi
        fi
}

case "$1" in
    --check)    password_checker_prompt && assess_password_compliance_and_breaches ;;
    --generate) password_generate "$@";;
    --help)     usage ;;
    *)          usage ;;
esac
