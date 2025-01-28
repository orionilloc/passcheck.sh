#!/bin/bash

# Section declaring regex patterns for validating user-provided password
illegal_characters="[\x00-\x1F\x7F\s\x80-\xFF]|[^\x00-\x7F]"
repeating_characters="(.)\1{2,}"
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

# Section prompting user to provide a password for validation
password_checker_prompt () {
    read -r -s -p "Please enter a new password for assessment: " password_checker_input
    echo
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
    ["PCI DSS"]="7 uppercase_letters lowercase_letters numbers special_characters"
)

# Function to check compliance for each framework
check_compliance() {
    local framework=$1
    local rules=(${2// / })
    local min_length=${rules[0]}
    local complexity_checks=("${rules[@]:1}")
    local pass_length=${#password_checker_input}

    # Check password length
    if (( pass_length < min_length )); then
        echo -e "$framework: ${RED}NO${NC}"
        return
    fi

    # Check password complexity
    for check in "${complexity_checks[@]}"; do
        if ! [[ "$password_checker_input" =~ ${!check} ]]; then
            echo -e "$framework: ${RED}NO${NC}"
            return
        fi
    done

    # If all checks pass echo the following:
    echo -e "$framework: ${GREEN}YES${NC}"
}

# Ordered positive checks for display
ordered_positive_checks=(
    "Password contains uppercase letters:"
    "Password contains lowercase letters:"
    "Password contains numbers:"
    "Password contains special characters:"
)

# Main script execution
while true; do
    # Initial password input prompt
    password_checker_prompt

    # Calculate password length after input
    password_checker_input_length=${#password_checker_input}

    # Check if the password is empty or contains spaces
    if [[ -z "$password_checker_input" ]]; then
        echo -e "${YELLOW}No user input detected. Please try again.${NC}"
    elif [[ "$password_checker_input" =~ [[:space:]] ]]; then
        echo -e "${YELLOW}Whitespace character(s) detected in user input. Please try again.${NC}"
    else
        echo ""
        echo -e "${BLUE}Checking for user-provided password length:${NC}"
        # Print the length of the user-provided password
        echo ""
        echo -e "The password you have provided is ${password_checker_input_length} character(s) long"
        # Completing positive trait checks
        echo -e "${BLUE}\nChecking positive traits required for a strong password:${NC}\n"
        for check in "${ordered_positive_checks[@]}"; do
            if [[ "$password_checker_input" =~ ${positive_password_traits[$check]} ]]; then
                echo -e "$check ${GREEN}YES${NC}"
            else
                echo -e "$check ${RED}NO${NC}"
            fi
        done

        # Completing compliance framework checks
        echo -e "${BLUE}\nDisplaying compliance criteria met:${NC}\n"
        for framework in "${!compliance_frameworks[@]}"; do
            check_compliance "$framework" "${compliance_frameworks[$framework]}"
        done
        break
    fi
done

# Subsection for checking haveibeenpwned's free passwords database
hashed_password_checker_input=$(echo -n "$password_checker_input"  | openssl sha1 | awk '{print $2}')

hash_prefix=$(echo "$hashed_password_checker_input" | awk '{print substr($0, 1, 5)}')

haveibeenpwned_response=$(curl -s "https://api.pwnedpasswords.com/range/$hash_prefix")

hash_suffix=$(echo "$hashed_password_checker_input" | awk '{print substr($0, 6)}')
echo -e "${BLUE}\nChecking for the hashed password in any known data breaches:${NC}\n"
if echo "$haveibeenpwned_response" | grep -i "$hash_suffix" > /dev/null; then
    echo -e "${RED}This password has been found in a known data breach!${NC}"
else
    echo -e "${GREEN}This password has not been found in any known data breaches.${NC}"
fi
