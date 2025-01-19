# passcheck.sh draft

# Completes a character count for user inputted password
password_user_input_length=$("$password_checker_input" | wc -m)

# generates password strength score, how should i score it
#password_strength_score

# Section declaring regex patterns to test against
illegal_characters="[\x00-\x1F\x7F\s\x80-\xFF]|[^\x00-\x7F]"
repeating_characters="(.)\1{2,}"
numerical_sequences="(012|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)"
alphabetical_sequences="(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|mlk|lkj|kji|jih|ihg|hgf|gfe|fed|edc|dcb|cba)"
keyboard_patterns="(qwerty|asdfgh|zxcvbn|ytrewq|hgfdsa|nbvcxz)"
alternating_patterns="(qaz|wsx|edc|rfv|tgb|yhn|ujm|ik,|ol.|pl;|;'/|zaq|xsw|cde|vfr|bgt|nhy|mju|,ki|.lo|;lp|'/;|;'[)"

# Section defining color codes to add visual interest to the generated report
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# The main prompt requesting user input in the form of a password
password_checker_prompt () {
read -r -s -p "Please enter a new password for assessment:" password_checker_input
}

if [[ -z "$password_checker_input" ]]; then
    echo "No user input detected." && password_checker_prompt
elif [[ "$password_checker_input" =~ [[:space:]] ]]; then
    echo "Whitespace character(s) detected in user input." && password_checker_prompt
else

declare -A regex_patterns_validation=(
    ["Password contains illegal characters:"]="$illegal_characters"
    ["Password contains repeating characters:"]="$repeating_characters"
    ["Password contains numerical sequences:"]="$numerical_sequences"
    ["Password contains alphabetical sequences:"]="$alphabetical_sequences"
    ["Password contains keyboard patterns:"]="$keyboard_patterns"
    ["Password contains alternating patterns:"]="$alternating_patterns"
)


for check in "${!regex_patterns_validation[@]}"; do
    if [[ $password_checker_input =~ ${regex_patterns_validation[$check]} ]]; then
        echo -e "$check ${RED}YES${NC}"
    else
        echo -e "$check ${GREEN}NO${NC}"
    fi
done

# format: character length, whether it matches for any of those, API pull and then reformatting information from that, then listing compliance-related information
#i can use the haveibeenpwned API by pulling dicrtioanries, consider using a hashed version of the password when checking online
#hex
#ascending descending numerical
#ascending descending alphabet
#common keyboard patteerns
#common number patterns
#morekeyboard patterns
#flag along with these (green or red check, then generate a report based on those results, how would i score it?
#create a scoring scheme also dependent on top
#make it read through or check results from text files like rockyou.txt or others?
# need to create a loop function, read prompt, and echo command for input or instruct user to exit the program

#ensure every single character pattern matches from approved regex ive made, then check

#hex and escape characters that would be illegal in other systems, also repetition of the following characers: need to include all ([\x00-\x1F\x7F\s\x80-\xFF]|[^\x00-\x7F])|(.)\1{2,}|
(012|123|234|345|456|567|678|789|890)|(098|987|876|765|654|543|432|321|210)|
(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)|
(zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|mlk|lkj|kji|jih|ihg|hgf|gfe|fed|edc|dcb|cba)|
(qwerty|asdfgh|zxcvbn|ytrewq|hgfdsa|nbvcxz)|
(123456|654321|7890|09876|56789)|
(qaz|wsx|edc|rfv|tgb|yhn|ujm|ik,|ol.|pl;|;'/|zaq|xsw|cde|vfr|bgt|nhy|mju|,ki|.lo|;lp|'/;|;'[|)


prints results based on certain compliance standards

as well as any recommendations. Also links to more information for those specfiic standards. also flag if password is found in a file like rockyou.txt
