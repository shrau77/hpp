import requests, base64, re, os, sys, socket, geoip2.database
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# --- ТВОИ НАСТРОЙКИ (ПОЛНЫЙ СПИСОК SNI) ---
TARGET_SNI = [
    "unicreditbank.ru", "gazprombank.ru", "gpb.ru", "mkb.ru", "open.ru", "tbank.ru", 
    "rosbank.ru", "psbank.ru", "raiffeisen.ru", "rzd.ru", "dns-shop.ru", "pochta.ru", 
    "x5.ru", "ivi.ru", "hh.ru", "kp.ru", "ria.ru", "lenta.ru", "rambler.ru", "rbc.ru", 
    "yandex.net", "pikabu.ru", "tutu.ru", "apteka.ru", "drom.ru", "farpost.ru", 
    "drive2.ru", "lemanapro.ru", "vk-portal.net", "userapi.com", "vk.com", "mail.ru", 
    "ozone.ru", "ozon.ru", "sberbank.ru", "wildberries.ru", "alfabank.ru", "tinkoff.ru", 
    "mts.ru", "megafon.ru", "t2.ru", "beeline.ru", "dzen.ru", "avito.ru", "rutube.ru", 
    "kinopoisk.ru", "magnit.com", "2gis.ru", "ok.ru", "yandex.ru"
]

urls = [
    "https://s3c3.001.gpucloud.ru/dg68glfr8yyyrm9hoob72l3gdu/xicrftxzsnsz",
    "https://etoneya.a9fm.site/", "https://etoneya.a9fm.site/2",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://sub-aggregator.vercel.app/"
]
for i in range(1, 27):
    urls.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

GEOIP_DB_PATH = 'GeoLite2-Country.mmdb'
reader = geoip2.database.Reader(GEOIP_DB_PATH) if os.path.exists(GEOIP_DB_PATH) else None
geo_cache, dns_cache = {}, {}

def get_country_code(node):
    try:
        parsed = urlparse(node)
        host = parsed.netloc.split('@')[-1].split(':')[0]
        if host in geo_cache: return geo_cache[host]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            ip = host
        else:
            if host not in dns_cache:
                dns_cache[host] = socket.gethostbyname(host)
            ip = dns_cache[host]
        if reader:
            response = reader.country(ip)
            code = response.country.iso_code
            geo_cache[host] = code
            return code
    except: pass
    return "UN"

def calculate_score(config):
    score = 0
    c_l = config.lower()
    if any(p in c_l for p in ['xtls-rprx-vision', 'hysteria2', 'hy2']): score += 150
    if any(p in c_l for p in ['reality', 'trojan']): score += 100
    if ':443' in c_l: score += 50
    sni_match = re.search(r'(?:sni|peer)=([^&?#]+)', c_l)
    if sni_match:
        found_sni = sni_match.group(1)
        if any(tsni in found_sni for tsni in TARGET_SNI): score += 150
    return score

def patch_node(node, force_fp=False):
    base = node.split('#')[0]
    if force_fp and 'fp=' not in base:
        sep = '&' if '?' in base else '?'
        base += f"{sep}fp=chrome"
    return base

def finalize_and_save(filename, data, tag="", limit=None, comment=None, force_fp=False):
    if limit: data = data[:limit]
    if not data: return
    with ThreadPoolExecutor(max_workers=50) as ex:
        countries = list(ex.map(get_country_code, data))
    output = []
    if comment: output.append(f"# {comment}")
    for i, (node, country) in enumerate(zip(data, countries)):
        c_code = country if country else "UN"
        flag = "".join(chr(ord(c.upper()) + 127397) for c in c_code) if c_code != "UN" else "🌐"
        clean_node = patch_node(node, force_fp)
        new_name = f"{flag} {tag}{c_code}-{i+1:05}-HPP"
        output.append(f"{clean_node}#{new_name}")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(output))
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 {filename} ({len(output)})")

all_collected = []
for url in urls:
    try:
        r = requests.get(url, timeout=15)
        content = r.text
        if "://" not in content[:100]:
            try: content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: pass
        for line in content.splitlines():
            line = line.strip()
            if "://" in line and not line.startswith("//"):
                all_collected.append(line)
    except: pass

all_collected.sort(key=calculate_score, reverse=True)
unique_ips, unique_nodes = set(), []
for node in all_collected:
    try:
        parts = urlparse(node)
        addr_key = f"{parts.scheme}://{parts.netloc.split('@')[-1]}" 
        if addr_key not in unique_ips:
            unique_ips.add(addr_key)
            unique_nodes.append(node)
    except: pass

# --- СОХРАНЕНИЕ (НОВЫЕ ФАЙЛЫ) ---
finalize_and_save("hard_hidden.txt", [n for n in unique_nodes if calculate_score(n) >= 300 and ':443' in n], tag="HARD-", force_fp=True)
finalize_and_save("shadowsocks.txt", [n for n in unique_nodes if n.startswith("ss://") and get_country_code(n) != "RU"], tag="SS-")
finalize_and_save("mobile_special.txt", [n for n in unique_nodes if 'mobile' in n.lower() or calculate_score(n) >= 200], tag="MOB-", comment=f"Total: {len(unique_nodes)}")
finalize_and_save("mobile_high_quality.txt", [n for n in unique_nodes if 200 <= calculate_score(n) < 300], tag="HQ-", force_fp=True)
finalize_and_save("all_configs.txt", unique_nodes, limit=15000)

# --- СОХРАНЕНИЕ (СТАРЫЕ ФАЙЛЫ ДЛЯ СОВМЕСТИМОСТИ) ---
finalize_and_save("sub.txt", unique_nodes, limit=10000)
finalize_and_save("sub_lite.txt", unique_nodes, limit=1000)
finalize_and_save("business.txt", [n for n in unique_nodes if calculate_score(n) >= 150])
finalize_and_save("vless_vmess.txt", [n for n in unique_nodes if not n.startswith("ss://")], limit=5000)
finalize_and_save("whitelist_cable.txt", [n for n in unique_nodes if 'cable' in n.lower()], tag="CABLE-")
finalize_and_save("whitelist_mobile.txt", [n for n in unique_nodes if 'mobile' in n.lower()], tag="MOB-")

if reader: reader.close()
print(f"🚀 ВСЕ ГОТОВО. Уникальных серверов: {len(unique_nodes)}")
