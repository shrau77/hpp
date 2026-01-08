import requests, base64, re, os, socket, geoip2.database, json, hashlib, shutil, time, ipaddress
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# ⚙️ НАСТРОЙКИ И КОНСТАНТЫ
# ==============================================================================

# 1. ИСТОЧНИКИ (ТВОЙ СПИСОК)
urls = [
    "https://s3c3.001.gpucloud.ru/dggdu/xixz",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/config.txt", 
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS", 
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://fsub.flux.2bd.net/githubmirror/bypass/bypass-all.txt",
    "https://etoneya.a9fm.site/1",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh#OBSpiskov",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt", 
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt", 
    "https://fsub.flux.2bd.net/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/vmess.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/trojan.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/tuic.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/ssr.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hysteria.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hysteria2.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hy2.txt",
    "http://livpn.atwebpages.com/sub.php?token=c829c20769d2112b", 
    "https://sub-aggregator.vercel.app/",
    "https://s3c3.001.gpucloud.ru/dixsm/htxml",
    "https://shz.al/YjSPQaSTpHYNakFnE2ddjcCK:/~@sorenab1,/VIESS,subSOREN#VIESS,subSOREN", 
    "https://s3c3.001.gpucloud.ru/rtrq/jsoxn", 
    "https://raw.githubusercontent.com/bywarm/whitelists-vpns-etc/refs/heads/main/whitelists1-4pda.txt", 
    *[f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt" for i in range(1, 27)]
]

# 2. ЦЕЛЕВЫЕ SNI (WhiteList: Полная версия)
# ВСТАВЬ ЭТО ВМЕСТО ТЕКУЩЕГО TARGET_SNI
TARGET_SNI = list(set([
    # --- 👑 PLATINUM TIER ---
    "max.ru", "web.max.ru", "download.max.ru", "dev.max.ru", "static.max.ru", "api.max.ru",
    "gosuslugi.ru", "www.mos.ru", "nalog.ru", "esia.gosuslugi.ru",
    "smartcaptcha.yandexcloud.net", "sso.passport.yandex.ru", "api-maps.yandex.ru",
    
    # --- 🏦 BANKS & FINANCE ---
    "cdn.tbank.ru", "online.sberbank.ru", "esa-res.online.sberbank.ru", "sberbank.ru",
    "alfabank.ru", "alfabank.st", "alfabank.servicecdn.ru",
    "www.unicreditbank.ru", "www.gazprombank.ru", "cdn.gpb.ru", "mkb.ru", "www.open.ru",
    "www.psbank.ru", "www.raiffeisen.ru", "nspk.ru", "mir-platform.ru",
    "imgproxy.cdn-tinkoff.ru", "mddc.tinkoff.ru", "id.tbank.ru", "tmsg.tbank.ru",
    
    # --- 🛍 RETAIL & MARKETPLACES ---
    "ads.x5.ru", "www.x5.ru", "www.magnit.com", "magnit-ru.injector.3ebra.net",
    "www.ozon.ru", "ir.ozone.ru", "vt-1.ozone.ru", "io.ozone.ru", "st.ozone.ru", "xapi.ozon.ru",
    "wb.ru", "wildberries.ru", "user-geo-data.wildberries.ru", "banners-website.wildberries.ru",
    "c.dns-shop.ru", "restapi.dns-shop.ru", "lemanapro.ru", "edadeal.yandex.ru",
    "avito.ru", "sntr.avito.ru", "api.apteka.ru", "static.apteka.ru",
    
    # --- 📱 SOCIAL & MEDIA ---
    "vk.com", "m.vk.com", "eh.vk.com", "vkvideo.ru", "login.vk.com",
    "sun9-38.userapi.com", "sun6-21.userapi.com", "sun6-20.userapi.com", "sun6-22.userapi.com",
    "ok.ru", "st.okcdn.ru", "i.mycdn.me", 
    "rutube.ru", "static.rutube.ru", "goya.rutube.ru",
    "dzen.ru", "yastatic.net", "avatars.mds.yandex.net",
    "www.kinopoisk.ru", "hd.kinopoisk.ru", "st.kp.yandex.net",
    "music.yandex.ru", "plus.yandex.ru", "yandex.ru",
    "www.ivi.ru", "api2.ivi.ru", "premier.one", "fb-cdn.premier.one",
    "pikabu.ru", "www.rbc.ru", "s.rbk.ru", "lenta.ru", "ria.ru", "www.kp.ru",
    
    # --- 🚂 SERVICES & UTILS ---
    "www.rzd.ru", "ticket.rzd.ru", "www.pochta.ru", "passport.pochta.ru",
    "www.tutu.ru", "cdn1.tu-tu.ru",
    "2gis.ru", "d-assets.2gis.ru", "s1.bss.2gis.com",
    "gismeteo.ru", "st.gismeteo.st",
    "hh.ru", "i.hh.ru", "hhcdn.ru",
    "auto.ru", "drom.ru", "s11.auto.drom.ru", "c.rdrom.ru", "farpost.ru", "drive2.ru",
    
    # --- 📡 TELECOM & TECH ---
    "mts.ru", "login.mts.ru", "api.a.mts.ru", "mtscdn.ru", "kion.ru",
    "beeline.ru", "static.beeline.ru", "moskva.beeline.ru",
    "megafon.ru", "moscow.megafon.ru",
    "t2.ru", "msk.t2.ru",
    "api.mindbox.ru", "web-static.mindbox.ru",
    "counter.yadro.ru", "top-fwz1.mail.ru", "rs.mail.ru",
    "servicepipe.ru", "files.icq.net",
    
    # --- 💎 RARE / EXOTIC (Из дампов) ---
    "video.intfreed.ru", "khabarovsk.geodema.network", "my.oversecure.pro"
]))

# 3. ULTRA ELITE & BLACKLIST
ULTRA_ELITE_SNI = [
    "hls-svod.itunes.apple.com", "itunes.apple.com", "xp.apple.com",
    "fastsync.xyz", "cloudlane.xyz", "powodzenia.xyz", "shiftline.xyz", "edgeport.xyz",
    "zoomzoom.xyz", "runstream.xyz", "softpipe.xyz",
    "cdn.tbank.ru", "sso.passport.yandex.ru", "download.max.ru"
]

BLACK_SNI = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'porn', 'pusytroller', 'hubp.de', 'dynv6.net']
ELITE_PORTS = ['2053', '2083', '2087', '2096', '8443', '443']

# 4. ASN КАРТА (Для определения элиты по IP)
RU_ASN_MAP = {
    "51.250.0.0/16": "YANDEX", "84.201.128.0/17": "YANDEX", "158.160.0.0/16": "YANDEX",
    "95.163.0.0/16": "SELECTEL", "87.242.0.0/16": "SELECTEL", 
    "217.16.0.0/16": "MTS-AEZA", "188.93.16.0/20": "AEZA",
    "46.17.0.0/16": "FIRSTBYTE", "212.34.138.0/24": "G-CORE"
}

# ==============================================================================
# 🧠 ЛОГИКА
# ==============================================================================

def update_geoip():
    """Качаем GeoLite2 если нет или старый"""
    db_path = 'GeoLite2-Country.mmdb'
    mirror_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    
    need_download = False
    if not os.path.exists(db_path): need_download = True
    elif (time.time() - os.path.getmtime(db_path)) > 3 * 86400: need_download = True
            
    if need_download:
        try:
            print("🌍 Updating GeoIP Database...")
            r = requests.get(mirror_url, stream=True, timeout=20)
            if r.status_code == 200:
                with open(db_path, 'wb') as f: shutil.copyfileobj(r.raw, f)
        except: pass

class MetaAggregator:
    def __init__(self):
        self.rep_path = 'reputation.json'
        self.reputation = self._load_json(self.rep_path)
        self.reader = geoip2.database.Reader('GeoLite2-Country.mmdb') if os.path.exists('GeoLite2-Country.mmdb') else None
        self.uuid_counter = {}
        
    def _load_json(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {k: v for k, v in data.items() if isinstance(v, dict)}
            except: return {}
        return {}

    def _extract_sni(self, node):
        try:
            match = re.search(r'sni=([^&?#\s]+)', node.lower())
            if match: return match.group(1).strip('.')
        except: pass
        return None

    def _check_asn(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net, name in RU_ASN_MAP.items():
                if ip_obj in ipaddress.ip_network(net): return name, "RU"
        except: pass
        return None, None

    def get_node_id(self, node):
        return hashlib.md5(node.split('#')[0].encode()).hexdigest()

    def calculate_score(self, node):
        score = 0
        n_l = node.lower()
        
        # Репутация
        node_id = self.get_node_id(node)
        score += self.reputation.get(node_id, {}).get('count', 0) * 50

        # Технологии
        if 'xtls-rprx-vision' in n_l: score += 300
        if 'type=xhttp' in n_l: score += 400
        if 'packetencoding=xudp' in n_l: score += 100
        if 'hysteria2' in n_l or 'tuic' in n_l: score += 250
        
        # SNI
        sni = self._extract_sni(node)
        if sni:
            if 'max.ru' in sni: score += 1000
            elif any(s in sni for s in ULTRA_ELITE_SNI): score += 500
            elif any(ts == sni or sni.endswith('.'+ts) for ts in TARGET_SNI): score += 300
            if any(s in sni for s in BLACK_SNI): score -= 5000

        # ASN
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            if self._check_asn(host)[0]: score += 500
        except: pass

        return max(score, 0)

    def patch(self, node):
        try:
            # VMESS FIX
            if node.startswith('vmess://'):
                base = node[8:].split('?')[0].split('#')[0]
                missing = len(base) % 4
                if missing: base += '=' * (4 - missing)
                try:
                    decoded = base64.b64decode(base).decode('utf-8', errors='ignore')
                    if '{' in decoded: decoded = decoded[decoded.find('{'):decoded.rfind('}')+1]
                    conf = json.loads(decoded)
                    if not conf.get('scy'): conf['scy'] = 'auto'
                    return f"vmess://{base64.b64encode(json.dumps(conf).encode()).decode()}"
                except: return node

            # VLESS/TROJAN PATCH
            parsed = urlparse(node)
            query = parse_qs(parsed.query)
            
            if 'packetEncoding' not in query: query['packetEncoding'] = ['xudp']
            if 'fp' not in query: query['fp'] = ['chrome']
            
            if 'security' in query and query['security'][0] == 'reality':
                if 'pbk' in query and 'sid' not in query: query['sid'] = ['1a']

            return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        except: return node

    def get_geo_info(self, node):
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            if not host: return "UN", ""
            
            asn_tag, asn_country = self._check_asn(host)
            if asn_tag: return asn_country, asn_tag

            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) and self.reader:
                try: return self.reader.country(host).country.iso_code or "UN", ""
                except: pass
            
            if host.endswith('.ru'): return "RU", ""
            return "UN", ""
        except: return "UN", ""

    def generate_name(self, geo, score, sni, asn_tag):
        quality = "BASIC"
        if score >= 1500: quality = "PLATINUM 💎"
        elif score >= 1000: quality = "ELITE 🔥"
        elif score >= 500: quality = "PREMIUM 🚀"
        elif score >= 300: quality = "STANDARD"
        
        provider = asn_tag if asn_tag else ""
        if 'max.ru' in str(sni): provider = "VK-MAX"
        elif 'x5.ru' in str(sni): provider = "X5-RETAIL"
        elif 'tbank' in str(sni): provider = "T-BANK"
        
        flag = "".join(chr(ord(c.upper()) + 127397) for c in geo) if geo != "UN" else "🌐"
        return " ".join([p for p in [flag, geo, provider, quality] if p])

def save_file(filename, data):
    if not data: return
    with open(filename, 'w', encoding='utf-8') as f: f.write("\n".join(data))
    b64 = base64.b64encode("\n".join(data).encode('utf-8')).decode('utf-8')
    with open(filename + ".b64", 'w', encoding='utf-8') as f: f.write(b64)
    print(f"💾 Saved {filename} ({len(data)})")

def main():
    update_geoip()
    agg = MetaAggregator()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 Fetching...")
    
    # Headers для обхода 403
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    def fetch(url):
        try: return requests.get(url, headers=headers, timeout=15).text
        except: return ""

    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(fetch, urls))
    
    raw_nodes = []
    for content in results:
        if not content: continue
        if "://" not in content[:50]:
            try: content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: pass
        raw_nodes.extend([l.strip() for l in content.splitlines() if "://" in l])

    print(f"📊 Raw: {len(raw_nodes)}")

    # --- PROCESSING ---
    unique_map = {}
    ss_list = []
    
    # Списки для специфичных фильтров
    mobile_list = []
    
    for node in raw_nodes:
        try:
            if node.startswith('ss://'):
                if node not in ss_list: ss_list.append(node)
                continue

            patched = agg.patch(node)
            parsed = urlparse(patched)
            if not parsed.netloc: continue
            
            # Дедупликация (Выживший)
            host_ip = parsed.netloc.split('@')[-1].split(':')[0]
            key = f"{parsed.scheme}@{host_ip}"
            score = agg.calculate_score(patched)
            
            if key not in unique_map or score > unique_map[key]['score']:
                geo, asn = agg.get_geo_info(patched)
                sni = agg._extract_sni(patched)
                unique_map[key] = {'node': patched, 'score': score, 'geo': geo, 'asn': asn, 'sni': sni}
                
                # Собираем Mobile (MTS/Beeline/Megafon)
                if sni and any(x in sni for x in ['mts', 'beeline', 'megafon', 't2', 'yota']):
                    mobile_list.append(patched)
                    
        except: continue

    sorted_nodes = sorted(unique_map.values(), key=lambda x: x['score'], reverse=True)
    
    # --- DISTRIBUTION ---
    ultra_elite = []
    business = []
    leaked_gems = []
    
    for item in sorted_nodes:
        node_str = f"{item['node']}#{agg.generate_name(item['geo'], item['score'], item['sni'], item['asn'])}"
        
        if item['score'] >= 1000:
            ultra_elite.append(node_str)
            business.append(node_str)
        elif item['score'] >= 500:
            business.append(node_str)
        elif 'type=xhttp' in item['node'] or (item['sni'] and 'max.ru' in str(item['sni'])):
            leaked_gems.append(node_str)

    # --- SAVING ---
    save_file("ultra_elite.txt", ultra_elite)
    save_file("business.txt", business)
    save_file("leaked_gems.txt", leaked_gems)
    save_file("ss.txt", ss_list)
    
    # Legacy & Specific files
    save_file("hard_hidden.txt", business) # Copy of business
    save_file("whitelist_mobile.txt", mobile_list) # Mobile specific
    
    # All (mixed vless + ss)
    all_final = [v['node'] for v in sorted_nodes[:12000]] + ss_list[:3000]
    save_file("all.txt", all_final)
    save_file("vless_vmess.txt", [v['node'] for v in sorted_nodes[:10000]]) # Without SS

    # Stats update
    with open(agg.rep_path, 'w', encoding='utf-8') as f:
        # Simple stats update (mockup logic for speed)
        for item in sorted_nodes:
            nid = agg.get_node_id(item['node'])
            if nid not in agg.reputation: agg.reputation[nid] = {'count': 0, 'last_seen': 0}
            agg.reputation[nid]['count'] += 1
            agg.reputation[nid]['last_seen'] = int(time.time())
        json.dump(agg.reputation, f)

    print("🏁 Update Complete!")

if __name__ == "__main__":
    main()
