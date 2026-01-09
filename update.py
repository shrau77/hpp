import requests, base64, re, os, socket, geoip2.database, json, hashlib, shutil, time, ipaddress
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor

# ============================================================================
# ⚙️ 0. ПРЕДВАРИТЕЛЬНАЯ НАСТРОЙКА
# ============================================================================

def update_geoip():
    """Авто-скачивание базы GeoIP (из нового кода)"""
    db_path = 'GeoLite2-Country.mmdb'
    mirror_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    
    # <ОТСТУП: 4 пробела>
    if not os.path.exists(db_path) or (time.time() - os.path.getmtime(db_path)) > 3 * 86400:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 🌍 Updating GeoIP database...")
            r = requests.get(mirror_url, stream=True, timeout=20)
            if r.status_code == 200:
                with open(db_path, 'wb') as f: shutil.copyfileobj(r.raw, f)
                print("✅ GeoIP database updated.")
        except Exception as e: 
            print(f"⚠️ GeoIP update failed: {e}")

# ============================================================================
# ⚙️ 1. СПИСКИ И КОНСТАНТЫ
# ============================================================================

# Карта "Своих" IP (ASN)
RU_ASN_MAP = {
    "51.250.0.0/16": "YANDEX", "84.201.128.0/17": "YANDEX", "158.160.0.0/16": "YANDEX",
    "95.163.0.0/16": "SELECTEL", "87.242.0.0/16": "SELECTEL", 
    "217.16.0.0/16": "MTS-AEZA", "46.17.0.0/16": "FIRSTBYTE",
    "188.93.16.0/20": "AEZA", "77.246.100.0/22": "SERV-PIPE",
    "212.34.138.0/24": "G-CORE"
}

# Объединенный список SNI
TARGET_SNI = list(set([
    # 👑 PLATINUM
    "max.ru", "web.max.ru", "download.max.ru", "dev.max.ru", "static.max.ru", "api.max.ru",
    "gosuslugi.ru", "www.mos.ru", "nalog.ru", "esia.gosuslugi.ru",
    "smartcaptcha.yandexcloud.net", "sso.passport.yandex.ru", "api-maps.yandex.ru",
    "video.intfreed.ru", "khabarovsk.geodema.network", "my.oversecure.pro",
    
    # Исходный список
    "www.unicreditbank.ru", "www.gazprombank.ru", "cdn.gpb.ru", "mkb.ru", "www.open.ru",
    "cobrowsing.tbank.ru", "cdn.rosbank.ru", "www.psbank.ru", "www.raiffeisen.ru",
    "www.rzd.ru", "st.gismeteo.st", "stat-api.gismeteo.net", "c.dns-shop.ru",
    "restapi.dns-shop.ru", "www.pochta.ru", "passport.pochta.ru", "chat-ct.pochta.ru",
    "www.x5.ru", "www.ivi.ru", "api2.ivi.ru", "hh.ru", "i.hh.ru", "hhcdn.ru",
    "sentry.hh.ru", "cpa.hh.ru", "www.kp.ru", "cdnn21.img.ria.ru", "lenta.ru",
    "sync.rambler.ru", "s.rbk.ru", "www.rbc.ru", "target.smi2.net", "hb-bidder.skcrtxr.com",
    "strm-spbmiran-07.strm.yandex.net", "pikabu.ru", "www.tutu.ru", "cdn1.tu-tu.ru",
    "api.apteka.ru", "static.apteka.ru", "images.apteka.ru", "scitylana.apteka.ru",
    "www.drom.ru", "c.rdrom.ru", "www.farpost.ru", "s11.auto.drom.ru", "i.rdrom.ru",
    "yummy.drom.ru", "www.drive2.ru", "lemanapro.ru", "stats.vk-portal.net",
    "sun6-21.userapi.com", "sun6-20.userapi.com", "avatars.mds.yandex.net",
    "queuev4.vk.com", "sun6-22.userapi.com", "sync.browser.yandex.net", "top-fwz1.mail.ru",
    "ad.mail.ru", "eh.vk.com", "akashi.vk-portal.net", "sun9-38.userapi.com",
    "st.ozone.ru", "ir.ozone.ru", "vt-1.ozone.ru", "io.ozone.ru", "ozone.ru",
    "xapi.ozon.ru", "strm-rad-23.strm.yandex.net", "online.sberbank.ru",
    "esa-res.online.sberbank.ru", "egress.yandex.net", "st.okcdn.ru", "rs.mail.ru",
    "counter.yadro.ru", "742231.ms.ok.ru", "splitter.wb.ru", "a.wb.ru",
    "user-geo-data.wildberries.ru", "banners-website.wildberries.ru",
    "chat-prod.wildberries.ru", "servicepipe.ru", "alfabank.ru", "statad.ru",
    "alfabank.servicecdn.ru", "alfabank.st", "ad.adriver.ru", "privacy-cs.mail.ru",
    "imgproxy.cdn-tinkoff.ru", "mddc.tinkoff.ru", "le.tbank.ru", "hrc.tbank.ru",
    "id.tbank.ru", "rap.skcrtxr.com", "eye.targetads.io", "px.adhigh.net", "nspk.ru",
    "sba.yandex.net", "identitystatic.mts.ru", "tag.a.mts.ru", "login.mts.ru",
    "serving.a.mts.ru", "cm.a.mts.ru", "login.vk.com", "api.a.mts.ru", "mtscdn.ru",
    "d5de4k0ri8jba7ucdbt6.apigw.yandexcloud.net", "moscow.megafon.ru", "api.mindbox.ru",
    "web-static.mindbox.ru", "storage.yandexcloud.net", "personalization-web-stable.mindbox.ru",
    "www.t2.ru", "beeline.api.flocktory.com", "static.beeline.ru", "moskva.beeline.ru",
    "wcm.weborama-tech.ru", "1013a--ma--8935--cp199.stbid.ru", "msk.t2.ru", "s3.t2.ru",
    "get4click.ru", "dzen.ru", "yastatic.net", "csp.yandex.net", "sntr.avito.ru",
    "yabro-wbplugin.edadeal.yandex.ru", "cdn.uxfeedback.ru", "goya.rutube.ru",
    "api.expf.ru", "fb-cdn.premier.one", "www.kinopoisk.ru", "widgets.kinopoisk.ru",
    "payment-widget.plus.kinopoisk.ru", "api.events.plus.yandex.net", "tns-counter.ru",
    "speller.yandex.net", "widgets.cbonds.ru", "www.magnit.com", "magnit-ru.injector.3ebra.net",
    "jsons.injector.3ebra.net", "2gis.ru", "d-assets.2gis.ru", "s1.bss.2gis.com",
    "www.tbank.ru", "strm-spbmiran-08.strm.yandex.net", "id.tbank.ru", "tmsg.tbank.ru",
    "vk.com", "www.wildberries.ru", "www.ozon.ru", "ok.ru", "yandex.ru"
]))

# Список черных SNI
BLACK_SNI = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'porn', 'pusytroller', 'hubp.de', 'dynv6.net']

# Элитные порты
ELITE_PORTS = ['2053', '2083', '2087', '2096', '8447', '9443', '10443', '8443', '443']
ELITE_PORTS = list(set(ELITE_PORTS))

CHAMPION_HOSTS = ['yandex', 'selectel', 'timeweb', 'firstbyte', 'gcore', 'vkcloud', 'mail.ru']

# УЛЬТРА-ЭЛИТНЫЕ SNI
ULTRA_ELITE_SNI = [
    "hls-svod.itunes.apple.com", "itunes.apple.com", "xp.apple.com",
    "fastsync.xyz", "cloudlane.xyz", "powodzenia.xyz", 
    "shiftline.xyz", "edgeport.xyz", "zoomzoom.xyz", "runstream.xyz", "softpipe.xyz",
    "stats.vk-portal.net", "akashi.vk-portal.net",
    "deepl.com", "www.samsung.com", "cdnjs.cloudflare.com",
    "st.ozone.ru", "disk.yandex.ru", "api.mindbox.ru",
    "travel.yandex.ru", "egress.yandex.net", "sba.yandex.net",
    "strm.yandex.net", "goya.rutube.ru",
    "cdn.tbank.ru", "sso.passport.yandex.ru", "download.max.ru"
]

# Паттерны платных провайдеров
PREMIUM_PROVIDER_PATTERNS = {
    "iskra": ['connect-iskra.ru', 'iskra-connect.xyz', 'fp=qq', 'xpaddingbytes='],
    "tcp_reset": ['tcp-reset-club.net', 'tcp-reset-club'],
    "abvpn": ['tcpnet.fun', 'tcpdoor.net', 'abvpn.ru', 'fp=firefox'],
    "vezdehod": ['blh', 'rblx', 'gmn']
}

# Источники
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
class MetaAggregator:
    # <ОТСТУП: 4 пробела>
    def __init__(self):
        self.rep_path = 'reputation.json'
        self.reputation = self._load_json(self.rep_path)
        self.geo_cache = {}
        # Загрузка базы GeoLite2 происходит в main, но здесь инициализируем ридер если файл есть
        self.reader = geoip2.database.Reader('GeoLite2-Country.mmdb') if os.path.exists('GeoLite2-Country.mmdb') else None
        
        # Счетчики статистики
        self.uuid_counter = {}
        self.sni_counter = {}
    
    # <ОТСТУП: 4 пробела>
    def _load_json(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Поддержка обоих форматов репутации
                    cleaned = {}
                    for k, v in data.items():
                        if isinstance(v, int): 
                            cleaned[k] = {"count": v, "last_seen": int(time.time())}
                        elif isinstance(v, dict):
                            cleaned[k] = v
                    return cleaned
            except: return {}
        return {}
    
    # <ОТСТУП: 4 пробела>
    def _check_asn(self, ip):
        """Проверка ASN по диапазонам IP"""
        try:
            # Пропускаем, если это не IP
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                return None, None
            
            ip_obj = ipaddress.ip_address(ip)
            for net, name in RU_ASN_MAP.items():
                if ip_obj in ipaddress.ip_network(net):
                    return name, "RU"
        except: 
            pass
        return None, None

    # <ОТСТУП: 4 пробела>
    def _extract_alpn_decoded(self, node):
        """Извлекает и декодирует ALPN"""
        try:
            patterns = [r'alpn=([^&?\s]+)', r'"alpn":"([^"]+)"', r"'alpn':'([^']+)'"]
            for pattern in patterns:
                match = re.search(pattern, node, re.IGNORECASE)
                if match:
                    alpn_value = match.group(1)
                    try: alpn_value = unquote(alpn_value)
                    except: pass
                    return alpn_value.replace('\\"', '"').replace("\\'", "'")
        except: pass
        return None
    
    # <ОТСТУП: 4 пробела>
    def _extract_uuid(self, node):
        """Извлекает UUID"""
        try:
            if node.startswith('vmess://'):
                base_part = node[8:].split('?')[0]
                try:
                    missing = len(base_part) % 4
                    if missing: base_part += '=' * (4 - missing)
                    decoded = base64.b64decode(base_part).decode('utf-8')
                    return json.loads(decoded).get('id')
                except:
                    return re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', node, re.IGNORECASE).group(0)
            elif node.startswith(('vless://', 'trojan://')):
                return urlparse(node).netloc.split('@')[0]
        except: pass
        return None
    
    # <ОТСТУП: 4 пробела>
    def _extract_sni(self, node):
        """Извлекает SNI"""
        try:
            match = re.search(r'sni=([^&?#\s]+)', node.lower())
            if match: return match.group(1).strip('.')
        except: pass
        return None

    # <ОТСТУП: 4 пробела>
    def _get_uuid_frequency(self, uuid):
        return self.uuid_counter.get(uuid, 0)
    
    def _get_sni_frequency(self, sni):
        return self.sni_counter.get(sni, 0)

    # <ОТСТУП: 4 пробела>
    def _update_statistics(self, nodes):
        """Обновляем статистику UUID и SNI"""
        try:
            self.uuid_counter.clear()
            self.sni_counter.clear()
            for node in nodes:
                try:
                    uuid = self._extract_uuid(node)
                    if uuid: self.uuid_counter[uuid] = self.uuid_counter.get(uuid, 0) + 1
                    sni = self._extract_sni(node)
                    if sni: self.sni_counter[sni] = self.sni_counter.get(sni, 0) + 1
                except: continue
        except: pass

    # <ОТСТУП: 4 пробела>
    def get_node_id(self, node):
        return hashlib.md5(node.split('#')[0].encode()).hexdigest()

    # <ОТСТУП: 4 пробела>
    def get_fp(self, node):
        hash_val = int(self.get_node_id(node), 16)
        choice = hash_val % 100
        if choice < 65: return "chrome"
        if choice < 85: return "edge"
        if choice < 95: return "safari"
        return "ios"

    # <ОТСТУП: 4 пробела>
    def calculate_score(self, node):
        score = 0
        n_l = node.lower()
        parsed = urlparse(node)
        
        # 1. Reputation (База)
        node_id = self.get_node_id(node)
        rep_data = self.reputation.get(node_id, {})
        score += rep_data.get('count', 0) * 50

        # 2. Tech Bonuses (Новые фичи)
        if 'xtls-rprx-vision' in n_l: score += 300
        if 'type=xhttp' in n_l: score += 400          
        if 'packetencoding=xudp' in n_l: score += 100 
        if any(p in n_l for p in ['mode=stream-up', 'tuic', 'hysteria2', 'hy2']): score += 250
        if 'trojan' in n_l: score += 100
        
        # 3. Port Logic
        port = parsed.netloc.split(':')[-1] if ':' in parsed.netloc else '443'
        if port in ELITE_PORTS: score += 250
        elif port == '443': score += 100

        # 4. SNI & Host Logic
        sni = self._extract_sni(node)
        
        # 4.1. Platinum SNI
        if sni and 'max.ru' in sni: 
            score += 1000 
        
        # 4.2. Ultra Elite SNI
        if sni and any(elite_sni in sni for elite_sni in ULTRA_ELITE_SNI):
            score += 500
        
        # 4.3. Target & Blacklist
        if sni:
            if any(s in sni for s in BLACK_SNI): score -= 5000
            if any(ts == sni or sni.endswith('.'+ts) for ts in TARGET_SNI): score += 300
            if "itunes.apple.com" in sni: score += 250
            # Bonus for subdomains
            if (sni.count('.') >= 3 or any(sub in sni for sub in ['st.', 'api.', 'cdn.', 'disk.'])):
                score += 100
        
        # 4.4. ASN Ghost Logic
        try:
            host_ip = parsed.netloc.split('@')[-1].split(':')[0]
            if self._check_asn(host_ip)[0]: # Если IP принадлежит RU_ASN_MAP
                score += 500
        except: pass
        
        if any(h in parsed.netloc for h in CHAMPION_HOSTS): score += 50

        # 5. Premium Providers Logic
        for _, patterns in PREMIUM_PROVIDER_PATTERNS.items():
            if any(marker in n_l for marker in patterns):
                score += 200

        # 6. ALPN & FP Logic
        alpn_value = self._extract_alpn_decoded(node)
        if alpn_value:
            if 'h3' in alpn_value: score += 80
            elif 'h2' in alpn_value: score += 40
            
        if any(fp in n_l for fp in ['fp=safari', 'fp=ios', 'fp=firefox', 'fp=edge']):
            score += 80
            
        # 7. UUID Frequency Logic
        uuid = self._extract_uuid(node)
        if uuid:
            uuid_count = self._get_uuid_frequency(uuid)
            if uuid_count >= 10: score += 150
            elif uuid_count >= 5: score += 80

        return max(score, 0)

    # <ОТСТУП: 4 пробела>
    def patch(self, node):
        """БРОНЕБОЙНЫЙ ПАТЧЕР v3.0"""
        try:
            parsed = urlparse(node)
            query = parse_qs(parsed.query)
            
            # --- VMESS ---
            if node.startswith('vmess://'):
                base_part = node[8:].split('?')[0].split('#')[0]
                if not base_part or len(base_part) < 5: return node
                
                # Check 1: UUID string
                if re.match(r'^[a-f0-9-]{36}$', base_part.lower()): return node
                
                # Check 2: Decode Base64
                try:
                    # Fix padding
                    missing_padding = len(base_part) % 4
                    if missing_padding: base_part += '=' * (4 - missing_padding)
                    
                    decoded = base64.b64decode(base_part).decode('utf-8', errors='ignore')
                    
                    # Clean junk before JSON bracket
                    if '{' in decoded:
                        decoded = decoded[decoded.find('{'):decoded.rfind('}')+1]
                    
                    try: config = json.loads(decoded)
                    except: return node
                    
                    # Merge URL params INTO JSON
                    mapping = {'sni': 'sni', 'host': 'host', 'path': 'path', 'fp': 'fp', 'alpn': 'alpn', 'type': 'net'}
                    if query:
                        for q_key, j_key in mapping.items():
                            if q_key in query and query[q_key][0] and not config.get(j_key):
                                config[j_key] = query[q_key][0]
                    
                    # Defaults
                    if not config.get('fp'): config['fp'] = self.get_fp(node)
                    if not config.get('alpn'): config['alpn'] = 'h2,http/1.1'
                    if not config.get('scy'): config['scy'] = 'auto'
                    
                    # Re-encode
                    new_json = json.dumps(config, separators=(',', ':'))
                    new_base64 = base64.b64encode(new_json.encode()).decode().rstrip('=')
                    return f"vmess://{new_base64}"
                    
                except: return node
            
            # --- VLESS / TROJAN ---
            elif node.startswith(('vless', 'trojan')):
                # xUDP Injection
                if 'packetEncoding' not in query:
                    query['packetEncoding'] = ['xudp']
                
                # Reality SID fix
                if 'security' in query and query['security'][0] == 'reality':
                    if 'pbk' in query and 'sid' not in query:
                        query['sid'] = ['1a']

                if not query.get('fp'): query['fp'] = [self.get_fp(node)]
                if not query.get('alpn'): query['alpn'] = ['h2,http/1.1']
                
                net_type = query.get('type', [''])[0]
                if net_type == 'ws' and not query.get('path'): query['path'] = ['/graphql']
                if net_type == 'grpc' and not query.get('serviceName'): query['serviceName'] = ['grpc']
                
                new_query = urlencode(query, doseq=True)
                return urlunparse(parsed._replace(query=new_query))
            
            return node
        except: return node
        # <ОТСТУП: 4 пробела> (Продолжение класса MetaAggregator)
    def get_geo(self, node):
        """Геолокация: ASN (First) → IP (GeoLite) → Domain Rules"""
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            if not host: return "UN"
            
            # 1. Check ASN Map first
            asn_name, asn_country = self._check_asn(host)
            if asn_country == "RU":
                self.geo_cache[host] = "RU"
                return "RU"

            # Cache check
            if host in self.geo_cache: return self.geo_cache[host]
            
            # 2. GeoLite2
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                if self.reader:
                    try:
                        result = self.reader.country(host)
                        country = result.country.iso_code or "UN"
                        self.geo_cache[host] = country
                        return country
                    except: pass
            
            # 3. Domain Rules
            if host.endswith(('.ru', '.su', '.рф', '.yandex.net', '.mail.ru')):
                self.geo_cache[host] = "RU"
                return "RU"
            if host.endswith('.kz'): return "KZ"
            if host.endswith('.by'): return "BY"
            if host.endswith('.ua'): return "UA"
            if host.endswith('.tr'): return "TR"
            
            self.geo_cache[host] = "UN"
            return "UN"
        except: return "UN"

    # <ОТСТУП: 4 пробела>
    def generate_server_name(self, geo, index, rep_count, score, node=""):
        """Генерация имени"""
        
        # Определяем качество
        if score >= 1500: quality = "PLATINUM 💎"
        elif score >= 1000: quality = "ELITE 🔥"
        elif score >= 500: quality = "PREMIUM 🚀"
        elif score >= 300: quality = "STANDARD"
        else: quality = "BASIC"
        
        # Определяем провайдера
        provider = ""
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            asn_name, _ = self._check_asn(host)
            if asn_name: provider = f"-{asn_name}"
            
            sni = self._extract_sni(node)
            if sni:
                if 'max.ru' in sni: provider = "-VK-MAX"
                elif 'x5.ru' in sni: provider = "-X5-RETAIL"
                elif 'tbank' in sni: provider = "-T-BANK"
        except: pass
        
        flag = "".join(chr(ord(c.upper()) + 127397) for c in geo) if geo != "UN" else "🌐"
        
        # Формат: FLAG GEO-PROV-INDEX-REP QUALITY
        return f"{flag} {geo}{provider}-{index:05d}-REP({rep_count}) {quality}"

    # <ОТСТУП: 4 пробела> (Важно: этот метод должен быть внутри класса!)
    def cleanup_reputation(self, max_age_days=30, max_entries=15000):
        now = int(time.time())
        cutoff = now - (max_age_days * 86400)
        clean_db = {k: v for k, v in self.reputation.items() if v.get('last_seen', 0) > cutoff}
        if len(clean_db) > max_entries:
            sorted_rep = sorted(clean_db.items(), key=lambda x: x[1]['count'], reverse=True)
            clean_db = dict(sorted_rep[:max_entries])
        self.reputation = clean_db

# ============================================================================
# 💾 ФУНКЦИИ СОХРАНЕНИЯ И MAIN
# ============================================================================

# <ОТСТУП: 0 пробелов> (Выход из класса)
def save(file, data):
    """Функция сохранения файлов + генерация Base64 версии"""
    if not data: 
        return
    try:
        # Сохранение текстовой версии
        content = "\n".join(data)
        with open(file, 'w', encoding='utf-8') as f: 
            f.write(content)
        
        # Сохранение Base64 версии
        b64_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(file + ".b64", 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"💾 {file} (+.b64): {len(data)} записей")
    except Exception as e:
        print(f"❌ Ошибка сохранения {file}: {e}")

# <ОТСТУП: 0 пробелов>
def main():
    # 1. Обновляем базы
    update_geoip()
    
    agg = MetaAggregator()
    
    # 2. Скачивание с заголовками
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    # <ОТСТУП: 4 пробела> (Внутренняя функция внутри main)
    def fetch(url):
        try: 
            return requests.get(url, headers=headers, timeout=15).text
        except Exception as e:
            print(f"⚠️ Ошибка загрузки {url[:50]}...: {e}")
            return ""
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚡ Сбор источников...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(fetch, urls))
    
    raw_nodes = []
    for idx, content in enumerate(results):
        if not content:
            continue
            
        # Декодирование если источник полностью в Base64
        if "://" not in content[:100]:
            try: 
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: 
                continue
        
        nodes = [l.strip() for l in content.splitlines() if "://" in l and not l.startswith("//")]
        raw_nodes.extend(nodes)

    print(f"📊 Всего собрано строк: {len(raw_nodes)}")
    # <ОТСТУП: 4 пробела> (Продолжение функции main)
    # 3. Первичная фильтрация и классификация
    unique_map = {}
    ss_nodes = []
    mobile_nodes = [] 
    
    processed_count = 0
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Первичная обработка...")
    
    for node in raw_nodes:
        processed_count += 1
        if processed_count % 5000 == 0:
            print(f"  ...обработано {processed_count} строк")
            
        if any(trash in node for trash in ["0.0.0.0", "127.0.0.1"]):
            continue
            
        try:
            base_link = node.split('#')[0]
            
            # --- SS HANDLING ---
            if base_link.startswith('ss://'):
                if len(base_link) < 15: continue
                # Исключаем VLESS/Reality замаскированные под SS
                if 'v2ray-plugin' in base_link or 'obfs-local' in base_link:
                    pass 
                elif any(x in base_link.lower() for x in ['vless', 'reality', 'uuid']):
                    continue 
                
                # Простая дедупликация для SS
                if base_link not in ss_nodes:
                    ss_nodes.append(base_link)
                continue
            
            # --- VLESS/VMESS/TROJAN HANDLING ---
            sni = agg._extract_sni(base_link)
            
            # Mobile Logic
            if sni and any(x in sni for x in ['mts', 'beeline', 'megafon', 't2.ru', 'yota', 'tele2']):
                mobile_nodes.append(base_link)

            # Deduplication Key
            p = urlparse(base_link)
            if not p.netloc: continue
            
            host_part = p.netloc.split('@')[-1].split(':')[0]
            ip_key = f"{p.scheme}@{host_part}"
            
            # Считаем предварительный скор
            score = agg.calculate_score(base_link)
            
            # Сохраняем лучшую версию ноды для этого IP
            if ip_key not in unique_map or score > unique_map[ip_key]['score']:
                unique_map[ip_key] = {
                    'node': base_link,
                    'score': score
                }
        except: 
            continue
    
    # Формируем список уникальных VLESS/VMESS нод
    all_unique_vless = [v['node'] for v in unique_map.values()]
    
    print(f"✅ Уникальных VLESS/VMESS: {len(all_unique_vless)}")
    print(f"✅ Уникальных SS: {len(ss_nodes)}")

    # 4. Обновляем статистику (CRITICAL STEP)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 📊 Анализ статистики (UUID/SNI)...")
    agg._update_statistics(all_unique_vless)
    
    # 5. Финальное обогащение и расчет скора
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💎 Финальный расчет рангов...")
    
    enriched_nodes = []
    
    for node in all_unique_vless:
        # Патчим ноду
        patched_node = agg.patch(node)
        
        # Пересчитываем скор с учетом статистики
        final_score = agg.calculate_score(patched_node)
        
        geo = agg.get_geo(patched_node)
        
        enriched_nodes.append({
            'node': patched_node,
            'score': final_score,
            'sni': agg._extract_sni(patched_node),
            'uuid': agg._extract_uuid(patched_node), 
            'geo': geo,
            'raw': node
        }) 
    
    # Сортировка по очкам
    enriched_nodes.sort(key=lambda x: x['score'], reverse=True)
    
    # 6. Подготовка списков для сохранения
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 📝 Генерация списков...")
    
    processed_final = []
    now_ts = int(time.time())
    
    # Ограничение общего пула
    TOP_LIMIT = 20000 
    
    for i, item in enumerate(enriched_nodes[:TOP_LIMIT]):
        node = item['node']
        score = item['score']
        geo = item['geo']
        
        # Обновление репутации
        node_id = agg.get_node_id(node)
        rep_entry = agg.reputation.get(node_id, {"count": 0, "last_seen": now_ts})
        rep_entry["count"] += 1
        rep_entry["last_seen"] = now_ts
        agg.reputation[node_id] = rep_entry
        
        # Генерация имени
        name = agg.generate_server_name(str(geo), i+1, rep_entry["count"], score, node)
        
        full_link = f"{node}#{name}"
        
        processed_final.append({
            'link': full_link,
            'score': score,
            'sni': item['sni'],
            'node_clean': node
        })
        
    # 7. Распределение по категориям
    ultra_elite_list = []
    business_list = []
    leaked_gems_list = []
    vless_vmess_list = []
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🗂️ Категоризация...")
    
    for item in processed_final:
        link = item['link']
        score = item['score']
        node_clean = item['node_clean']
        sni = item['sni']
        
        # Общий список
        vless_vmess_list.append(link)
        
        # 7.1. Ultra Elite (Score >= 1000)
        if score >= 1000:
            ultra_elite_list.append(link)
            business_list.append(link)
            
        # 7.2. Business (Score >= 500)
        elif score >= 500:
            business_list.append(link)
            
        # 7.3. Leaked Gems (Экспериментальные/Редкие)
        is_xhttp = 'type=xhttp' in node_clean
        is_max = sni and 'max.ru' in sni
        
        if is_xhttp or is_max:
            leaked_gems_list.append(link)

    # 8. Сохранение файлов
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 Запись на диск...")

    save("ultra_elite.txt", ultra_elite_list)
    save("business.txt", business_list)
    save("leaked_gems.txt", leaked_gems_list)
    save("ss.txt", ss_nodes[:3000])
    save("whitelist_mobile.txt", mobile_nodes)
    save("vless_vmess.txt", vless_vmess_list[:15000])
    
    # ALL: Объединяем лучшие VLESS и SS
    all_content = vless_vmess_list[:20000] + ss_nodes[:5000]
    save("all.txt", all_content)
    
    # Legacy Support
    try:
        shutil.copy("business.txt", "hard_hidden.txt")
        shutil.copy("all.txt", "sub.txt")
        shutil.copy("all.txt", "all_configs.txt")
        print("✅ Созданы Legacy-копии файлов")
    except Exception as e:
        print(f"⚠️ Ошибка копирования Legacy: {e}")

    # 9. Финализация
    agg.cleanup_reputation()
    try:
        with open(agg.rep_path, 'w', encoding='utf-8') as f:
            json.dump(agg.reputation, f, indent=2)
        print("✅ База репутации обновлена")
    except Exception as e:
        print(f"❌ Ошибка записи репутации: {e}")

    if agg.reader:
        agg.reader.close()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 Скрипт успешно завершен.")
    print(f"📊 ИТОГИ:")
    print(f"  - 💎 Ultra Elite: {len(ultra_elite_list)}")
    print(f"  - 💼 Business: {len(business_list)}")
    print(f"  - 🧪 Leaked Gems: {len(leaked_gems_list)}")
    print(f"  - 🔑 SS Nodes: {len(ss_nodes)}")
    print(f"  - 🌐 Total (All): {len(all_content)}")

# <ОТСТУП: 0 пробелов>
if __name__ == "__main__":
    main()
