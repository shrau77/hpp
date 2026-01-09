import requests, base64, re, os, socket, geoip2.database, json, hashlib, shutil, time, ipaddress
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor

# ============================================================================
# ⚙️ 0. ПРЕДВАРИТЕЛЬНАЯ НАСТРОЙКА
# ============================================================================

def update_geoip():
    """Авто-скачивание базы GeoIP"""
    db_path = 'GeoLite2-Country.mmdb'
    mirror_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    
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

# Источники (Полный список)
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
    def __init__(self):
        self.rep_path = 'reputation.json'
        self.reputation = self._load_json(self.rep_path)
        self.geo_cache = {}
        # Загрузка базы GeoLite2 происходит в main
        self.reader = geoip2.database.Reader('GeoLite2-Country.mmdb') if os.path.exists('GeoLite2-Country.mmdb') else None
        
        self.uuid_counter = {}
        self.sni_counter = {}
    
    def _load_json(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cleaned = {}
                    for k, v in data.items():
                        if isinstance(v, int): 
                            cleaned[k] = {"count": v, "last_seen": int(time.time())}
                        elif isinstance(v, dict):
                            cleaned[k] = v
                    return cleaned
            except: return {}
        return {}
    
    def _check_asn(self, ip):
        """Проверка ASN"""
        try:
            # FIX: Если IP похож на IP, проверяем. Если нет - игнорируем, чтобы не крашилось
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ip_obj = ipaddress.ip_address(ip)
                for net, name in RU_ASN_MAP.items():
                    if ip_obj in ipaddress.ip_network(net):
                        return name, "RU"
        except: 
            pass
        return None, None

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
    
    def _extract_uuid(self, node):
        """Извлекает UUID (Safe Mode)"""
        try:
            if node.startswith('vmess://'):
                # Для VMess пытаемся декодировать, если не вышло - ищем по регексу в base64 (редко, но бывает)
                try:
                    base_part = node[8:].split('?')[0].split('#')[0]
                    missing = len(base_part) % 4
                    if missing: base_part += '=' * (4 - missing)
                    decoded = base64.b64decode(base_part).decode('utf-8', errors='ignore')
                    # Пробуем найти JSON
                    if '{' in decoded:
                        try:
                            js = json.loads(decoded[decoded.find('{'):decoded.rfind('}')+1])
                            return js.get('id', '')
                        except: pass
                except: pass
            
            # Универсальный Regex для UUID в строке
            match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', node, re.IGNORECASE)
            if match: return match.group(0)
            
            # Для Vless/Trojan если нет UUID (например, password), берем user part
            if node.startswith(('vless://', 'trojan://')):
                return urlparse(node).netloc.split('@')[0]
                
        except: pass
        return None
    
    def _extract_sni(self, node):
        """Извлекает SNI"""
        try:
            match = re.search(r'sni=([^&?#\s]+)', node.lower())
            if match: return match.group(1).strip('.')
            # Для VMess внутри JSON
            if 'vmess://' in node:
                # (Упрощенная проверка без полного декода для скорости, если строка открыта)
                pass 
        except: pass
        return None
    def _get_uuid_frequency(self, uuid):
        return self.uuid_counter.get(uuid, 0)
    
    def _get_sni_frequency(self, sni):
        return self.sni_counter.get(sni, 0)

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

    def get_node_id(self, node):
        """Хеш конфига без имени для идентификации в репутации"""
        return hashlib.md5(node.split('#')[0].encode()).hexdigest()

    def get_fp(self, node):
        """Генерация Fingerprint на основе хеша ссылки"""
        hash_val = int(self.get_node_id(node), 16)
        choice = hash_val % 100
        if choice < 50: return "chrome"
        if choice < 75: return "ios"
        if choice < 90: return "edge"
        return "safari"

    def calculate_score(self, node):
        score = 0
        n_l = node.lower()
        try:
            parsed = urlparse(node)
        except: return 0
        
        # 1. Reputation (История жизни сервера)
        node_id = self.get_node_id(node)
        rep_data = self.reputation.get(node_id, {})
        score += rep_data.get('count', 0) * 50

        # 2. Технические бонусы
        if 'xtls-rprx-vision' in n_l: score += 300
        if 'type=xhttp' in n_l: score += 400          
        # XUDP больше не бонусится принудительно, но если есть - не штрафуем
        if any(p in n_l for p in ['tuic', 'hysteria2', 'hy2']): score += 250
        if 'trojan' in n_l: score += 100
        if 'reality' in n_l or 'security=reality' in n_l: score += 200
        
        # 3. Порты
        try:
            port = parsed.netloc.split(':')[-1]
            if port in ELITE_PORTS: score += 250
            elif port == '443': score += 100
        except: pass

        # 4. SNI & Host анализ
        sni = self._extract_sni(node)
        if sni:
            if 'max.ru' in sni: score += 1000 
            if any(elite_sni in sni for elite_sni in ULTRA_ELITE_SNI): score += 500
            
            if any(s in sni for s in BLACK_SNI): score -= 5000
            if any(ts == sni or sni.endswith('.'+ts) for ts in TARGET_SNI): score += 300
            if "itunes.apple.com" in sni: score += 250
            
            # Бонус за субдомены (часто признак чистого CDN)
            if (sni.count('.') >= 3 or any(sub in sni for sub in ['st.', 'api.', 'cdn.', 'disk.'])):
                score += 100
        
        # 4.1. ASN Ghost Logic (Проверка провайдера)
        try:
            host_ip = parsed.netloc.split('@')[-1].split(':')[0]
            asn_name, _ = self._check_asn(host_ip)
            if asn_name: score += 500
        except: pass
        
        if any(h in parsed.netloc for h in CHAMPION_HOSTS): score += 50

        # 5. Платные провайдеры
        for _, patterns in PREMIUM_PROVIDER_PATTERNS.items():
            if any(marker in n_l for marker in patterns):
                score += 200

        # 6. ALPN & FP
        alpn_value = self._extract_alpn_decoded(node)
        if alpn_value:
            if 'h3' in alpn_value: score += 80
            elif 'h2' in alpn_value: score += 40
            
        if 'fp=' in n_l: score += 50
            
        # 7. Частота UUID (отсеиваем паблик мусор)
        uuid = self._extract_uuid(node)
        if uuid:
            uuid_count = self._get_uuid_frequency(uuid)
            # Если 1 UUID на 50 серверах - это мусорный паблик
            if uuid_count >= 50: score -= 100
            elif uuid_count >= 3: score += 50 # Популярный, но в меру

        return max(score, 0)

    def patch(self, node):
        """
        ИСПРАВЛЕННЫЙ ПАТЧЕР (SAFE MODE)
        - Не ломает VMess
        - Не удаляет PBK/SID для Reality
        - Не навязывает XUDP
        """
        try:
            # --- VMESS: SKIP PATCHING ---
            # Избегаем перекодирования Base64, чтобы не терять параметры json
            if node.startswith('vmess://'):
                return node
            
            # --- VLESS / TROJAN ---
            if node.startswith(('vless://', 'trojan://')):
                parsed = urlparse(node)
                # keep_blank_values=True важен, чтобы не терять пустые параметры если они есть
                query = parse_qs(parsed.query, keep_blank_values=True)
                
                changed = False
                
                # 1. Fingerprint (FP) - ставим рандомный, только если нет
                if 'fp' not in query or not query['fp'][0]:
                    query['fp'] = [self.get_fp(node)]
                    changed = True
                
                # 2. ALPN - ставим дефолт, только если нет
                if 'alpn' not in query or not query['alpn'][0]:
                    query['alpn'] = ['h2,http/1.1']
                    changed = True
                
                # 3. Type fix
                if 'type' in query:
                    net_type = query['type'][0]
                    if net_type == 'ws' and 'path' not in query:
                        query['path'] = ['/']
                        changed = True
                    if net_type == 'grpc' and 'serviceName' not in query:
                        query['serviceName'] = ['grpc']
                        changed = True

                # 4. Reality Fixes (SID check)
                if 'security' in query and query['security'][0] == 'reality':
                    # Если есть pbk, но нет sid -> добавляем sid (иногда нужно для коннекта)
                    if 'pbk' in query and 'sid' not in query:
                        query['sid'] = ['1a']
                        changed = True
                    # ВАЖНО: Мы больше не удаляем и не перезаписываем параметры. 
                    # PBK останется на месте, так как parse_qs его считал.

                if changed:
                    new_query = urlencode(query, doseq=True)
                    return urlunparse(parsed._replace(query=new_query))
            
            return node
        except: 
            return node

    def get_geo(self, node):
        """Геолокация: ASN (Map) → IP (GeoLite) → Domain Rules"""
        try:
            parsed = urlparse(node)
            if not parsed.netloc: return "UN"
            
            host = parsed.netloc.split('@')[-1].split(':')[0]
            if not host: return "UN"
            
            # 1. Check ASN Map first (Свои диапазоны - самые точные для нас)
            asn_name, asn_country = self._check_asn(host)
            if asn_country == "RU":
                self.geo_cache[host] = "RU"
                return "RU"

            # Cache check
            if host in self.geo_cache: return self.geo_cache[host]
            
            # 2. GeoLite2 (если это IP)
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                if self.reader:
                    try:
                        result = self.reader.country(host)
                        country = result.country.iso_code or "UN"
                        self.geo_cache[host] = country
                        return country
                    except: pass
            
            # 3. Domain Rules (если это домен)
            domain_lower = host.lower()
            if domain_lower.endswith(('.ru', '.su', '.рф', '.yandex.net', '.mail.ru')):
                self.geo_cache[host] = "RU"
                return "RU"
            if domain_lower.endswith('.kz'): return "KZ"
            if domain_lower.endswith('.by'): return "BY"
            if domain_lower.endswith('.ua'): return "UA"
            if domain_lower.endswith('.tr'): return "TR"
            if domain_lower.endswith('.de'): return "DE"
            if domain_lower.endswith('.us'): return "US"
            
            self.geo_cache[host] = "UN"
            return "UN"
        except: return "UN"

    def generate_server_name(self, geo, index, rep_count, score, node=""):
        """Генерация имени"""
        # Определяем качество
        if score >= 1500: quality = "PLATINUM"
        elif score >= 1000: quality = "ELITE"
        elif score >= 500: quality = "PREMIUM"
        elif score >= 300: quality = "STANDARD"
        else: quality = "BASIC"
        
        # Определяем провайдера
        provider = ""
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            
            # Проверка по ASN
            asn_name, _ = self._check_asn(host)
            if asn_name: 
                provider = f"-{asn_name}"
            else:
                # Проверка по SNI
                sni = self._extract_sni(node)
                if sni:
                    if 'max.ru' in sni: provider = "-VK-MAX"
                    elif 'x5.ru' in sni: provider = "-X5-RETAIL"
                    elif 'tbank' in sni: provider = "-T-BANK"
                    elif 'google' in sni: provider = "-GGL"
        except: pass
        
        flag = "🏳️"
        if geo != "UN" and len(geo) == 2:
            try: flag = "".join(chr(ord(c.upper()) + 127397) for c in geo)
            except: pass
        elif geo == "RU": flag = "🇷🇺"
        
        # Формат более компактный, чтобы не резалось на мобилках
        return f"{flag} {geo}{provider}-{index:04d} {quality}"

    def cleanup_reputation(self, max_age_days=30, max_entries=20000):
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

def save(file, data):
    """Функция сохранения файлов + генерация Base64 версии"""
    if not data: 
        return
    try:
        # Сохранение текстовой версии
        content = "\n".join(data)
        with open(file, 'w', encoding='utf-8') as f: 
            f.write(content)
        
        # Сохранение Base64 версии (для многих клиентов это важно)
        b64_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(file + ".b64", 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"💾 {file} (+.b64): {len(data)} записей")
    except Exception as e:
        print(f"❌ Ошибка сохранения {file}: {e}")

def main():
    # 1. Обновляем базы
    update_geoip()
    
    agg = MetaAggregator()
    
    # 2. Скачивание с заголовками
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    def fetch(url):
        try: 
            # Таймаут поменьше, чтобы не висело вечно
            return requests.get(url, headers=headers, timeout=10).text
        except Exception:
            return ""
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚡ Сбор источников...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(fetch, urls))
    
    raw_nodes = []
    for content in results:
        if not content: continue
        
        # Декодирование если источник полностью в Base64
        # (Простая проверка: если нет :// в начале, скорее всего это b64)
        if "://" not in content[:100]:
            try: 
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: pass
        
        # Разбиваем по строкам и чистим
        nodes = [l.strip() for l in content.splitlines() if l and "://" in l and not l.startswith("//")]
        raw_nodes.extend(nodes)

    print(f"📊 Всего сырых строк: {len(raw_nodes)}")

    # 3. Первичная фильтрация и дедупликация
    # Используем более точный ключ для дедупликации, чтобы не терять серверы на одном IP
    unique_map = {}
    ss_nodes = []
    mobile_nodes = [] 
    
    processed_count = 0
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Обработка и дедупликация...")
    
    for node in raw_nodes:
        processed_count += 1
        if processed_count % 5000 == 0:
            print(f"  ...обработано {processed_count} строк")
            
        if any(trash in node for trash in ["127.0.0.1", "localhost"]):
            continue
            
        try:
            # Убираем имя (хвост после #), чтобы сравнивать чисто конфиги
            base_link = node.split('#')[0]
            
            # --- SS HANDLING ---
            if base_link.startswith('ss://'):
                # Исключаем VLESS замаскированные под SS (плагины)
                if 'v2ray-plugin' in base_link or 'obfs-local' in base_link:
                    pass 
                elif 'vless' in base_link or 'uuid' in base_link:
                    continue 
                
                if base_link not in ss_nodes:
                    ss_nodes.append(node) # Сохраняем с именем если есть
                continue
            
            # --- VLESS/VMESS/TROJAN HANDLING ---
            # Парсим URL
            try:
                p = urlparse(base_link)
                if not p.netloc: continue
            except: continue

            # Извлекаем параметры для уникального ключа
            host = p.netloc.split('@')[-1].split(':')[0]
            try: port = p.netloc.split(':')[-1]
            except: port = '443'
            
            uuid = agg._extract_uuid(base_link)
            path = "root"
            
            # Если это WS/GRPC, путь тоже важен для уникальности
            # (один сервер может раздавать разные конфиги по разным путям)
            query = parse_qs(p.query)
            if 'path' in query: path = query['path'][0]
            elif 'serviceName' in query: path = query['serviceName'][0]
            
            # !!! ИСПРАВЛЕНИЕ "ИСЧЕЗАЮЩИХ" СЕРВЕРОВ !!!
            # Ключ теперь включает PORT, UUID и PATH.
            # Раньше был только host, поэтому 5 конфигов на одном IP схлопывались в 1.
            uniq_key = f"{host}:{port}:{uuid}:{path}"
            
            # Мобильные подборки
            sni = agg._extract_sni(base_link)
            if sni and any(x in sni for x in ['mts', 'beeline', 'megafon', 't2.ru', 'yota', 'tele2']):
                mobile_nodes.append(base_link)

            # Сохраняем
            if uniq_key not in unique_map:
                unique_map[uniq_key] = base_link
                
        except: 
            continue
    
    # Формируем список уникальных VLESS/VMESS нод
    all_unique_vless = list(unique_map.values())
    
    print(f"✅ Уникальных VLESS/VMESS/Trojan: {len(all_unique_vless)}")
    print(f"✅ Уникальных SS: {len(ss_nodes)}")

    # 4. Обновляем статистику (UUID/SNI) для скоринга
    agg._update_statistics(all_unique_vless)
    
    # 5. Финальное обогащение
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💎 Финальный патчинг и ранжирование...")
    
    enriched_nodes = []
    for node in all_unique_vless:
        # Патчим (безопасно, см. класс MetaAggregator)
        patched_node = agg.patch(node)
        
        # Считаем очки
        final_score = agg.calculate_score(patched_node)
        
        # Определяем ГЕО
        geo = agg.get_geo(patched_node)
        
        enriched_nodes.append({
            'node': patched_node,
            'score': final_score,
            'sni': agg._extract_sni(patched_node),
            'geo': geo,
            'raw': node # на всякий случай
        }) 
    
    # Сортировка: Сначала по очкам (убывание)
    enriched_nodes.sort(key=lambda x: x['score'], reverse=True)
    
    # 6. Подготовка списков
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 📝 Генерация имен и списков...")
    
    processed_final = []
    now_ts = int(time.time())
    
    # Берем ТОП-20000 (или сколько нужно)
    TOP_LIMIT = 20000 
    
    for i, item in enumerate(enriched_nodes[:TOP_LIMIT]):
        node = item['node']
        score = item['score']
        geo = item['geo']
        
        # Обновляем счетчик репутации для следующего запуска
        node_id = agg.get_node_id(node)
        rep_entry = agg.reputation.get(node_id, {"count": 0, "last_seen": now_ts})
        rep_entry["count"] += 1
        rep_entry["last_seen"] = now_ts
        agg.reputation[node_id] = rep_entry
        
        # Генерируем красивое имя
        name = agg.generate_server_name(str(geo), i+1, rep_entry["count"], score, node)
        
        # Прикрепляем имя через решетку (стандартный формат)
        full_link = f"{node}#{name}"
        
        processed_final.append({
            'link': full_link,
            'score': score,
            'sni': item['sni'],
            'node_clean': node
        })
        
    # 7. Категоризация
    ultra_elite_list = []
    business_list = []
    leaked_gems_list = []
    vless_vmess_list = []
    
    for item in processed_final:
        link = item['link']
        score = item['score']
        node_clean = item['node_clean']
        sni = item['sni']
        
        vless_vmess_list.append(link)
        
        if score >= 1000:
            ultra_elite_list.append(link)
            business_list.append(link)
        elif score >= 500:
            business_list.append(link)
            
        # "Leaked Gems" - редкие протоколы или важные SNI
        is_xhttp = 'type=xhttp' in node_clean
        is_max = sni and 'max.ru' in sni
        if is_xhttp or is_max:
            leaked_gems_list.append(link)

    # 8. Сохранение
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 Запись файлов...")

    save("ultra_elite.txt", ultra_elite_list)
    save("business.txt", business_list)
    save("leaked_gems.txt", leaked_gems_list)
    save("ss.txt", ss_nodes) # Сохраняем все SS
    save("whitelist_mobile.txt", mobile_nodes)
    save("vless_vmess.txt", vless_vmess_list)
    
    # ALL: VLESS + SS
    all_content = vless_vmess_list + ss_nodes
    # Перемешивать не будем, пусть VLESS (отсортированные) идут первыми
    save("all.txt", all_content)
    
    # Legacy Support (для совместимости со старыми ссылками)
    try:
        shutil.copy("business.txt", "hard_hidden.txt")
        shutil.copy("all.txt", "sub.txt")
        shutil.copy("all.txt", "all_configs.txt")
    except: pass

    # 9. Сохранение базы репутации
    agg.cleanup_reputation()
    try:
        with open(agg.rep_path, 'w', encoding='utf-8') as f:
            json.dump(agg.reputation, f, indent=2)
        print("✅ База репутации обновлена")
    except Exception as e:
        print(f"❌ Ошибка записи репутации: {e}")

    if agg.reader:
        agg.reader.close()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 Готово.")
    print(f"📊 ИТОГИ:")
    print(f"  - 💎 Ultra Elite: {len(ultra_elite_list)}")
    print(f"  - 💼 Business: {len(business_list)}")
    print(f"  - 🌐 Total (All): {len(all_content)}")

if __name__ == "__main__":
    main() 
