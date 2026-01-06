import requests, base64, re, os, socket, geoip2.database, json, hashlib, shutil, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
TARGET_SNI = list(set([
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

BLACK_SNI = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'porn']
ELITE_PORTS = ['2053', '2083', '2087', '2096']
CHAMPION_HOSTS = ['yandex', 'selectel', 'timeweb', 'firstbyte', 'gcore', 'vkcloud', 'mail.ru']

# ============================================================================
# ULTRA ELITE КОНСТАНТЫ
# ============================================================================

# УЛЬТРА-ЭЛИТНЫЕ SNI (из анализа платных серверов)
ULTRA_ELITE_SNI = [
    # Апловский CDN
    "hls-svod.itunes.apple.com", "itunes.apple.com",
    # Кастомные домены платных
    "fastsync.xyz", "cloudlane.xyz", "powodzenia.xyz", 
    "shiftline.xyz", "edgeport.xyz",
    # Редкие поддомены ВК
    "stats.vk-portal.net", "akashi.vk-portal.net",
    # Иностранные ресурсы
    "deepl.com", "www.samsung.com", "cdnjs.cloudflare.com",
    # Наши старые элитные
    "st.ozone.ru", "disk.yandex.ru", "api.mindbox.ru",
    # Дополнительные редкие
    "travel.yandex.ru", "egress.yandex.net", "sba.yandex.net",
    "strm.yandex.net", "goya.rutube.ru",
]

# Паттерны платных провайдеров
PREMIUM_PROVIDER_PATTERNS = {
    "iskra": ['connect-iskra.ru', 'iskra-connect.xyz', 'fp=qq', 'xpaddingbytes='],
    "tcp_reset": ['tcp-reset-club.net', 'tcp-reset-club'],
    "abvpn": ['tcpnet.fun', 'tcpdoor.net', 'abvpn.ru', 'fp=firefox'],
    "vezdehod": ['blh', 'rblx', 'gmn']
}

# Элитные порты (расширяем существующие)
ELITE_PORTS = ['2053', '2083', '2087', '2096', '8447', '9443', '10443'] + ELITE_PORTS
ELITE_PORTS = list(set(ELITE_PORTS))  # Убираем дубли

urls = [
    "https://s3c3.001.gpucloud.ru/dggdu/xixz",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
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
        self.reader = geoip2.database.Reader('GeoLite2-Country.mmdb') if os.path.exists('GeoLite2-Country.mmdb') else None
        self.server_counter = {}
        
        # ДОБАВЛЕНО: новые счетчики для ULTRA ELITE
        self.uuid_counter = {}
        self.sni_counter = {}
    
    def _load_json(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        if isinstance(v, int): data[k] = {"count": v, "last_seen": int(time.time())}
                    return data
            except: return {}
        return {}

    # ДОБАВЛЕННЫЕ МЕТОДЫ ДЛЯ ULTRA ELITE
    def _extract_alpn_decoded(self, node):
        """Извлекает и декодирует ALPN для любого протокола"""
        try:
            patterns = [
                r'alpn=([^&?\s]+)',
                r'"alpn":"([^"]+)"',
                r"'alpn':'([^']+)'",
            ]
            
            for pattern in patterns:
                match = re.search(pattern, node, re.IGNORECASE)
                if match:
                    alpn_value = match.group(1)
                    try:
                        alpn_value = unquote(alpn_value)
                    except:
                        pass
                    alpn_value = alpn_value.replace('\\"', '"').replace("\\'", "'")
                    return alpn_value
            return None
        except:
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
                    if uuid:
                        self.uuid_counter[uuid] = self.uuid_counter.get(uuid, 0) + 1
                    
                    sni = self._extract_sni(node)
                    if sni:
                        self.sni_counter[sni] = self.sni_counter.get(sni, 0) + 1
                except:
                    continue
        except:
            pass
    
    # ДОБАВЛЕНО: метод извлечения UUID
    def _extract_uuid(self, node):
        """Извлекает UUID из ноды"""
        try:
            if node.startswith('vmess://'):
                # Пробуем извлечь из Base64
                base_part = node[8:].split('?')[0]
                try:
                    missing_padding = len(base_part) % 4
                    if missing_padding:
                        base_part += '=' * (4 - missing_padding)
                    decoded = base64.b64decode(base_part).decode('utf-8')
                    json_data = json.loads(decoded)
                    return json_data.get('id')
                except:
                    # Пробуем найти UUID в строке
                    uuid_match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', node, re.IGNORECASE)
                    if uuid_match:
                        return uuid_match.group(0)
            elif node.startswith(('vless://', 'trojan://')):
                # Извлекаем из URL
                parsed = urlparse(node)
                user_info = parsed.netloc.split('@')[0]
                if user_info and '@' in parsed.netloc:
                    return user_info
        except:
            pass
        return None
    
    # ДОБАВЛЕНО: метод извлечения SNI
    def _extract_sni(self, node):
        """Извлекает SNI из ноды"""
        try:
            match = re.search(r'sni=([^&?#\s]+)', node.lower())
            if match:
                return match.group(1).strip('.')
        except:
            pass
        return None

    def get_node_id(self, node):
        return hashlib.md5(node.split('#')[0].encode()).hexdigest()

    def get_fp(self, node):
        hash_val = int(self.get_node_id(node), 16)
        choice = hash_val % 100
        if choice < 65: return "chrome"
        if choice < 85: return "edge"
        if choice < 95: return "safari"
        return "ios"

    def calculate_score(self, node):
        score = 0
        n_l = node.lower()
        parsed = urlparse(node)
        
        node_id = self.get_node_id(node)
        rep_data = self.reputation.get(node_id, {})
        score += rep_data.get('count', 0) * 50

        if 'xtls-rprx-vision' in n_l: score += 150
        if any(p in n_l for p in ['type=xhttp', 'mode=stream-up', 'tuic', 'hysteria2', 'hy2']): score += 250
        if 'trojan' in n_l: score += 100
        
        port = parsed.netloc.split(':')[-1] if ':' in parsed.netloc else '443'
        if port in ELITE_PORTS: score += 250
        elif port == '443': score += 100

        sni_match = re.search(r'sni=([^&?#\s]+)', n_l)
        if sni_match:
            sni = sni_match.group(1).strip('.')
            if any(s in sni for s in BLACK_SNI): score -= 2000
            if any(ts == sni or sni.endswith('.'+ts) for ts in TARGET_SNI): score += 300
        
        if any(h in parsed.netloc for h in CHAMPION_HOSTS): score += 50
        
        # ========================================================================
        # ДОБАВЛЕННЫЙ БЛОК ULTRA ELITE БОНУСОВ
        # ========================================================================
        
        # ULTRA ELITE БОНУСЫ
        sni = self._extract_sni(node)
        
        # 1. Ultra Elite SNI
        if sni and any(elite_sni in sni for elite_sni in ULTRA_ELITE_SNI):
            score += 300
        
        # 2. Особый бонус за itunes.apple.com
        if sni and "itunes.apple.com" in sni:
            score += 250
        
        # 3. Платные провайдеры
        if any(marker in n_l for marker in PREMIUM_PROVIDER_PATTERNS["iskra"]):
            score += 200
        
        if any(marker in n_l for marker in PREMIUM_PROVIDER_PATTERNS["tcp_reset"]):
            score += 150
        
        if any(marker in n_l for marker in PREMIUM_PROVIDER_PATTERNS["abvpn"]):
            score += 180
        
        if any(marker in n_l for marker in PREMIUM_PROVIDER_PATTERNS["vezdehod"]):
            score += 130
        
        # 4. ALPN с декодированием
        alpn_value = self._extract_alpn_decoded(node)
        if alpn_value:
            if 'h3' in alpn_value or 'h3-29' in alpn_value:
                score += 80 if not node.startswith('vmess://') else 40
            elif 'h2' in alpn_value:
                score += 40 if not node.startswith('vmess://') else 20
        
        # 5. UUID частота (используется в _update_statistics)
        uuid = self._extract_uuid(node)
        if uuid:
            uuid_count = self._get_uuid_frequency(uuid)
            if uuid_count >= 10:
                score += 150
            elif uuid_count >= 5:
                score += 80
            elif uuid_count >= 2:
                score += 30
        
        # 6. Поддомены в SNI
        if sni and (sni.count('.') >= 3 or any(sub in sni for sub in ['st.', 'api.', 'cdn.', 'disk.'])):
            score += 100
        
        # 7. Не-chrome fingerprint
        if any(fp in n_l for fp in ['fp=safari', 'fp=ios', 'fp=firefox', 'fp=edge']):
            score += 80
        
        # КОНЕЦ ДОБАВЛЕНИЙ
        return max(score, 0)

    def patch(self, node):
        try:
            parsed = urlparse(node)
            query = parse_qs(parsed.query)
            
            # ОБРАБОТКА VMESS
            if node.startswith('vmess://'):
                base_part = node[8:].split('?')[0]
                
                if not base_part or len(base_part) < 5:
                    return node
                
                # 1. Проверяем UUID формат
                uuid_match = re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', base_part.lower())
                if uuid_match:
                    if query:
                        new_query = urlencode(query, doseq=True)
                        return urlunparse(parsed._replace(query=new_query))
                    return node
                
                # 2. Проверяем формат UUID@host
                uuid_host_match = re.match(r'^[a-f0-9-]+@[^@]+$', base_part.lower())
                if uuid_host_match:
                    if query:
                        new_query = urlencode(query, doseq=True)
                        return urlunparse(parsed._replace(query=new_query))
                    return node
                
                # 3. Пытаемся декодировать как Base64
                try:
                    base_part_clean = base_part.strip()
                    missing_padding = len(base_part_clean) % 4
                    if missing_padding:
                        base_part_clean += '=' * (4 - missing_padding)
                    
                    decoded = base64.b64decode(base_part_clean, validate=True)
                    
                    try:
                        json_str = decoded.decode('utf-8')
                    except UnicodeDecodeError:
                        json_str = decoded.decode('latin-1')
                    
                    try:
                        config = json.loads(json_str)
                    except json.JSONDecodeError:
                        return node
                    
                    # Исправляем некорректный type
                    type_val = config.get('type', '')
                    if type_val == '---':
                        config['type'] = 'none'
                    
                    # Переносим параметры из query в JSON
                    if query:
                        if 'fp' in query and query['fp'][0]:
                            config['fp'] = query['fp'][0]
                        elif not config.get('fp'):
                            config['fp'] = self.get_fp(node)
                        
                        # ИСПРАВЛЕННЫЙ БЛОК ALPN С ДЕКОДИРОВАНИЕМ
                        if 'alpn' in query and query['alpn'][0]:
                            alpn_value = query['alpn'][0]
                            try:
                                alpn_value = unquote(alpn_value)
                            except:
                                pass
                            config['alpn'] = alpn_value
                        elif not config.get('alpn'):
                            config['alpn'] = 'h2,http/1.1'
                        
                        for key in ['sni', 'host', 'path', 'serviceName']:
                            if key in query and query[key][0] and not config.get(key):
                                config[key] = query[key][0]
                    else:
                        if not config.get('fp'):
                            config['fp'] = self.get_fp(node)
                        if not config.get('alpn'):
                            config['alpn'] = 'h2,http/1.1'
                    
                    new_json = json.dumps(config, separators=(',', ':'))
                    new_base64 = base64.b64encode(new_json.encode()).decode().rstrip('=')
                    
                    return f"vmess://{new_base64}"
                    
                except Exception:
                    return node
            
            # ОБРАБОТКА VLESS/TROJAN
            elif node.startswith(('vless', 'trojan')):
                if not query.get('fp'):
                    query['fp'] = [self.get_fp(node)]
                if not query.get('alpn'):
                    query['alpn'] = ['h2,http/1.1']
                
                net_type = query.get('type', [''])[0]
                if net_type == 'ws' and not query.get('path'):
                    query['path'] = ['/graphql']
                if net_type == 'grpc' and not query.get('serviceName'):
                    query['serviceName'] = ['grpc']
                
                new_query = urlencode(query, doseq=True)
                return urlunparse(parsed._replace(query=new_query))
            
            return node
            
        except Exception:
            return node
            
    def get_geo(self, node):
        """Геолокация: IP → GeoLite2, домены → простые правила"""
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            
            if not host:
                return "UN"
                
            # Кэш
            if host in self.geo_cache:
                return self.geo_cache[host]
            
            # 1. Если это IP - GeoLite2
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                if self.reader:
                    try:
                        result = self.reader.country(host)
                        country = result.country.iso_code or "UN"
                        self.geo_cache[host] = country
                        return country
                    except:
                        self.geo_cache[host] = "UN"
                        return "UN"
            
            # 2. Если домен - простые правила БЕЗ DNS
            # Самые очевидные русские домены
            if host.endswith(('.ru', '.su', '.рф')):
                self.geo_cache[host] = "RU"
                return "RU"
                
            if host.endswith('.ua'):
                self.geo_cache[host] = "UA"
                return "UA"
                
            if host.endswith('.kz'):
                self.geo_cache[host] = "KZ"
                return "KZ"
                
            if host.endswith('.by'):
                self.geo_cache[host] = "BY"
                return "BY"
                
            if host.endswith('.tr'):
                self.geo_cache[host] = "TR"
                return "TR"
            
            # 3. Популярные хосты которые знаем
            RU_HOSTS = ['.yandex.', '.mail.', '.vk.', '.rutube.', 
                       '.rambler.', '.sber.', '.tinkoff.']
            
            for ru_host in RU_HOSTS:
                if ru_host in host:
                    self.geo_cache[host] = "RU"
                    return "RU"
            
            # 4. Не знаем - UN
            self.geo_cache[host] = "UN"
            return "UN"
                
        except Exception:
            return "UN"
            
    def generate_server_name(self, geo, index, rep_count, score):
        """Генерирует имя для тега (после #)"""
        
        if score >= 500:
            quality = "ELITE"
        elif score >= 300:
            quality = "PREMIUM"
        elif score >= 150:
            quality = "STANDARD"
        else:
            quality = "BASIC"
        
        flag = "".join(chr(ord(c.upper()) + 127397) for c in geo) if geo != "UN" else "🌐"
        
        return f"{flag} {geo}-{index:05d}-REP({rep_count})-HPP {quality}"

    def cleanup_reputation(self, max_age_days=30, max_entries=10000):
        now = int(time.time())
        cutoff = now - (max_age_days * 86400)
        clean_db = {k: v for k, v in self.reputation.items() if v.get('last_seen', 0) > cutoff}
        if len(clean_db) > max_entries:
            sorted_rep = sorted(clean_db.items(), key=lambda x: x[1]['count'], reverse=True)
            clean_db = dict(sorted_rep[:max_entries])
        self.reputation = clean_db

def save(file, data):
    """Функция сохранения файлов"""
    if not data: 
        return
    try:
        with open(file, 'w', encoding='utf-8') as f: 
            f.write("\n".join(data))
        print(f"💾 {file}: {len(data)} записей")
    except Exception as e:
        print(f"❌ Ошибка сохранения {file}: {e}")

def main():
    agg = MetaAggregator()
    
    def fetch(url):
        try: 
            return requests.get(url, timeout=15).text
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
            
        if "://" not in content[:100]:
            try: 
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: 
                continue
        
        nodes = [l.strip() for l in content.splitlines() if "://" in l and not l.startswith("//")]
        raw_nodes.extend(nodes)
        print(f"  📥 Источник {idx+1}: {len(nodes)} нод")

    print(f"📊 Всего собрано нод: {len(raw_nodes)}")
    
    unique_map = {}
    ss_nodes = []
    cable_nodes = []
    mobile_nodes = []
    
    processed_count = 0
    for node in raw_nodes:
        processed_count += 1
        if processed_count % 1000 == 0:
            print(f"  🔄 Обработано {processed_count}/{len(raw_nodes)} нод")
            
        if any(trash in node for trash in ["0.0.0.0", "127.0.0.1"]):
            continue
            
        try:
            base_link = node.split('#')[0]
            tag = node.split('#')[1] if '#' in node else ""
            
            if base_link.startswith('ss://'):
                if len(base_link) < 10:
                    continue
                
                if any(x in base_link.lower() for x in ['vless', 'reality', 'vnext', 'uuid']):
                    continue
                
                if '@' not in base_link and ':' not in base_link[5:]:
                    try:
                        b64_part = base_link[5:].split('#')[0]
                        if not re.match(r'^[A-Za-z0-9+/=]+$', b64_part):
                            continue
                    except:
                        continue
                
                ss_nodes.append(node)
                continue
            
            p = urlparse(base_link)
            ip_key = f"{p.scheme}@{p.netloc.split('@')[-1].split(':')[0]}"
            score = agg.calculate_score(base_link)
            
            full_node_with_tag = f"{base_link}#{tag}" if tag else base_link
            tag_lower = tag.lower()
            if 'cable' in tag_lower:
                cable_nodes.append(full_node_with_tag)
            if 'mobile' in tag_lower:
                mobile_nodes.append(full_node_with_tag)
            
            if ip_key not in unique_map or score > unique_map[ip_key]['score']:
                unique_map[ip_key] = {
                    'node': base_link, 
                    'score': score, 
                    'tag': tag,
                    'full_with_tag': full_node_with_tag
                }
        except: 
            continue
    
    sorted_nodes = sorted(unique_map.values(), key=lambda x: x['score'], reverse=True)
    all_unique = [v['node'] for v in sorted_nodes]
    
    print(f"✅ Уникальных нод после фильтрации: {len(all_unique)}")
    print(f"✅ SS нод: {len(ss_nodes)}")

    # 1. Обновляем статистику
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 📊 Обновление статистики UUID/SNI...")
    agg._update_statistics(all_unique)
    
    # 2. Обогащаем ноды данными
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 📊 Обогащение нод данными...")
    enriched_nodes = []
    for i, node in enumerate(all_unique):
        score = agg.calculate_score(node)  # пересчитываем с учётом статистики
        geo = agg.get_geo(node)
        enriched_nodes.append({
            'node': node,
            'score': score,
            'sni': agg._extract_sni(node),
            'uuid': agg._extract_uuid(node), 
            'geo': geo
        }) 
    
    # 3. Сортируем
    enriched_nodes.sort(key=lambda x: x['score'], reverse=True)
    
    vless_pool = [n['node'] for n in enriched_nodes if not n['node'].startswith('ss://')][:5000]
    ss_pool = ss_nodes[:2000]
    
    processed_vless = []
    now_ts = int(time.time())
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Обработка воронки ТОП-5000...")
    for i, node in enumerate(vless_pool):
        if i % 500 == 0:
            print(f"  ⏳ Обработано {i}/{len(vless_pool)} VLESS нод")
            
        node_id_hash = agg.get_node_id(node)
        rep_entry = agg.reputation.get(node_id_hash, {"count": 0, "last_seen": now_ts})
        rep_entry["count"] += 1
        rep_entry["last_seen"] = now_ts
        agg.reputation[node_id_hash] = rep_entry
        
        geo = agg.get_geo(node)
        patched = agg.patch(node)
        score = agg.calculate_score(node)
        
        rep_val = rep_entry["count"]
        geo_str = str(geo) if geo else "UN"
        
        name = agg.generate_server_name(geo_str, i+1, rep_val, score)
        
        processed_vless.append({'node': f"{patched}#{name}", 'geo': geo_str, 'score': score, 'raw': node})
    
    # 4. Функция определения ultra elite
    def is_ultra_elite(node_data):
        try:
            node = node_data['node']
            n_l = node.lower()
            sni = node_data['sni']
            score = node_data['score']
            
            ultra_score = 0
            
            # Elite SNI
            if sni and any(elite_sni in sni for elite_sni in ULTRA_ELITE_SNI):
                ultra_score += 3
            
            # Платные провайдеры
            for patterns in PREMIUM_PROVIDER_PATTERNS.values():
                if any(pattern in n_l for pattern in patterns):
                    ultra_score += 2
            
            # xHTTP
            if 'type=xhttp' in n_l:
                ultra_score += 2
                if 'mode=auto' in n_l or 'mode=stream-up' in n_l:
                    ultra_score += 1
                if 'xpaddingbytes=' in n_l:
                    ultra_score += 1
            
            # Качественные настройки
            if 'flow=xtls-rprx-vision' in n_l:
                ultra_score += 1
            
            if any(fp in n_l for fp in ['fp=safari', 'fp=ios', 'fp=firefox', 'fp=edge']):
                ultra_score += 1
            
            # Элитные порты
            if any(port in node for port in [f':{p}' for p in ELITE_PORTS]):
                ultra_score += 2
            
            # UUID частота
            uuid = node_data['uuid']
            if uuid:
                uuid_count = agg._get_uuid_frequency(uuid)
                if uuid_count >= 10:
                    ultra_score += 3
                elif uuid_count >= 5:
                    ultra_score += 2
            
            # Поддомены
            if sni and (sni.count('.') >= 3 or any(sub in sni for sub in ['st.', 'api.', 'cdn.', 'disk.'])):
                ultra_score += 1
            
            # Редкий SNI
            if sni and agg._get_sni_frequency(sni) <= 5:
                ultra_score += 2
            
            # Порог
            if len(enriched_nodes) > 0:
                top_30_threshold = enriched_nodes[int(len(enriched_nodes) * 0.3)]['score']
            else:
                top_30_threshold = 0
            
            return ultra_score >= 5 and score >= top_30_threshold
        except:
            return False
    
    # 5. Собираем ultra elite (С ТЕГАМИ КАК В business.txt)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💎 Формирование ULTRA ELITE списка...")
    ultra_elite_servers = []
    
    # Берем ТОЛЬКО уже обработанные ноды из processed_vless (они уже имеют теги с флагами)
    elite_counter = 0
    for processed in processed_vless:
        if elite_counter >= 1000:
            break
        
        # Находим эту ноду в enriched_nodes для проверки is_ultra_elite
        node_data = None
        for n in enriched_nodes:
            if n['node'] == processed['raw']:
                node_data = n
                break
        
        if node_data and is_ultra_elite(node_data):
            ultra_elite_servers.append(processed['node'])  # Уже содержит тег с флагом
            elite_counter += 1
        
        # Прогресс
        if elite_counter > 0 and elite_counter % 100 == 0:
            print(f"    ⏳ Найдено {elite_counter} ULTRA ELITE серверов")

    print(f"    ✅ Итог: {elite_counter} ULTRA ELITE серверов с тегами")

    # 6. Сохраняем ultra elite
    with open("ultra_elite.txt", 'w', encoding='utf-8') as f:
        f.write("\n".join(ultra_elite_servers))
    print(f"  💎 ultra_elite.txt: {len(ultra_elite_servers)} ULTRA ELITE серверов")
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 📊 Подготовка ultra elite...")
    
    # Сохранение остальных файлов
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 Сохранение файлов...")

    save("hard_hidden.txt", [n['node'] for n in processed_vless[:1000] if n['score'] >= 500])
    save("mob.txt", [n['node'] for n in processed_vless if n['score'] >= 300][:1000])
    save("med.txt", [n['node'] for n in processed_vless if 150 <= n['score'] < 450][:2000])
    save("vls.txt", [n['node'] for n in processed_vless])

    filtered_ss = []
    for ss_node in ss_pool:
        try:
            base_link = ss_node.split('#')[0]
            if agg.get_geo(base_link) != "RU":
                filtered_ss.append(ss_node)
        except:
            continue

    save("ss.txt", filtered_ss[:2000])
    save("all.txt", all_unique[:25000])

    save("whitelist_cable.txt", cable_nodes)
    save("whitelist_mobile.txt", mobile_nodes)

    try:
        shutil.copy("hard_hidden.txt", "business.txt")
        shutil.copy("vls.txt", "vless_vmess.txt")
        shutil.copy("all.txt", "sub.txt")
        shutil.copy("all.txt", "all_configs.txt")
        print("✅ Созданы дополнительные копии файлов")
    except Exception as e:
        print(f"⚠️ Ошибка копирования файлов: {e}")

    agg.cleanup_reputation()
    with open(agg.rep_path, 'w', encoding='utf-8') as f:
        json.dump(agg.reputation, f, indent=2)
    print("✅ Обновлена репутация серверов")

    if agg.reader:
        agg.reader.close()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 Скрипт успешно завершен.")
    print(f"📊 Итоги:")
    print(f"  - Всего нод: {len(raw_nodes)}")
    print(f"  - Уникальных: {len(all_unique)}")
    print(f"  - ULTRA ELITE: {len(ultra_elite_servers)}")
    print(f"  - Обработано VLESS: {len(processed_vless)}")
    print(f"  - SS нод: {len(filtered_ss)}")

if __name__ == "__main__":
    main()  
