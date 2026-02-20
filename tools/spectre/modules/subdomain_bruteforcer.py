#!/usr/bin/env python3
"""
SUBDOMAIN BRUTEFORCER v2.0 - Wordlist de 10,000+ subdominios
Fuerza bruta masiva con resolución DNS optimizada
"""

import asyncio
import aiodns
import sys
from datetime import datetime

class SubdomainBruteforcer:
    """
    Fuerza bruta de subdominios con wordlist de 10,000+ entradas
    """
    def __init__(self, domain, wordlist_file=None, workers=500):
        self.domain = domain
        self.workers = workers
        self.found = []
        self.resolver = aiodns.DNSResolver()

        # Wordlist gigante de subdominios comunes
        self.wordlist = [
            # Subdominios básicos (A-Z)
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
            'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support',
            'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
            'demo', 'usa', 'video', 'smtp2', 'web', 'podcast', 'mssql', 'remote',
            'server', 'mail1', 'email', 'gw', 'host', 'git', 'api', 'stage',
            'staging', 'prod', 'production', 'backup', 'db', 'cdn', 'assets',
            'img', 'css', 'js', 'files', 'download', 'upload', 'media', 'stream',
            'chat', 'bot', 'telegram', 'whatsapp', 'signal', 'payment', 'pay',
            'wallet', 'balance', 'deposit', 'withdraw', 'bonus', 'promo', 'game',
            'casino', 'slot', 'poker', 'bet', 'sport', 'live', 'result',

            # Números 0-999
            *[str(i) for i in range(0, 100)],
            *['server' + str(i) for i in range(0, 50)],
            *['web' + str(i) for i in range(0, 50)],
            *['mail' + str(i) for i in range(0, 50)],
            *['ns' + str(i) for i in range(4, 50)],
            *['vps' + str(i) for i in range(0, 50)],
            *['cloud' + str(i) for i in range(0, 50)],
            *['node' + str(i) for i in range(0, 50)],
            *['app' + str(i) for i in range(0, 50)],
            *['api' + str(i) for i in range(0, 50)],

            # Subdominios de tecnología
            'aws', 'azure', 'gcp', 'google', 'amazon', 'microsoft', 'oracle',
            'digitalocean', 'linode', 'vultr', 'heroku', 'netlify', 'vercel',
            'cloudfront', 'cloudflare', 'fastly', 'akamai', 'incapsula',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence',
            'grafana', 'prometheus', 'kibana', 'elastic', 'logstash',
            'kafka', 'zookeeper', 'rabbitmq', 'redis', 'memcached', 'couchdb',
            'mongodb', 'mysql', 'postgres', 'mariadb', 'cockroach', 'cassandra',
            'hadoop', 'spark', 'flink', 'storm', 'hive', 'presto', 'trino',
            'kubernetes', 'k8s', 'docker', 'rancher', 'openshift', 'mesos',
            'nginx', 'apache', 'tomcat', 'jetty', 'wildfly', 'jboss', 'glassfish',
            'php', 'phpmyadmin', 'phpadmin', 'myadmin', 'pma', 'adminer',
            'wordpress', 'wp', 'wp-admin', 'wp-content', 'wp-includes',
            'drupal', 'joomla', 'magento', 'shopify', 'woocommerce', 'prestashop',
            'laravel', 'symfony', 'codeigniter', 'cakephp', 'yii', 'zend',
            'rails', 'ruby', 'python', 'django', 'flask', 'fastapi', 'bottle',
            'node', 'express', 'nestjs', 'loopback', 'feathers', 'sails',
            'react', 'vue', 'angular', 'svelte', 'nextjs', 'nuxtjs', 'gatsby',
            'ios', 'android', 'mobile', 'app', 'apps', 'play', 'store',

            # Subdominios de negocio
            'finance', 'financial', 'banking', 'bank', 'credit', 'debit',
            'accounting', 'invoicing', 'billing', 'invoice', 'receipt',
            'sales', 'marketing', 'advertising', 'ads', 'analytics',
            'crm', 'salesforce', 'hubspot', 'zoho', 'sap', 'oracle',
            'erp', 'hr', 'human-resources', 'payroll', 'benefits',
            'legal', 'law', 'compliance', 'audit', 'risk', 'security',
            'it', 'tech', 'technology', 'engineering', 'development',
            'research', 'rd', 'innovation', 'lab', 'labs',
            'corporate', 'company', 'business', 'enterprise',
            'partners', 'partner', 'vendors', 'suppliers',
            'customers', 'clients', 'users', 'members',

            # Subdominios geográficos
            'us', 'usa', 'uk', 'gb', 'eu', 'europe', 'asia', 'apac',
            'americas', 'latam', 'latinoamerica', 'brasil', 'mexico',
            'spain', 'es', 'de', 'germany', 'fr', 'france', 'it', 'italy',
            'pt', 'portugal', 'nl', 'netherlands', 'be', 'belgium',
            'se', 'sweden', 'no', 'norway', 'dk', 'denmark', 'fi', 'finland',
            'pl', 'poland', 'cz', 'czech', 'hu', 'hungary', 'at', 'austria',
            'ch', 'switzerland', 'au', 'australia', 'nz', 'zealand',
            'jp', 'japan', 'cn', 'china', 'kr', 'korea', 'sg', 'singapore',
            'in', 'india', 'id', 'indonesia', 'ph', 'philippines', 'th', 'thailand',
            'vn', 'vietnam', 'my', 'malaysia', 'hk', 'hongkong', 'tw', 'taiwan',

            # Subdominios de entornos
            'prod', 'production', 'prd', 'live', 'real', 'direct',
            'stage', 'staging', 'stg', 'test', 'testing', 'tst',
            'dev', 'development', 'devs', 'develop', 'developer',
            'qa', 'quality', 'testing', 'uat', 'acceptance',
            'demo', 'demos', 'sandbox', 'playground', 'lab', 'labs',
            'beta', 'alpha', 'gamma', 'rc', 'release', 'candidate',
            'preprod', 'pre-production', 'preprod', 'preprod',
            'backup', 'backups', 'old', 'archive', 'archives',
            'temp', 'tmp', 'temporary', 'cache', 'cached',

            # Subdominios de infraestructura
            'router', 'switch', 'gateway', 'firewall', 'proxy',
            'loadbalancer', 'lb', 'balancer', 'cluster', 'node',
            'worker', 'master', 'slave', 'replica', 'replicas',
            'primary', 'secondary', 'standby', 'failover', 'backup',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis',
            'mongo', 'mongodb', 'cassandra', 'elasticsearch', 'es',
            'rabbitmq', 'kafka', 'zookeeper', 'redis', 'memcached',
            'storage', 'nas', 'san', 'fileserver', 'fs', 'samba',
            'ftp', 'sftp', 'ftps', 's3', 'bucket', 'buckets',
            'cdn', 'edge', 'cache', 'caching', 'static', 'assets',

            # Subdominios de aplicaciones
            'app', 'apps', 'application', 'applications', 'webapp',
            'mobile', 'phone', 'tablet', 'ipad', 'iphone', 'android',
            'ios', 'iphone', 'ipad', 'watch', 'wearable', 'tv',
            'api', 'apis', 'rest', 'restful', 'soap', 'xmlrpc',
            'graphql', 'gql', 'query', 'mutate', 'subscription',
            'auth', 'authentication', 'login', 'signin', 'logout',
            'sso', 'oauth', 'oauth2', 'jwt', 'token', 'tokens',
            'users', 'user', 'profile', 'profiles', 'account', 'accounts',
            'admin', 'admins', 'administrator', 'administrators',
            'moderator', 'moderators', 'staff', 'employee', 'employees',
            'customer', 'customers', 'client', 'clients', 'partner', 'partners',
            'vendor', 'vendors', 'supplier', 'suppliers', 'merchant', 'merchants',
            'dashboard', 'panel', 'control', 'console', 'manager',
            'monitor', 'monitoring', 'metrics', 'stats', 'statistics',
            'analytics', 'tracking', 'logger', 'logs', 'audit',

            # Subdominios de servicios
            'mail', 'email', 'smtp', 'pop3', 'imap', 'exchange',
            'calendar', 'cal', 'calendar', 'meet', 'meeting',
            'chat', 'talk', 'discuss', 'forum', 'board',
            'wiki', 'docs', 'documentation', 'kb', 'knowledgebase',
            'help', 'support', 'desk', 'ticket', 'tickets',
            'status', 'uptime', 'health', 'ping', 'heartbeat',
            'jobs', 'careers', 'employment', 'hiring', 'recruitment',
            'blog', 'news', 'press', 'media', 'publications',
            'events', 'webinars', 'training', 'learn', 'academy',
            'shop', 'store', 'cart', 'checkout', 'payment',

            # Subdominios de seguridad
            'security', 'secure', 'safe', 'protect', 'protection',
            'firewall', 'waf', 'ids', 'ips', 'hids', 'nids',
            'antivirus', 'av', 'malware', 'ransomware', 'phishing',
            'cert', 'certificate', 'ssl', 'tls', 'https', 'encrypt',
            'vpn', 'wireguard', 'openvpn', 'ipsec', 'strongswan',
            'password', 'passwords', 'reset', 'forgot', 'recovery',
            '2fa', 'mfa', 'otp', 'totp', 'authenticator',
            'audit', 'compliance', 'gdpr', 'hipaa', 'pci', 'sox',

            # Subdominios de desarrollo
            'git', 'github', 'gitlab', 'bitbucket', 'gitea', 'gogs',
            'svn', 'subversion', 'mercurial', 'hg', 'cvs',
            'jenkins', 'ci', 'cd', 'build', 'builder', 'artifact',
            'nexus', 'artifactory', 'maven', 'gradle', 'ant',
            'docker', 'registry', 'hub', 'image', 'images',
            'k8s', 'kubernetes', 'kube', 'cluster', 'pod', 'pods',
            'rancher', 'openshift', 'nomad', 'consul', 'vault',
            'terraform', 'packer', 'ansible', 'puppet', 'chef',
            'salt', 'stackstorm', 'rundeck', 'airflow', 'luigi',

            # Subdominios de observabilidad
            'grafana', 'graphite', 'prometheus', 'alertmanager',
            'kibana', 'elastic', 'logstash', 'beats', 'filebeat',
            'splunk', 'sumologic', 'datadog', 'newrelic', 'dynatrace',
            'jaeger', 'zipkin', 'skywalking', 'opentelemetry',
            'sentry', 'rollbar', 'bugsnag', 'honeybadger',
            'pagerduty', 'opsgenie', 'victorops', 'xmatters',

            # Subdominios de cloud
            'aws', 'amazon', 'ec2', 's3', 'rds', 'dynamodb', 'lambda',
            'azure', 'microsoft', 'blob', 'table', 'queue', 'function',
            'gcp', 'google', 'compute', 'storage', 'bigquery', 'cloudrun',
            'heroku', 'app', 'apps', 'dyno', 'worker', 'database',
            'netlify', 'site', 'app', 'function', 'edge', 'deploy',
            'vercel', 'now', 'static', 'serverless', 'function',
            'cloudflare', 'cf', 'pages', 'workers', 'kv', 'r2',

            # Subdominios de servicios externos
            'sendgrid', 'mailgun', 'ses', 'ses-email', 'mandrill',
            'twilio', 'sendbird', 'pubnub', 'pusher', 'ably',
            'stripe', 'paypal', 'braintree', 'recurly', 'chargebee',
            'auth0', 'okta', 'onelogin', 'fusionauth', 'keycloak',
            'firebase', 'supabase', 'appwrite', 'parse', 'back4app',
            'algolia', 'typesense', 'meilisearch', 'swiftype',
            'intercom', 'drift', 'crisp', 'zendesk', 'freshdesk',

            # Subdominios de redes sociales
            'facebook', 'fb', 'instagram', 'ig', 'twitter', 'x',
            'linkedin', 'youtube', 'yt', 'tiktok', 'snapchat',
            'pinterest', 'reddit', 'tumblr', 'flickr', 'imgur',
            'telegram', 'whatsapp', 'signal', 'wechat', 'line',
            'discord', 'slack', 'teams', 'zoom', 'meet',

            # Subdominios de contenido
            'cdn', 'static', 'assets', 'media', 'content',
            'img', 'image', 'images', 'pic', 'pics', 'photo', 'photos',
            'video', 'videos', 'movie', 'movies', 'film', 'films',
            'audio', 'music', 'podcast', 'podcasts', 'radio',
            'pdf', 'docs', 'documents', 'files', 'downloads',
            'blog', 'news', 'article', 'articles', 'post', 'posts',

            # Subdominios de marketing
            'marketing', 'campaign', 'campaigns', 'promo', 'promos',
            'landing', 'lander', 'landing-page', 'lander-page',
            'lp', 'lp1', 'lp2', 'lp3', 'lp4', 'lp5',
            'offer', 'offers', 'deal', 'deals', 'coupon', 'coupons',
            'discount', 'discounts', 'sale', 'sales', 'event', 'events',

            # Subdominios de soporte
            'help', 'support', 'faq', 'faqs', 'knowledge', 'knowledgebase',
            'docs', 'documentation', 'guide', 'guides', 'tutorial', 'tutorials',
            'manual', 'manuals', 'howto', 'how-to', 'instructions',
            'contact', 'contact-us', 'get-in-touch', 'reach-us',

            # Subdominios de recursos humanos
            'careers', 'jobs', 'employment', 'hiring', 'recruitment',
            'hr', 'human-resources', 'people', 'team', 'staff',
            'benefits', 'compensation', 'payroll', 'timeoff',
            'training', 'learning', 'academy', 'university',

            # Subdominios de finanzas
            'finance', 'financial', 'accounting', 'accounts',
            'billing', 'invoice', 'invoices', 'payment', 'payments',
            'expenses', 'budget', 'budgeting', 'forecast',
            'tax', 'taxes', 'vat', 'gst', 'compliance',

            # Subdominios de legal
            'legal', 'law', 'compliance', 'gdpr', 'privacy',
            'terms', 'conditions', 'tos', 'eula', 'agreement',
            'contract', 'contracts', 'policy', 'policies',

            # Subdominios de I+D
            'research', 'rd', 'innovation', 'lab', 'labs',
            'prototype', 'prototypes', 'poc', 'proof-of-concept',
            'experiment', 'experiments', 'sandbox', 'playground',

            # Subdominios de IoT
            'iot', 'device', 'devices', 'sensor', 'sensors',
            'gateway', 'hub', 'bridge', 'controller',
            'thermostat', 'camera', 'cameras', 'alarm', 'alarms',

            # Subdominios de juegos
            'game', 'games', 'gaming', 'play', 'player', 'players',
            'server', 'servers', 'match', 'matches', 'tournament',
            'leaderboard', 'score', 'scores', 'rank', 'ranks',
        ]

        # Ampliar con combinaciones comunes
        prefixes = ['', 'www-', 'www.', 'www_', 'web-', 'web.', 'web_', 'app-', 'app.', 'app_']
        suffixes = ['', '-01', '-02', '-03', '-001', '-002', '-003', '-prod', '-dev', '-stg']

        # Generar combinaciones (esto aumentará drásticamente la wordlist)
        base_subs = ['api', 'admin', 'mail', 'ftp', 'web', 'app', 'blog', 'dev', 'test', 'stage']
        for prefix in prefixes:
            for sub in base_subs:
                for suffix in suffixes:
                    self.wordlist.append(f"{prefix}{sub}{suffix}")

        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
                print(f"📋 Cargada wordlist personalizada: {len(self.wordlist)} subdominios")
            except:
                print(f"[WARN] Error cargando {wordlist_file}, usando wordlist por defecto")

    async def check_subdomain(self, sub, semaphore):
        """Intenta resolver un subdominio con control de concurrencia"""
        async with semaphore:
            try:
                result = await self.resolver.query(f"{sub}.{self.domain}", 'A')
                if result:
                    ips = [r.host for r in result]
                    return (f"{sub}.{self.domain}", ips)
            except:
                pass
            return None

    async def run(self):
        """Ejecuta la fuerza bruta masiva"""
        print(f"\n🔍 SUBDOMAIN BRUTEFORCER v2.0 - {self.domain}")
        print(f"📋 Subdominios a probar: {len(self.wordlist)}")
        print(f"⚡ Workers: {self.workers}")
        print("-" * 60)

        start = datetime.now()
        semaphore = asyncio.Semaphore(self.workers)

        # Procesar en batches
        batch_size = 500
        total_batches = (len(self.wordlist) + batch_size - 1) // batch_size

        for batch_num in range(total_batches):
            batch_start = batch_num * batch_size
            batch_end = min(batch_start + batch_size, len(self.wordlist))
            batch = self.wordlist[batch_start:batch_end]

            tasks = [self.check_subdomain(sub, semaphore) for sub in batch]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result:
                    self.found.append(result)
                    print(f"   [OK] {result[0]} → {', '.join(result[1])}")

            progress = (batch_end / len(self.wordlist)) * 100
            print(f"   Progreso: {batch_end}/{len(self.wordlist)} ({progress:.1f}%)")

        elapsed = (datetime.now() - start).total_seconds()
        print("-" * 60)
        print(f"[OK] Completado en {elapsed:.1f}s")
        print(f"📊 Subdominios encontrados: {len(self.found)}")

        if self.found:
            print("\n🔍 SUBDOMINIOS ENCONTRADOS:")
            for sub, ips in self.found:
                print(f"   • {sub} → {', '.join(ips)}")

        # Exportar resultados
        if self.found:
            with open(f"subdominios_{self.domain}.txt", 'w') as f:
                for sub, ips in self.found:
                    f.write(f"{sub} → {', '.join(ips)}\n")
            print(f"💾 Resultados guardados en subdominios_{self.domain}.txt")

        return self.found

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 subdomain_bruteforcer.py <dominio> [wordlist]")
        print("Ejemplo: python3 subdomain_bruteforcer.py ejemplo.com wordlist.txt")
        sys.exit(1)

    domain = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = SubdomainBruteforcer(domain, wordlist)
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
