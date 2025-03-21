proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080',  # 通常https代理也使用http协议
}

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]

defult_Timeout = 5
defult_THREAD_POOL_SIZE = 1
defult_log_dir = "./log"

tags_file = 'templates/tags.txt'
map_file = 'templates/map.json'
templates_dir = 'F:\\桌面\\CTF\\工具包\\yakit\\Yakit\\nuclei-templates'
fingerprinting_file = 'templates/fingerprinthub-web-fingerprints.yaml'
fingerprinting_dir = "F:\\桌面\\CTF\\工具包\\2024HW漏洞\\FingerprintHub\\web-fingerprint"
email_sender = ''    # 发送方的邮箱账号
email_passwd = ''            # 授权码
email_team = ['']        # 接收方的邮箱账号，不一定是QQ邮箱