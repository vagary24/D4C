import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import openpyxl
from openpyxl.styles import Alignment
from time import sleep
from bs4 import BeautifulSoup
from colorama import Fore
import warnings
import argparse
from config import proxies,defult_Timeout
from lib.log import logger
warnings.filterwarnings("ignore")

proxy = proxies

def get_title(response):
    # 获取响应的 Content-Type，判断内容格式
    content_type = response.headers.get('Content-Type', '').lower()
    
    if 'html' in content_type:
        # 处理 HTML 响应
        soup = BeautifulSoup(response.content, 'html.parser')
        title = str(soup.title.string) if soup.title else ""
    elif 'json' in content_type:
        # 处理 JSON 响应
        json_data = response.json()  # 转换为 JSON 对象
        title = "JSON Response"
    elif 'xml' in content_type or 'text/xml' in content_type or 'application/xml' in content_type:
        # 处理 XML 响应
        soup = BeautifulSoup(response.content, 'xml')
        title = "XML Response"
    else:
        # 处理其他类型的响应（如纯文本、二进制文件等）
        title = f"Non-HTML Response: {content_type}"
    return title

# 定义一个函数来探测单个 IP 地址
def probe_ip(ip, baseurl, status_codes, session):
    if 'http' not in ip:
        url = f"http://{ip}{baseurl}"
    else:
        url = f"{ip}{baseurl}"
    logger.info(f"请求{ip}{baseurl}")
    try:
        response = session.get(url, proxies=proxy, timeout=defult_Timeout, verify=False)
        status_code = response.status_code
        # print(status_code)
        if status_code in status_codes:
            title = get_title(response)
            if status_code >= 200 and status_code <= 299:
                logger.info(Fore.GREEN+f"请求成功{url} <StatusCode>: {status_code} <title>: {title} <lenth>: {len(response.content)}"+Fore.RESET)
                # print(Fore.GREEN+f"[INFO] 请求成功{url} <StatusCode>: {status_code} <title>: {title} <lenth>: {len(response.content)}"+Fore.RESET)
            if status_code >= 300 and status_code <= 399: 
                logger.info(Fore.YELLOW+f"请求成功{url} <StatusCode>: {status_code} <title>: {title} <lenth>: {len(response.content)}"+Fore.RESET) 
                # print(Fore.YELLOW+f"[WARNING] 请求成功{url} <StatusCode>: {status_code} <title>: {title} <lenth>: {len(response.content)}"+Fore.RESET)
            if status_code >= 400 and status_code <= 599:
                logger.info(Fore.RED+f"请求成功{url} <StatusCode>: {status_code} <title>: {title} <lenth>: {len(response.content)}"+Fore.RESET) 
                # print(Fore.RED+f"[WARNING] 请求成功{url} <StatusCode>: {status_code} <title>: {title} <lenth>: {len(response.content)}"+Fore.RESET)
            return {
                'url': url,
                'status_code': status_code,
                'title': title,  # 通常用标题来标识，但HTTP没有标题，所以用X-Frame-Options代替
                'response_length': len(response.content)
            }
    except requests.exceptions.SSLError as e:
        # 如果发生SSL错误，可能是因为站点需要HTTPS
        ip.replace('http://', 'https://')
        print(e)
        # print(Fore.RED+f"[ERROR] {url} 需要HTTPS"+Fore.RESET)
        return probe_ip(ip, baseurl, status_codes, session)
    except requests.RequestException as e:
        logger.info(f"{ip} RequestException : {e}")
        # print(Fore.RED+f"[ERROR] {ip} RequestException : {e}"+Fore.RESET)
    except Exception as e:
        logger.info(f"Exception {ip}: {e}")
        # print(Fore.RED+f"[ERROR] Exception {ip}: {e}"+Fore.RESET)
    return None

def process_results(futures):
    """
    生成器函数，用于处理 Future 对象并产生结果。
    """
    for future in as_completed(futures):
        # print("-----------as_completed--------------")
        result = future.result()  # 等待结果并获取
        if result:
            yield result

# 文件迭代器生成器函数
def file_iterator(input_file_path):
    with open(input_file_path, 'r') as file:
        for line in file:
            yield line.strip()

# 定义主函数
def probe_ips(input_file_path, output_file_path, status_codes, baseurl, thread_count,bs=100,use_proxy=False):
    # print(Fore.GREEN+"SurvivalScan基本参数"+Fore.RESET)
    logger.info(f"输入文件 {input_file_path}")
    logger.info(f"输出文件 {output_file_path}")
    logger.info(f"基本路径BaseURL {baseurl}")
    logger.info(f"最大线程数 {thread_count}")
    logger.info(f"缓冲区大小 {bs}"+Fore.RESET)
    if not use_proxy:
        global proxy
        proxy = None

    # 创建一个 Excel 工作簿
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Probe Results"
    ws.append(["URL", "Status Code", "Title", "Response Length"])

    # 设置 Excel 单元格居中
    for cell in ws["1:1"]:
        cell.alignment = Alignment(horizontal='center')

    # 创建一个缓冲区来存储结果
    buffer = []
    buffer_size = bs  # 当缓冲区达到这个大小时，写入文件并清空
    sum = 0
    # 创建一个会话，以便复用底层的 TCP 连接
    with requests.Session() as session:
        with open(input_file_path, 'r') as file:
            ips = [line.strip() for line in file.readlines()]
            
            # 使用线程池来并发探测 IP 地址
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                # 提交所有的探测任务，并收集 Future 对象
                futures = [executor.submit(probe_ip, ip, baseurl, status_codes, session) for ip in file_iterator(input_file_path)]
                # 使用生成器函数来处理结果
                
                for result in process_results(futures):
                    sum += 1
                    buffer.append(result)
                    # 当缓冲区达到一定大小时，写入 Excel 并清空缓冲区
                    if len(buffer) >= buffer_size:
                        logger.info("缓冲区已满正在写入结果")
                        for item in buffer:
                            ws.append([item['url'], item['status_code'], item['title'], item['response_length']])
                        buffer.clear()
                        logger.success(f"成功写入{buffer_size}条结果保存至 {output_file_path}")

        # 将剩余的结果写入 Excel
        for item in buffer:
            ws.append([item['url'], item['status_code'], item['title'], item['response_length']])

    # 保存 Excel 文件
    wb.save(output_file_path)
    logger.success(f"共{sum}条结果保存至 {output_file_path}")

def process_status_codes(statusCode):
    # 将状态码参数转换为整数列表，并处理范围
    status_codes = []
    for code in statusCode:
        if '-' in code:
            start, end = map(int, code.split('-'))
            status_codes.extend(range(start, end + 1))
        else:
            status_codes.append(int(code))
    # print(status_codes)
    return status_codes

# 调用主函数
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Probe IP addresses for liveliness.")
    parser.add_argument("-f","--file", help="Path to the input file containing IP addresses.")
    parser.add_argument("-of","--outputFile", help="Path to the output Excel file.")
    parser.add_argument("-c","--statusCode", nargs='+', help="Status codes that indicate liveliness.")
    parser.add_argument("-bu","--baseurl", help="Base URL to append to IP addresses for HTTP requests.")
    parser.add_argument("-t","--threads", type=int, default=10, help="Number of threads to use.")
    parser.add_argument("-bs","--buffer_size", type=int, default=100, help="缓冲区大小用于优化内存建议默认")
    args = parser.parse_args()

    # 将状态码参数转换为整数列表，并处理范围
    status_codes = process_status_codes(args)
    # print(status_codes)
    probe_ips(args.file, args.outputFile, status_codes, args.baseurl, args.threads,args.buffer_size)
    