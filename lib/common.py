import requests
import json
import re
import urllib
import socket
from ipaddress import ip_address
import os
import html
from colorama import Fore
from lib.process import evaluate
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from lib.log import logger
import shutil
import zipfile

'''
通用函数
'''
UNRESOLVED_VARIABLE = '---UNRESOLVED-VARIABLE---'

# 标记
class Marker:
    # General marker (open/close)
    General = "§"
    # ParenthesisOpen marker - begin of a placeholder
    ParenthesisOpen = "{{"
    # ParenthesisClose marker - end of a placeholder
    ParenthesisClose = "}}"

# 变量替换
def marker_replace(data, dynamic_values):
    """replaces placeholders in template with values
    """
    data = json.dumps(data)
    for k, v in dynamic_values.items():
        if k in data:
            data = data.replace(f'{Marker.General}{k}{Marker.General}', str(v))
            data = data.replace(f'{Marker.ParenthesisOpen}{k}{Marker.ParenthesisClose}', str(v))

    # TODO 执行函数
    # execute various helper functions
    data = evaluate(data, dynamic_values)

    if UNRESOLVED_VARIABLE in data:
        raise Exception

    return json.loads(data)

# 讲response转换成dsl_map用于后续dsl匹配和提取
def http_response_to_dsl_map(resp: requests.Response):
    """Converts an HTTP response to a map for use in DSL matching
    """
    data = {}
    if not isinstance(resp, requests.Response):
        return data

    for k, v in resp.cookies.items():
        data[k.lower()] = v
    for k, v in resp.headers.items():
        data[k.lower().replace('-', '_')] = v

    req_headers_raw = '\n'.join(f'{k}: {v}' for k, v in resp.request.headers.items())
    req_body = resp.request.body
    if not req_body:
        req_body = b''
    if not isinstance(req_body, bytes):
        req_body = req_body.encode()
    resp_headers_raw = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
    resp_body = resp.content

    data['request'] = req_headers_raw.encode() + b'\n\n' + req_body
    data['response'] = resp_headers_raw.encode() + b'\n\n' + resp_body
    data['status_code'] = resp.status_code
    data['body'] = resp_body
    data['all_headers'] = resp_headers_raw
    data['header'] = resp_headers_raw
    data['kval_extractor_dict'] = {}
    data['kval_extractor_dict'].update(resp.cookies)
    data['kval_extractor_dict'].update(resp.headers)

    return data

# 获取response中待匹配/提取的部分
def http_get_match_part(part: str, resp_data: dict, return_bytes: bool = False) -> str:
    result = ''
    if part == '':
        part = 'body'

    if part in resp_data:
        result = resp_data[part]

    if return_bytes and not isinstance(result, bytes):
        result = str(result).encode()
    elif not return_bytes and isinstance(result, bytes):
        try:
            result = result.decode()
        except UnicodeDecodeError:
            result = str(result)
    return result

# 解析url用作静态值提取
def urlparse(address):
    # https://stackoverflow.com/questions/50499273/urlparse-fails-with-simple-url
    try:
        ip = ip_address(address)
        if ip.version == 4:
            return urllib.parse.urlparse(f'tcp://{address}')
        elif ip.version == 6:
            return urllib.parse.urlparse(f'tcp://[{address}]')
    except ValueError:
        pass

    if not re.search(r'^[A-Za-z0-9+.\-]+://', address):
        address = f'tcp://{address}'
    return urllib.parse.urlparse(address)

# 获取基本的静态值
def get_base_dynamic_values(base_url, http_template):
    dynamic_values = {}
    u = urlparse(base_url)
    dynamic_values['BaseURL'] = base_url
    dynamic_values['RootURL'] = f'{u.scheme}://{u.netloc}'
    dynamic_values['Hostname'] = u.netloc
    dynamic_values['Scheme'] = u.scheme
    dynamic_values['Host'] = u.hostname
    dynamic_values['Port'] = u.port
    dynamic_values['Path'] = '/'.join(u.path.split('/')[0:-1])
    dynamic_values['File'] = u.path.split('/')[-1]
    # DSL: Host != ip
    dynamic_values['IP'] = ''
    try:
        dynamic_values['IP'] = socket.gethostbyname(u.hostname)
    except socket.error:
        pass

    # 获取元数据
    metadata = http_template['info'].get('metadata',{})
    if metadata:
        for k,v in metadata.items():
            dynamic_values[k]=v
            # print(k,':',v)

    # 获取变量
    variables = http_template.get('variables',{})
    if variables:
        for k,v in variables.items():
            dynamic_values[k]=v

    # for k, v in dynamic_values.copy().items():
    #     dynamic_values[k.lower()] = v
    
    return dynamic_values

# 检测文件是否存在且可读
def check_file(filename):
    valid = True

    if filename is None or not os.path.isfile(filename):
        valid = False

    if valid:
        try:
            with open(filename, "rb"):
                pass
        except Exception:
            valid = False

    # if not valid:
    #     raise Exception("unable to read file '%s'" % filename)
    return valid


def getdirsize(dir):
    size = 0
    for root, dirs, files in os.walk(dir):
        size += sum([os.path.getsize(os.path.join(root, name)) for name in files])
    return size

# 清理result文件夹
def clear_dir(directory,minsize):
    import shutil
    # 输入大小大于10MB
    if minsize > 10000:
        while True:
            logger.warning(f'文件过大请谨慎操作 当前阈值为{minsize}KB')
            user_input = input("是否继续: Y/N").lower()
            if user_input == 'y' or user_input == 'yes':
                break
            elif user_input == 'n' or user_input == 'no':
                return

    for project_dir in os.listdir(directory):
        try:
            if getdirsize(os.path.join(directory,project_dir)) < minsize*1000 :
                shutil.rmtree(os.path.join(directory,project_dir))
                logger.info(f"Deleted project folder: {os.path.join(directory,project_dir)}")
        except Exception as e:
            print(e)
            pass

    # # 遍历目录下的所有文件和文件夹
    # for root, dirs, files in os.walk(directory, topdown=False):
    #     # 遍历文件
    #     for file in files:
    #         file_path = os.path.join(root, file)
    #         size = os.path.getsize(file_path)
    #         if os.path.getsize(file_path) <= minsize:  # 检查文件是否小于阈值
    #             try:
    #                 os.remove(file_path)
    #                 logger.info(f"Delete file: {file_path} size {size}")
    #             except:
    #                 pass

    #     # 遍历文件夹
    #     for dir in dirs:
    #         dir_path = os.path.join(root, dir)
    #         if len(os.listdir(dir_path)) == 0:  # 检查文件夹是否为空
    #             try:
    #                 os.rmdir(dir_path)
    #                 logger.info(f"Deleted empty folder: {dir_path}")
    #             except Exception as e:
    #                 pass

'''
函数使用
if __name__ == "__main__":
    json2html('session_test.json','report_template.html','report.html')
'''

def json2html(jsonfile,reportTemplateFile,reportfile):
    with open(jsonfile,'r',encoding='utf-8') as f:
        # 假设这是你的数据字典
        vulnerabilities_data = json.load(f)

    # 将请求响应包进行html编码避免其中携带的html片段影响报告生成
    # print(json.dumps(vulnerabilities_data, indent=4))
    html_vulnerabilities_data = vulnerabilities_data
    for vulnerability, details in vulnerabilities_data.items():
        for target_index,target in enumerate(details["targets"]):
            for req_resp_index,req_resp in enumerate(target["req_resp"]):
                # print(vulnerability," ",target_index," ",req_resp_index)
                html_vulnerabilities_data[vulnerability]["targets"][target_index]["req_resp"][req_resp_index]["req"] = html.escape(req_resp["req"])
                html_vulnerabilities_data[vulnerability]["targets"][target_index]["req_resp"][req_resp_index]["resp"] = html.escape(req_resp["resp"])

    json_data = json.dumps(html_vulnerabilities_data, indent=4)

    # 将替换后的内容写入新的HTML文件
    # with open('test.json', 'w', encoding='utf-8') as file:
    #     file.write(json_data)

    # 读取HTML模板文件
    with open(reportTemplateFile, 'r', encoding='utf-8') as file:
        content = file.read()

    # 替换模板中的{myjson}为实际的JSON数据
    content = content.replace('\'{{myjson}}\'', json_data)

    # 将替换后的内容写入新的HTML文件
    with open(reportfile, 'w', encoding='utf-8') as file:
        file.write(content)
    shutil.copy('share/chart.js',os.path.join(os.path.dirname(reportfile),'chart.js'))
    logger.success(f'[ReportFile] {reportfile}')
    # print(Fore.GREEN+f'[+] 报告生成至{reportfile}'+Fore.RESET)

# 读取文件函数
def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def getip(report_json_file):
    project_dir = os.path.dirname(report_json_file)
    with open(report_json_file,'r',encoding='utf-8') as f:
        report = json.load(f)
    for id in report.keys():
        id_output_file = os.path.join(project_dir,id+'_targets.txt')
        with open(id_output_file,'w',encoding='utf-8') as f:
            for session in report[id]['targets'] :
                f.write(f'{session["target"]}\n')
        logger.success(f'[GetIp] [{id}] {id_output_file}')

def getjson(input_file_path,jsonOutputFile):
    # 从文件中读取内容
    text_block = read_file(input_file_path)
    json_pattern = re.compile(r'\[\+\] (?P<url>https?://[^\s]+)(?::\d+)?\s+is\svulnerable\sto\sVuln.*?\((?P<vulnerability>[^\)]+)\)')
    matches = json_pattern.finditer(text_block)
    # vulnerability = matches[0].group('vulnerability')
    vulnerabilities = {}
    vulnerability = ""
    # if not matches:
    #     print("无匹配结果")
    for match in matches:
        # if match:
        #     print("匹配结果")
        if vulnerabilities :
            url = match.group('url')
            vulnerabilities[vulnerability].append(url)
        else :
            vulnerability = match.group('vulnerability')
            # print('\n\n: vulnerability',vulnerability)
            url = match.group('url')
            vulnerabilities = {vulnerability:[url]}

    # 将字典转换为JSON格式的字符串，indent参数用于美化输出，表示缩进的空格数
    json_string = json.dumps(vulnerabilities, indent=4)
    # 打开文件用于写入（'w' 表示写入模式，如果文件不存在则创建）
    with open(jsonOutputFile, 'w', encoding='utf-8') as file:
        # 写入JSON字符串到文件
        file.write(json_string)
    logger.success(f'共{len(vulnerabilities[vulnerability])}条已写入到文件: {jsonOutputFile}')
    # print(Fore.GREEN+f'[+] 共{len(vulnerabilities[vulnerability])}条已写入到文件: {jsonOutputFile}'+Fore.RESET)

def zip_folder(folder_path, output_zip):
    """
    将文件夹打包成ZIP文件。

    :param folder_path: 要打包的文件夹路径
    :param output_zip: 输出ZIP文件的路径
    """
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file == os.path.basename(output_zip):
                    continue
                # 创建文件夹内的相对路径
                file_path = os.path.join(root, file)
                # 获取文件在ZIP中的存储路径
                zip_path = os.path.relpath(file_path, os.path.dirname(folder_path))
                # 将文件添加到ZIP
                zipf.write(file_path, zip_path)

def send_QQ_email(project_file,sender,passwd,receivers,title="Vulnerability Report"):
    
    output_zip = os.path.join(project_file,'report.zip')
    zip_folder(project_file,output_zip)
    for receiver in receivers:
        # 创建邮件对象
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = receiver
        msg['Subject'] = title

        # 邮件正文
        msg.attach(MIMEText('请查看附件中的ZIP文件。', 'plain', 'utf-8'))

        # 附件部分
        with open(output_zip, 'rb') as attachment_file:
            attachment = MIMEApplication(attachment_file.read(), _subtype='zip')
        attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(output_zip))
        msg.attach(attachment)

        try:
            smtp = smtplib.SMTP_SSL('smtp.qq.com', 465)
            smtp.login(sender, passwd)
            smtp.sendmail(sender, receiver, msg.as_string())
            logger.success(f'[Email] sender:{sender} receiver:{receiver}')
        except Exception as e:
            logger.error(f'[Email] sender:{sender} receiver:{receiver} {str(e)}')

# 将临时文件归并输出到report_json_file
def tmp2report_json(nuclei_result_dir,report_json_file):
    report = {}
    for dir in os.listdir(nuclei_result_dir):
        # print(str(dir),nuclei_result_dir)
        first_flag = True
        result_dir = os.path.join(nuclei_result_dir,str(dir))
        if not os.path.isdir(result_dir):
            continue
        for result_json_filename in os.listdir(result_dir):
            result_json_file = os.path.join(result_dir,result_json_filename)
            with open(result_json_file,'r',encoding='utf-8') as f:
                result = json.load(f)
            if first_flag :
                first_flag = False
                for id in result.keys():
                    report[id] = result[id]
            else :
                for id in result.keys():
                    for target in result[id]['targets']:
                        report[id]['targets'].append(target)
    with open(report_json_file,'w',encoding='utf-8') as f :
        json.dump(report,f,indent=4,ensure_ascii=False)
    logger.success(f"[ResultFile] {report_json_file}")

# 将临时提取文件归并输出到extracts_outputfile
def tmp2extracts_json(nuclei_extracts_dir,extracts_outputfile):
    extracts_results = {}
    for dir in os.listdir(nuclei_extracts_dir):
        # print(str(dir),nuclei_extracts_dir)
        first_flag = True
        result_dir = os.path.join(nuclei_extracts_dir,str(dir))
        if not os.path.isdir(result_dir):
            continue
        for result_json_filename in os.listdir(result_dir):
            result_json_file = os.path.join(result_dir,result_json_filename)
            with open(result_json_file,'r',encoding='utf-8') as f:
                result = json.load(f)
            if first_flag:
                first_flag = False
                id = result['id']
                extracts_results[id] = {}
                for target in result.keys():
                    if target != 'id':
                        extracts_results[id][target] = result[target]
            else:
                for target in result.keys():
                    if target != 'id':
                        extracts_results[id][target] = result[target]

    with open(extracts_outputfile,'w',encoding='utf-8') as f :
        json.dump(extracts_results,f,indent=4,ensure_ascii=False)
    logger.success(f"[ExtractsFile] {extracts_outputfile}")

def banner():
#     print(Fore.LIGHTWHITE_EX+'''
# ╔══════════════════════════════════════════════════════════════════════════════════╗
# ║                                                                                  ║
# ║                          ██████╗     ██╗  ██╗     ██████╗                        ║
# ║                          ██╔══██╗    ██║  ██║    ██╔════╝                        ║
# ║                          ██║  ██║    ███████║    ██║                             ║
# ║                          ██║  ██║    ╚════██║    ██║                             ║
# ║                          ██████╔╝         ██║    ╚██████╗                        ║
# ║                          ╚═════╝          ╚═╝     ╚═════╝                        ║
# ╠══════════════════════════════════════════════════════════════════════════════════╣
# ║                            Dirty Deeps Done Drit Cheap                           ║
# ╚══════════════════════════════════════════════════════════════════════════════════╝
#             '''+Fore.RESET)
    print(Fore.LIGHTWHITE_EX+'''
                                                                                  
                          ██████╗     ██╗  ██╗     ██████╗                        
                          ██╔══██╗    ██║  ██║    ██╔════╝                        
                          ██║  ██║    ███████║    ██║                             
                          ██║  ██║    ╚════██║    ██║                             
                          ██████╔╝         ██║    ╚██████╗                        
                          ╚═════╝          ╚═╝     ╚═════╝                        
                            Dirty Deeps Done Drit Cheap                           
            '''+Fore.RESET)