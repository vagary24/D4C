import yaml
import requests
import warnings
import random
import itertools
import chardet
import config
# from config import proxies,user_agents,defult_Timeout,map_file
from requests.exceptions import Timeout
import threading
from queue import Queue
import json
import os

from lib.update import search_template_from_map,search_template_by_id
from lib.common import *
# from lib.common import marker_replace,http_response_to_dsl_map,UNRESOLVED_VARIABLE,Marker,get_base_dynamic_values,check_file,urlparse,tmp2extracts_json,json2html,getip,tmp2report_json
from lib.Extractors import http_extract
from lib.Matchers import http_match
from lib.process import evaluate
from lib.log import logger

# proxy = None
proxy = config.proxies

user_agent = config.user_agents

warnings.filterwarnings("ignore")

# URL队列，用于存储所有需要请求的URL
url_queue = Queue()

# 锁，用于同步队列操作
queue_lock = threading.Lock()

# 打印锁
print_lock = threading.Lock()

fingerPrinting_write_lock = threading.Lock()

# 将payload存储在dynamic_values中
def get_payloads(dynamic_values,http_request):   
    
    attack = http_request.get('attack','')
    # print('\n',attack,'\n')
    if attack:
        dynamic_values['attack'] = attack
        # dynamic_values['attack'].append(attack)
    
    dynamic_values['payloads'] = http_request.get('payloads',{})
    # print('\n',payloads,'\n')
    # if payloads:
    #     for k,v in payloads.items(): 
    #         dynamic_values[k] = v

    return dynamic_values

# 从文件中获取payload_items
def get_file_items(filename, comment_prefix='#', unicode=True, lowercase=False):
    ret = list()

    check_file(filename)
    
    try:
        with open(filename, 'rb') as f:
            for line in f.readlines():
                line = line.strip()
                if line:
                    # 编码
                    if unicode:
                        encoding = chardet.detect(line)['encoding'] or 'utf-8'
                        line = line.decode(encoding)

                    # 忽略注释行默认注释符'#'
                    if comment_prefix and line.startswith(comment_prefix):
                        continue
                    
                    # 转换成小写
                    if lowercase:
                        line = line.lower()
                    ret.append(line)

    except (IOError, OSError, MemoryError) as ex:
        err_msg = "something went wrong while trying "
        err_msg += "to read the content of file '{0}' ('{1}')".format(filename, ex)
        raise Exception(err_msg)

    return ret

# 生成payload
def payload_generator(payloads: dict, attack_type: str):
    payloads_final = {}
    payloads_final.update(payloads)

    # 如果payload是文件从文件中获取payload
    for k, v in payloads_final.items():
        if isinstance(v, str) and check_file(v):
            payloads_final[k] = get_file_items(v)

    payload_keys, payload_vals = payloads_final.keys(), payloads_final.values()
    payload_vals = [i if isinstance(i, list) else [i] for i in payload_vals]

    # pitchfork鱼叉模式
    if attack_type == "pitchfork":
        for instance in zip(*payload_vals):
            yield dict(zip(payload_keys, instance))
    # 获取payload直接的笛卡尔积
    else:
        for instance in itertools.product(*payload_vals):
            yield dict(zip(payload_keys, instance))

# 请求生成器
def http_request_generator(http_request,dynamic_values):    
    current_index = 0
    for payload_instance in payload_generator(dynamic_values.get('payloads',{}), dynamic_values.get('attack',{})):
        dynamic_values.update(payload_instance)
        # print(dynamic_values)
        method = http_request.get('method', '').upper()
        kwargs = {}
        allow_redirects = http_request.get('redirects',True)

        # base_http
        if method != '':
            paths = http_request.get('path', [])
            headers = http_request.get('headers', {'User-Agent': random.choice(config.user_agents)})
            data = http_request.get('body','')
            if data :
                data = data.strip('\n')
            for path in paths:
                current_index +=1
                kwargs.setdefault('allow_redirects', allow_redirects)
                kwargs.setdefault('data', data)
                kwargs.setdefault('headers', headers)
                try:
                    # 预加载替换
                    # print(f"替换前: \nkwargs:\n\t{kwargs}\npath:{path}")
                    kwargs_final = marker_replace(kwargs,dynamic_values)
                    path = marker_replace(path,dynamic_values)
                    # print(f"替换后: \nkwargs:\n\t{kwargs_final}\npath:{path}")
                except Exception as e:
                    kwargs_final = kwargs
                    pass
                yield (method, path, kwargs_final,current_index,payload_instance)

        # raw_http
        if http_request.get('raw',[]):
            raws = http_request.get('raw',[])
            for raw in raws:
                current_index += 1
                # logger.debug(f"raw: {raw}")
                raw_lines = list(map(lambda x: x.strip(), raw.splitlines()))
                method, path, _ = raw_lines[0].split()
                path = f'{Marker.ParenthesisOpen}BaseURL{Marker.ParenthesisClose}{path}'

                # 解析raw
                # 记录是否有body部分
                body_flag = False
                # POST_raw
                # if method == "POST":
                kwargs = {}
                # index用于记录data前有多少行
                index = 0
                for i in raw_lines:
                    index += 1
                    if i.strip() == "":
                        body_flag = True
                        break

                # 获取headers
                if body_flag:
                    headers = raw_lines[1:index - 1]
                    headers = {header.split(': ', 1)[0]: header.split(': ', 1)[1] for header in headers}
                    data = '\n'.join(raw_lines[index:])
                else:
                    headers = raw_lines[1:index]
                    headers = {header.split(': ', 1)[0]: header.split(': ', 1)[1] for header in headers}
                    data = ''
  
                # # GET_raw
                # else:
                #     headers = raw_lines[1:]
                #     headers = {header.split(': ', 1)[0]: header.split(': ', 1)[1] for header in headers}
                #     data = ''

                logger.debug(f"headers: {headers}")
                if not headers.get('User-Agent',''):
                    headers['User-Agent']=random.choice(config.user_agents)

                # 预加载替换
                kwargs.setdefault('data', data)
                kwargs.setdefault('headers', headers)

                try:
                    # logger.debug(f"替换前: \nkwargs:{kwargs}\npath:{path}")
                    kwargs_final = marker_replace(kwargs,dynamic_values)
                    path = marker_replace(path,dynamic_values)
                    # logger.debug(f"替换后: \nkwargs:\n\t{kwargs_final}\npath:{path}")
                except Exception as e:
                    kwargs_final = kwargs
                    pass
                yield (method, path, kwargs_final,current_index,payload_instance)

    return

# 发送请求/匹配/提取
def execute_http_request(http_request,dynamic_values):
    results = {}
    results['extracts'] = []
    results['matchers'] = []
    resp_data_all = {}
    match_results = []

    result_req_resp = []

    with requests.Session() as session:
        # print('\n\nhttp_request: ',http_request)
        req_conuts = len(http_request.get('path', [])) + len(http_request.get('raw', [])) 
        logger.debug(f"req_conuts: {req_conuts}")
        # if req_conuts > 1:
        #     req_condition = True
        # else:
        #     req_condition = False
        # req_condition = http_request.get("req_condition","and")
        for (method, url,kwargs,current_index,payload) in http_request_generator(http_request,dynamic_values):
            logger.debug(Fore.BLUE+f"Sending {method} request to: "+Fore.RESET+str(url))
            # print((method, url,kwargs))
            # 发送http请求
            session.max_redirects = http_request.get('max-redirects',10)
            try:    
                response = session.request(method=method, proxies=proxy,url=url, timeout=config.defult_Timeout, verify=False, **kwargs)
                # u = urlparse(url)
                # print(url)
                version = "HTTP/{0}.{1}".format(response.raw.version // 10, response.raw.version % 10)  # 然后使用解包的方式格式化字符串
                # 构造出请求/响应包
                req_str='{}\r\n{}\r\n{}\r\n\r\n{}'.format(
                    response.request.method + ' ' + '/'+'/'.join(url.split('/')[3:]) + " " + version,
                    "HOST: "+dynamic_values["Host"],
                    '\r\n'.join('{}: {}'.format(k, v) for k, v in response.request.headers.items()),
                    str(response.request.body) if response.request.body is not None else '',
                )
                resp_str='{}\r\n{}\r\n\r\n{}'.format(
                    version + " " + str(response.status_code),
                    '\r\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
                    str(response.text) if response.text is not None else '',
                )
                # logger.debug(f"Request:\n{req_str}")
                # logger.debug(f"Response:\n{resp_str}")
                
                if response:
                    response.close()

            except Timeout:
                result = {"status":"Error","Type":"Timeout","massage":f"[-] {url} 连接超时Timeout={config.defult_Timeout}"}
                return result
            # 记录连接错误
            except requests.exceptions.ConnectionError as e:
                logger.warning(f'[ConnError] {url}') 
                result = {"status":"Error","Type":"Timeout","massage":f"[-] {url}拒绝连接或者无法连接"} 
                return result
            except requests.exceptions.SSLError:
                # 如果发生SSL错误，可能是因为站点需要HTTPS
                result = {"status":"Error","Type":"HTTPS","massage":f"[-] {url} 需要HTTPS"}
                return result
            except Exception as e:
                logger.warning(f'{url} request failed: {e}')
                # print(f"[-] {url} request failed: {e}")
                result = {"status":"Error","Type":"Other","massage":e}
                return result

            # 数据提取
            resp_data = http_response_to_dsl_map(response)
            extract_result = http_extract(http_request,resp_data)
            # 将internal提取的数据更新dynamic_values
            for k, v in extract_result['internal'].items():
                if v == UNRESOLVED_VARIABLE and k in dynamic_values:
                    continue
                else:
                    dynamic_values[k] = v
            
            # 存在匹配规则时
            if 'matchers' in http_request:
                
                # dsl如果判断条件需要结合多次响应,则需要将响应结果记录编号
                resp_data_all.update(resp_data)
                for k, v in resp_data.items():
                    # logger.debug(str(resp_data_all))
                    resp_data_all[f'{k}_{current_index}'] = v

                match_res_raw = http_match(http_request, resp_data_all)
                match_res = match_res_raw['matchers_result']
                match_results.append(match_res)

                # 记录session
                req_and_resp = {"req":req_str,"resp":resp_str}
                result_req_resp.append(req_and_resp)

                # 如果匹配成功记录matchers和output
                if match_res:
                    for i in match_res_raw['matchers']:
                        results['matchers'].append(i)
                    output = {}
                    if payload or extract_result['extra_info']:
                        output.update(extract_result['external'])
                        output['payload'] = payload
                        output['extra_info'] = extract_result['extra_info']
                        results['extracts'].append(output)
                    if http_request.get('stop_at_first_match',False):
                        results['session'] = result_req_resp
                        logger.debug(f'match_results: {str(match_results)}')
                        return results
            # 无匹配时
            else :
                output = {}
                if payload or extract_result['extra_info']:
                    output.update(extract_result['external'])
                    output['payload'] = payload
                    output['extra_info'] = extract_result['extra_info']
                    results['extracts'].append(output)

    results['match'] = any(match_results)
    results['session'] = result_req_resp
    logger.debug(f'match_results: {str(match_results)}')
    # logger.debug(f"results:\n{str(results)}")
    return results

# 用于发送请求并检测漏洞
def send_request_and_check_vulnerability(http_template, base_url, use_proxy=False):
    results = {}
    results['extracts'] = []
    result_session = {}
    result_session['target'] = base_url
    result_session['req_resp'] = []

    if not use_proxy:
        global proxy
        proxy = None
    # print('\n\n代理：',proxy)
    # print('base_url: ',base_url)
    # 获取基本静态值包括变量variables
    # print(http_template)
    dynamic_base_values=get_base_dynamic_values(base_url,http_template)
    # print('\n\ndynamic_base_values: ',dynamic_base_values)
    # 发送http请求并匹配结果
    matchs = []
    for http_request in http_template.get("http",[]):
        method = http_request.get('method', '').upper()
        # print('\n\nhttp_request: ',http_request)
        # 获取payloads
        if 'payloads' in http_request or 'attack' in http_request:
            dynamic_values = get_payloads(dynamic_base_values,http_request)
        else :
            dynamic_values = dynamic_base_values
        result = execute_http_request(http_request,dynamic_values)

        # 检测是否出现报错状态
        if 'status' in result:
            status = result.get('status','')
            Type = result.get('Type','')
            massage = result.get('massage','')
            # HTTP请求错误转为HTTPS请求
            if status == 'Error' :
                if Type == 'HTTPS':
                    dynamic_values['BaseURL'] = dynamic_values['BaseURL'].replace('http://', 'https://')
                    dynamic_values['RootURL'] = dynamic_values['RootURL'].replace('http://', 'https://')
                    dynamic_values['Scheme'] = dynamic_values['Scheme'].replace('http', 'https')
                    # print(dynamic_values)
                    print(massage)
                    # print(f'[-] {base_url}HTTP请求错误转为HTTPS请求')
                    result = execute_http_request(http_request,dynamic_values)
                elif Type == 'Timeout':
                    # print(massage)
                    return
                else :
                    # print(massage)
                    return
        if result:
            # print(result)
            # yield result
            if result.get('match'):
                for i in result['session']:
                    result_session['req_resp'].append(i)
            # print('\n\nresult: ',result)
            if 'match' in result:
                matchs.append(result.get('match'))
            if 'extracts' in result and result.get('extracts'):
                for i in result.get('extracts',[]):
                    results['extracts'].append(i)
    logger.debug(Fore.BLUE+f"Is vulnerable : {str(any(matchs))}"+Fore.RESET)
    if any(matchs) and matchs:
        # print("\n\nVulnerable",result_session)
        results['session'] = result_session
        # logger.debug(str(result))
        return results
    else:
        return

# nuclei模板线程
def nuclei_thread(project_dir,template,use_proxy = False):
    global session_first_write
    global extracts_first_write
    report_json_dir = os.path.join(os.path.join(os.path.join(project_dir,"tmp"),"nuclei_result"),template['id'])
    extracts_json_dir = os.path.join(os.path.join(os.path.join(project_dir,"tmp"),"nuclei_extracts"),template['id'])

    try:
        if not os.path.exists(report_json_dir):
            os.mkdir(report_json_dir)
        if not os.path.exists(extracts_json_dir):
            os.mkdir(extracts_json_dir)
    except Exception as e:
        pass
    
    while True :
        # 使用锁来确保队列安全
        with queue_lock:
            if url_queue.empty():
                break  # 如果队列为空，退出循环
            target = url_queue.get()

        # 检查漏洞
        result = send_request_and_check_vulnerability(template, target, use_proxy)
        if result :
            report_json = {}
            report_json [template['id']] = {}
            report_json [template['id']]['info'] = template['info']
            report_json [template['id']]['targets'] = []
            report_json [template['id']]['targets'].append(result['session'])
            with print_lock:
                logger.success(f"[Vuln] "+Fore.RED+f"[{template['info']['name']}]"+Fore.RESET+f" {target}")
            # 写入扫描结果
            report_json_file = os.path.join(report_json_dir,target.split("://")[1].replace(":","_")+".json")
            logger.debug(f"临时输出到: {report_json_file}")
            # 写session
            with open(report_json_file,'w',encoding='utf-8') as f:
                json.dump(report_json,f,indent=4,ensure_ascii=False)

            # 写提取的信息
            if result['extracts']:
                extracts_outputfile_file = os.path.join(extracts_json_dir,target.split("://")[1].replace(":","_")+".json")
                # print(result['extracts'])
                info_extract = {}
                info_extract[target] = result['extracts']
                info_extract['id'] = template['id']
                with open(extracts_outputfile_file,'w',encoding='utf-8') as f:
                    json.dump(info_extract,f,ensure_ascii=False,indent=4)
        else:
            with print_lock:
                logger.info(f"   [Vuln] [NONE] {target}")

def nuclei_run_threadings(template_list=[],in_url='',in_file='',project_file='',THREAD_POOL_SIZE=5,use_proxy = False,save_tmpfile=False,output_target=False,output_html_report = False,output_result_json = True,output_extracts = True):
    # 确定是单目标还是多目标
    if in_url:
        urls = [in_url]
    elif in_file:
        logger.info(f'   [LoadUrls] {in_file}')
        with open(in_file, 'r') as f:
            urls = [line.strip() for line in f]
    else:
        return False
    
    if not os.path.exists(project_file):
        return False
    if not os.path.exists(os.path.join(project_file,'tmp')):
        os.mkdir(os.path.join(project_file,'tmp'))
    nuclei_result_dir = os.path.join(os.path.join(os.path.join(project_file,'tmp'),'nuclei_result'))
    nuclei_extracts_dir = os.path.join(os.path.join(os.path.join(project_file,'tmp'),'nuclei_extracts'))

    if not os.path.exists(nuclei_result_dir):
        os.mkdir(nuclei_result_dir)
    if not os.path.exists(nuclei_extracts_dir):
        os.mkdir(nuclei_extracts_dir)
    
    extracts_outputfile = os.path.join(project_file,'VulnScan_extracts.json')
    report_json_file = os.path.join(project_file,'VulnScan_report.json')
    report_file = os.path.join(project_file,'VulnScan_report.html')

    if output_html_report:
        logger.info(f"   [ReportFile] {report_file}")
    if output_result_json:
        logger.info(f"   [ResultFile] {report_json_file}")
    if output_extracts:
        logger.info(f"   [ExtractsFile] {extracts_outputfile}")

    

    for template_id in template_list:
        if os.path.exists(template_id):
            template = template_id
        else:
            template = search_template_by_id(config.map_file,template_id)
            # print(template)
            if not template:
                logger.error(f"不存在模板{template}")
                continue
            if not os.path.exists(template):
                logger.error(f"不存在模板{template}")
                continue
        # if not url_queue.empty:
        #     url_queue.clear()
        for url in urls:
            # 转换url并生成url队列用于多线程扫描
            if not url.startswith('https://') and not url.startswith('http://'):
                url = r'http://' + url
            else:
                url = url
            url_queue.put(url)

        # 读取并解析 YAML 模板文件
        with open(template, 'r', encoding='utf-8') as file:
            nuclei_template = yaml.safe_load(file)
        # print(nuclei_template)
        if "{{interactsh-url}}" in str(nuclei_template):
            logger.error(f"  [{nuclei_template['id']}] "+"暂不支持{{interactsh-url}}")
            continue

        # logger.debug(f'nuclei_template: \n{json.dumps(nuclei_template,indent=4)}')
        id = nuclei_template['id']
        logger.success(f'[{id}] 探测开始')
        # 创建并启动线程池
        threads = []
        for i in range(THREAD_POOL_SIZE):
            # thread = threading.Thread(target=nuclei_thread,args=(outputfile,extracts_outputfile,report_json_file,nuclei_template,args.proxy))
            thread = threading.Thread(target=nuclei_thread,args=(project_file,nuclei_template,use_proxy))
            thread.start()
            threads.append(thread)

        # 等待所有线程完成
        for thread in threads:
            thread.join()

    # 将临时文件归并输出到report_json_file
    if output_result_json and not os.path.exists(report_json_file):
        tmp2report_json(nuclei_result_dir,report_json_file)

    # 生成html报告
    if output_html_report :
        # 将临时文件归并输出到report_json_file
        if not os.path.exists(report_json_file):
            tmp2report_json(nuclei_result_dir,report_json_file)
        json2html(report_json_file,'share/report_template.html',report_file)

    # 归并提取数据到extracts_outputfile
    if output_extracts:
        tmp2extracts_json(nuclei_extracts_dir,extracts_outputfile)

    # 从report_json_file提取目标IP
    if output_target:
        if not os.path.exists(report_json_file):
            tmp2report_json(nuclei_result_dir,report_json_file)
        getip(report_json_file)

    # 删除临时文件
    if not save_tmpfile:
        from shutil import rmtree
        rmtree(os.path.join(os.path.join(project_file,'tmp')))
    return True

def fingerPrinting_threading(fingerPrint_template):
    global fingerPrinting_urls
    global fingerPrint_result
    while not fingerPrinting_urls.empty():
        with queue_lock:
            base_url = fingerPrinting_urls.get()
        dynamic_base_values=get_base_dynamic_values(base_url,fingerPrint_template)
        for http_request in fingerPrint_template.get("http",[]):
            # 获取payloads
            if 'payloads' in http_request or 'attack' in http_request:
                dynamic_values = get_payloads(dynamic_base_values,http_request)
            else :
                dynamic_values = dynamic_base_values
            result = execute_http_request(http_request,dynamic_values)
            # logger.debug(f'fingerPrinting->http_request->result(execute_http_request):{str(result)}')
            # 检测是否出现报错状态
            if 'status' in result:
                status = result.get('status','')
                Type = result.get('Type','')
                massage = result.get('massage','')
                # HTTP请求错误转为HTTPS请求
                if status == 'Error' :
                    if Type == 'HTTPS':
                        dynamic_values['BaseURL'] = dynamic_values['BaseURL'].replace('http://', 'https://')
                        dynamic_values['RootURL'] = dynamic_values['RootURL'].replace('http://', 'https://')
                        dynamic_values['Scheme'] = dynamic_values['Scheme'].replace('http', 'https')
                        # print(dynamic_values)
                        logger.debug(str(massage))
                        # print(f'[-] {base_url}HTTP请求错误转为HTTPS请求')
                        result = execute_http_request(http_request,dynamic_values)
                    elif Type == 'Timeout':
                        continue
                    else :
                        continue
            if result.get('matchers',[]):
                with fingerPrinting_write_lock :
                    name = result['matchers'][0].get('name','')
                    if name not in fingerPrint_result.keys():
                        fingerPrint_result[name] = []
                    fingerPrint_result[name].append(base_url)
                    # final_result = {'base_url':base_url,'match':result['match'],'name':name}
                    logger.info(Fore.LIGHTGREEN_EX+f"   [FingerPrinting] "+Fore.RESET+Fore.RED+f"[{name}]"+Fore.RESET+f" {base_url}")
            else:
                logger.info(f"   [FingerPrinting] [NONE] {base_url}")

# 指纹识别
def fingerPrinting(fingerPrint_template_dir, in_file, THREAD_POOL_SIZE=5):
    logger.debug(f"fingerPrinting:{fingerPrint_template_dir}")
    with open(fingerPrint_template_dir,'r',encoding='utf-8') as f:
        fingerPrint_template = yaml.safe_load(f)
    global fingerPrint_result
    fingerPrint_result = {}
    # 载入url
    global fingerPrinting_urls
    fingerPrinting_urls = Queue()
    with open(in_file,'r',encoding='utf-8') as f:
        for line in f:
            if line :
                url = line.strip()
            if not url.startswith('https://') and not url.startswith('http://'):
                url = r'http://' + url
            else:
                url = url
            fingerPrinting_urls.put(url)
    
    threads = []
    for i in range(THREAD_POOL_SIZE):  # 假设我们想要创建5个线程
        thread = threading.Thread(target=fingerPrinting_threading, args=(fingerPrint_template,))
        threads.append(thread)
        thread.start()
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()

    return fingerPrint_result

# 工作流实现
def workflow(workflow_template,in_file='', project_file='', THREAD_POOL_SIZE=5, use_proxy = False, save_tmpfile=False, output_target=False, output_html_report = False):
    if not use_proxy:
        global proxy
        proxy = None
    for workflow in workflow_template.get("workflows",[]):
        logger.debug(f'Nuclei.workflow workflow_template{str(workflow_template["id"])}')
        fp_results = fingerPrinting(workflow['template'], in_file, THREAD_POOL_SIZE)
        # logger.debug(str(fp_results))
        # exit()
        # 保存指纹识别结果
        if not os.path.exists(os.path.join(project_file,'tmp')):
            os.mkdir(os.path.join(project_file,'tmp'))
        for fp_tag,urls in fp_results.items():
            for matcher in workflow.get('matchers',{}):
                if not matcher:
                    logger.error('workflow模板格式,并将指纹添加进.\template\fingerprinthub-web-fingerprints.yaml')
                matcher_name = matcher.get('name','')
                if not matcher_name :
                    continue
                if fp_tag == matcher['name']:
                    fingerPrinting_output_file = os.path.join(os.path.join(project_file,'tmp'),'fp_'+fp_tag+'.txt')
                    with open(fingerPrinting_output_file,'w',encoding='utf-8') as f:
                        for url in urls :
                            f.write(url+'\n')
                    for subtemplate in matcher['subtemplates']:
                        template_list = search_template_from_map(config.map_file,subtemplate['tags'])
                        logger.info(f"Run Nuclei by tag {subtemplate['tags']} on {fingerPrinting_output_file}")
                        print(template_list)
                        nuclei_run_result = nuclei_run_threadings(template_list,'',fingerPrinting_output_file,project_file,THREAD_POOL_SIZE,
                                              use_proxy,save_tmpfile,output_target,output_html_report)
                        if not nuclei_run_result:
                            logger.error(f'nuclei_run_result:{nuclei_run_result}')

# 自动扫描
def AutoScan(fingerPrint_file,in_file='', project_file='', THREAD_POOL_SIZE=5, use_proxy = False, save_tmpfile=False, output_target=False, output_html_report = False):
    if not use_proxy:
        global proxy
        proxy = None
        logger.debug(f'AutoScan Starting fingerPrinting file {fingerPrint_file}')
        fp_results = fingerPrinting(fingerPrint_file, in_file, THREAD_POOL_SIZE)
        # 保存指纹识别结果
        if not os.path.exists(os.path.join(project_file,'tmp')):
            os.mkdir(os.path.join(project_file,'tmp'))

        index = 0
        for fp_tag,urls in fp_results.items():
            index += 1
            logger.info(Fore.LIGHTRED_EX+f"   [{fp_tag}]"+Fore.RESET + " Searching Tempalte")
            fingerPrinting_output_file = os.path.join(os.path.join(project_file,'tmp'),'fp_'+fp_tag+'.txt')
            with open(fingerPrinting_output_file,'w',encoding='utf-8') as f:
                for url in urls :
                    f.write(url+'\n')
            template_list = search_template_from_map(config.map_file,fp_tag)
            # 前几次扫描不不处理结果最后一次统一处理
            if index == len(fp_results):
                nuclei_run_result = nuclei_run_threadings(template_list,'',fingerPrinting_output_file,project_file,THREAD_POOL_SIZE,
                                        use_proxy,save_tmpfile,output_target,output_html_report)
            else:
                nuclei_run_result = nuclei_run_threadings(template_list,'',fingerPrinting_output_file,project_file,THREAD_POOL_SIZE,use_proxy,
                                        save_tmpfile = True,output_target = False,output_html_report = False,output_result_json = False,output_extracts=False)
            if not nuclei_run_result:
                logger.error(f'nuclei_run_result:{nuclei_run_result}')
                
        # for result in results:
        #     if result['match']:
        #         matchers = workflow.get('matchers',{})
        #         if matchers:
        #             for matcher in matchers:
        #                 if result['name'] == matcher['name']:
        #                     logger.success(f"指纹匹配{result['base_url']} <--> {matcher['name']}")
        #                     for subtemplate in matcher['subtemplates']:
        #                         logger.info(f"Run Nuclei by tag {subtemplate['tags']} on {result['base_url']}")
        #                 else:
        #                     logger.info(f"指纹不匹配{result['base_url']}[{result['name']}] <--> {result['name']}")
        #         elif workflow.get('subtemplates',{}):
        #             subtemplates = workflow.get('subtemplates',{})
        #             for subtemplate in subtemplates:
        #                 logger.info(f"Run Nuclei by tag {subtemplate['tags']} on {result['base_url']}")
                    # template_list = search_template_from_map(config.map_file,subtemplate['tags'])
                    # nuclei_run_threadings(template_list,'',in_file,project_file,THREAD_POOL_SIZE,use_proxy,save_tmpfile,output_target,output_html_report)   

if __name__ == "__main__":
    # 您的 YAML 模板文件路径
    yaml_file_path = 'F:\\桌面\\CTF\\工具包\\2024HW漏洞\\2024HWPOC_SCAN-main - 副本\\nacos_login.yaml'
    # 读取并解析 YAML 模板文件
    with open(yaml_file_path, 'r', encoding='utf-8') as file:
        nuclei_template = yaml.safe_load(file)

    # 目标 URL 基础路径
    base_url = 'http://10.10.10.1:8848'  # 替换为您要测试的目标 URL
    # 检查漏洞
    matchs = []
    for r in send_request_and_check_vulnerability(nuclei_template, base_url):
        if 'match' in r:
            matchs.append(r.get('match'))
        if 'extracts':
            print('正在写入文件')
    print(matchs)
    if all(matchs):
        print("A potential vulnerability was detected.")
    else:
        print("No vulnerabilities were detected.")
        