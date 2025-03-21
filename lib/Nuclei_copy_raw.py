import yaml
import requests
import warnings
import re
import random
from ipaddress import ip_address, ip_network
import urllib
import socket
import json
import itertools
import os
import chardet
import binascii
from lxml import etree
from config import proxies,user_agents
proxy = proxies

warnings.filterwarnings("ignore")

UNRESOLVED_VARIABLE = '---UNRESOLVED-VARIABLE---'

user_agent = user_agents

class Marker:
    # General marker (open/close)
    General = "§"
    # ParenthesisOpen marker - begin of a placeholder
    ParenthesisOpen = "{{"
    # ParenthesisClose marker - end of a placeholder
    ParenthesisClose = "}}"

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


# 获取payload
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

    if not valid:
        raise Exception("unable to read file '%s'" % filename)
    return valid

# 从文件中获取items
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
def payload_generator(payloads: dict, attack_type: str) -> dict:
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

# 匹配状态码
def match_status_code(matcher: dict, status_code: int):
    """Matches a status code check against a corpus
    """
    return status_code in matcher.get('status',[])

# 匹配大小
def match_size(matcher: dict, length: int):
    """Matches a size check against a corpus
    """
    return length in matcher.get('size',[])

# 匹配字符
def match_words(matcher: dict, corpus: str, data: dict):
    """Matches a word check against a corpus
    """
    corpus = str(corpus)
    if matcher.get('case_insensitive',False):
        corpus = corpus.lower()

    matched_words = []
    for i, word in enumerate(matcher.get('words',[])):
        # 内置函数待实现
        # word = evaluate(word, data)
        if matcher.get('encoding','') == 'hex':
            try:
                word = binascii.unhexlify(word).decode()
            except (ValueError, UnicodeDecodeError):
                pass
        if matcher.get('case_insensitive',False):
            word = word.lower()

        if word not in corpus:
            if matcher.get('condition','or') == 'and':
                return False, []
            elif matcher.get('condition','or') == 'or':
                continue

        if matcher.get('condition','or') == 'or' and not matcher.get('match_all',False):
            return True, [word]

        matched_words.append(word)

        # 全部匹配完
        if len(matcher.get('words',[])) - 1 == i and not matcher.get('match_all',False):
            return True, matched_words

    if len(matched_words) > 0 and matcher.get('match_all',False):
        return True, matched_words

    return False, []

# 正则匹配
def match_regex(matcher: dict, corpus: str):
    """Matches a regex check against a corpus
    """
    corpus = str(corpus)
    matched_regexes = []
    for i, regex in enumerate(matcher.get('regex',[])):
        if not re.search(regex, corpus):
            if matcher.get('condition','or') == 'and':
                return False, []
            elif matcher.get('condition','or') == 'or':
                continue

        current_matches = re.findall(regex, corpus)
        if matcher.get('condition','or') == 'or' and not matcher.get('match_all',False):
            return True, matched_regexes

        matched_regexes = matched_regexes + current_matches
        if len(matcher.get('regex',[])) - 1 == i and not matcher.get('match_all',False):
            return True, matched_regexes

    if len(matched_regexes) > 0 and matcher.get('match_all',False):
        return True, matched_regexes

    return False, []

# 匹配过程
def http_match(request: dict, resp_data: dict, interactsh=None):
    matchers = request.get('matchers',[])
    matchers_result = []

    # if 'interactsh_' in str(matchers) and isinstance(interactsh, InteractshClient):
    #     interactsh.poll()
    #     resp_data['interactsh_protocol'] = '\n'.join(interactsh.interactsh_protocol)
    #     resp_data['interactsh_request'] = '\n'.join(interactsh.interactsh_request)
    #     resp_data['interactsh_response'] = '\n'.join(interactsh.interactsh_response)
    # else:
    #     resp_data['interactsh_protocol'] = ''
    #     resp_data['interactsh_request'] = ''
    #     resp_data['interactsh_response'] = ''

    for i, matcher in enumerate(matchers):
        matcher_res = False
        item = http_get_match_part(matcher.get('part',''), resp_data, matcher.get('type','') == matcher['type'])
        # print('\n\nMatch: ',matcher['type'])
        # print('\n\nitem: ',item)
        # print('\n\nresp_data: ',resp_data)
        if matcher['type'] == 'status':
            matcher_res = match_status_code(matcher, resp_data.get('status_code', 0))

        elif matcher['type'] == 'size':
            matcher_res = match_size(matcher, len(item))

        elif matcher['type'] == 'word':
            matcher_res, _ = match_words(matcher, item, resp_data)

        elif matcher['type'] == 'regex':
            matcher_res, _ = match_regex(matcher, item)
        # print(matcher_res)
        # elif matcher.get('type','') == MatcherType.BinaryMatcher:
        #     matcher_res, _ = match_binary(matcher, item)

        # elif matcher.get('type','') == MatcherType.DSLMatcher:
        #     matcher_res = match_dsl(matcher, resp_data)

        if matcher.get('negative',False):
            matcher_res = not matcher_res
        
        if not matcher_res:
            # print(request.get('matchers-condition'))
            if request.get('matchers-condition') == 'and':
                return False
            elif request.get('matchers-condition') == 'or':
                continue

        # 匹配成功并且matchers-condition是or
        if request.get('matchers-condition') == 'or':
            return True

        matchers_result.append(matcher_res)

        if len(matchers) - 1 == i:
            return True

    return False

# 匹配过程封装成函数
'''
def Match_results(matchers,response,matchers_condition):
    matchs_results = []  # 用于存储每个matcher的匹配结果
    for matcher in matchers:
        print(matcher)
        match_found = [] # 用于存储matcher中每个并列项的匹配结果
        match_text = ""
        if matcher.get('part','') == 'body':
            match_text = response.text
        elif  matcher.get('part','') == 'header':
            match_text = str(response.headers)

        # 字符匹配
        if matcher['type'] == 'word':
            for word in matcher.get('words', []):
                if word in match_text:
                    match_found.append(True)
        # 正则匹配
        elif matcher['type'] == 'regex':
            for regex in matcher.get('regex', []):
                if re.search(regex, response.text):
                    match_found.append(True)
        # 匹配状态码
        elif matcher['type'] == 'status':
            if response.status_code in matcher.get('status', []):
                match_found.append(True)
        # 匹配大小
        elif matcher['type'] == 'size':
            if response.headers.get('Content-Length', None) == matcher.get('size', 0):
                match_found.append(True)
    
        print(f"match_found:{match_found}")
        # 根据matcher内的condition判断是否满足条件
        if matcher.get('condition', 'or') == 'and':
            if all(match_found):
                matchs_results.append(True)
            else:
                matchs_results.append(False)
        elif matcher.get('condition', 'or') == 'or':
            if any(match_found):
                matchs_results.append(True)
            else:
                matchs_results.append(False)

    print(f"matchs_results:{matchs_results}")
    # 根据matchers间的matchers-condition判断最终结果
    if matchers_condition == 'and':
        if all(matchs_results):
            print("Vulnerability found: All matchers conditions met.")
            return True
        else :
            return False
    elif matchers_condition == 'or':
        print("or")
        if any(matchs_results):
            print("Vulnerability found: At least one matcher condition met.")
            return True
        else :
            return False
'''

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
    # data = evaluate(data, dynamic_values)

    if UNRESOLVED_VARIABLE in data:
        raise Exception

    return json.loads(data)

# 请求生成器
def http_request_generator(http_request,dynamic_values):
    # print(dynamic_values)
    method = http_request.get('method', '').upper()
    kwargs = {}
    current_index = 0
    # base_request
    # print('method:',method)
    allow_redirects = http_request.get('redirects',True)

    # base_http
    if method != '':
        paths = http_request.get('path', [])
        headers = http_request.get('headers', {'User-Agent': random.choice(user_agents)})
        data = http_request.get('body','')

    # raw_http
    else :
        raw = http_request.get("raw")[0]
        # print(raw)
        raws = list(map(lambda x: x.strip(), raw.splitlines()))
        method, path, _ = raws[0].split()
        paths = [f'{Marker.ParenthesisOpen}BaseURL{Marker.ParenthesisClose}{path}']
        # print(paths)
        # POST_raw
        if method == "POST":
            kwargs = {}
            # index用于记录data前有多少行
            index = 0
            for i in raws:
                index += 1
                if i.strip() == "":
                    break
            if len(raws) == index:
                raise Exception

            # 获取headers
            headers = raws[1:index - 1]
            headers = {header.split(': ', 1)[0]: header.split(': ', 1)[1] for header in headers}
            # headers = extract_dict('\n'.join(headers), '\n', ": ")
            # 获取data
            data = '\n'.join(raws[index:])
            # print(headers)
            # print(data)
        # GET_raw
        else:
            headers = raws[1:]
            headers = {header.split(': ', 1)[0]: header.split(': ', 1)[1] for header in headers}
            data = ''

    for payload_instance in payload_generator(dynamic_values.get('payloads',{}), dynamic_values.get('attack',{})):
        dynamic_values.update(payload_instance)
        # print(dynamic_values)
        for path in paths:
            current_index +=1
            # path = path.replace('{{BaseURL}}', base_url)
            kwargs.setdefault('allow_redirects', allow_redirects)
            kwargs.setdefault('data', data)
            kwargs.setdefault('headers', headers)
            try:
                # print(f"替换前: \nkwargs:\n\t{kwargs}\npath:{path}")
                kwargs_final = marker_replace(kwargs,dynamic_values)
                path = marker_replace(path,dynamic_values)
                # print(f"替换后: \nkwargs:\n\t{kwargs_final}\npath:{path}")
            except Exception as e:
                print("替换时错误:",e)
                pass
            yield (method, path, kwargs_final,current_index,payload_instance)

    return

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

# 正则提取器
def extract_regex(e: dict, corpus: str) -> dict:
    """Extract data from response based on a Regular Expression.
    """
    results = {'internal': {}, 'external': {}, 'extra_info': []}

    if e.get('internal',False) and e.get('name',''):
        results['internal'][e.get('name','')] = UNRESOLVED_VARIABLE

    for regex in e.get('regex',[]):
        # print('\n\n',regex)
        matches = re.search(regex, corpus)
        if not matches:
            continue

        lastindex = matches.lastindex

        group = e.get('group',1) if lastindex and lastindex >= e.get('group',1) else 0
        res = matches.group(group)
        if not res:
            continue

        if e.get('name',''):
            if e.get('internal',False):
                results['internal'][e.get('name','')] = res
                # return results
            if e.get('external',False):
                # 如果没有建立列表则建立列表存储提取值
                if not results['external'].get(e.get('name','')):
                    results['external'][e.get('name','')] = []
                results['external'][e.get('name','')].append(res)
        else:
            results['extra_info'].append(res)
        # print
    return results

# kval 提取器
def extract_kval(e: dict, headers: dict) -> dict:
    """Extract key: value/key=value formatted data from Response Header/Cookie
    """
    if not isinstance(headers, dict):
        headers = dict(headers)

    results = {'internal': {}, 'external': {}, 'extra_info': []}

    if e.get('internal',False) and e.get('name',''):
        results['internal'][e.get('name','')] = UNRESOLVED_VARIABLE

    for k in e.get('kval',[]):
        
        res = ''
        if k in headers:
            res = headers[k]
        # kval extractor does not accept dash (-) as input and must be substituted with underscore (_)
        elif k.replace('_', '-') in headers:
            res = headers[k.replace('_', '-')]
        if not res:
            continue

        if e.get('name',''):
            if e.get('internal',False):
                results['internal'][e.get('name','')] = res
                # return results
            if e.get('external',False):
                # 如果没有建立列表则建立列表存储提取值
                if not results['external'].get(e.get('name','')):
                    results['external'][e.get('name','')] = []
                results['external'][e.get('name','')].append(res)
            # print('\n\nkval: ',k,':',res)
        else:
            results['extra_info'].append(res)

    return results

# Xpath 提取器
def extract_xpath(e: dict, corpus: str) -> dict:
    """A xpath extractor example to extract value of href attribute from HTML response
    """
    results = {'internal': {}, 'external': {}, 'extra_info': []}

    if e.get('internal',False) and e.get('name',''):
        results['internal'][e.get('name','')] = UNRESOLVED_VARIABLE

    # print(corpus)

    if corpus.startswith('<?xml'):
        doc = etree.XML(corpus)
    else:
        doc = etree.HTML(corpus)

    if not doc:
        return results

    for x in e.get('xpath',[]):
        # print(x)
        nodes = doc.xpath(x)
        # print(nodes)
        for n in nodes:
            res = ''
            if e.get('attribute',''):
                res = n.attrib[e.get('attribute','')]
            else:
                res = n.txt
            # print(res)
            if not res:
                continue
            
            # print(e.get('name',''))
            if e.get('name',''):
                if e.get('internal',False):
                    results['internal'][e.get('name','')] = res
                    # return results
                # print(e.get('external',False))
                if e.get('external',False):
                    # 如果没有建立列表则建立列表存储提取值
                    if not results['external'].get(e.get('name','')):
                        results['external'][e.get('name','')] = []
                    results['external'][e.get('name','')].append(res)
            else:
                results['extra_info'].append(res)
    return results

# JSON 提取器
def extract_json(e: dict, corpus: str) -> dict:
    """Extract data from JSON based response in JQ like syntax
    """
    results = {'internal': {}, 'external': {}, 'extra_info': []}

    if e.get('internal',False) and e.get('name',''):
        results['internal'][e.get('name','')] = UNRESOLVED_VARIABLE

    try:
        corpus = json.loads(corpus)
    except json.JSONDecodeError:
        return results
    print(corpus)
    try:
        import jq
    except ImportError:
        print('[-] json 提取器错误 Python bindings for jq not installed, it only supports linux and macos, https://pypi.org/project/jq/')
        return results

    for j in e.get('json',[]):
        try:
            res = jq.compile(j).input(corpus).all()
        except ValueError:
            continue
        if not res:
            continue

        if e.get('name',''):
            if e.get('internal',False):
                results['internal'][e.get('name','')] = res
                # return results
            if e.get('external',False):
                # 如果没有建立列表则建立列表存储提取值
                if not results['external'].get(e.get('name','')):
                    results['external'][e.get('name','')] = []
                results['external'][e.get('name','')].append(res)
        else:
            results['extra_info'].append(res)
    return results

# 提取http响应包中的特定数据
def http_extract(http_request: dict, resp_data: dict):
    extractors = http_request.get('extractors',[])
    # print(extractors)
    extractors_result = {'internal': {}, 'external': {}, 'extra_info': []}
    # print(resp_data)
    # print('\n\nkval_extractor_dict: ',resp_data.get('kval_extractor_dict', {}))
    for extractor in extractors:
        item = http_get_match_part(extractor.get('part','body'), resp_data)
        # print('\nitem:',item)
        res = None
        type = extractor.get('type','')
        # print('\n\n',type)
        # 正则提取器
        if type == 'regex':
            res = extract_regex(extractor, item)
            # print('\n\nres: ',res)
        # kval提取器提取response中键值对类型的数据如Header/Cookie
        elif type == 'kval':
            res = extract_kval(extractor, resp_data.get('kval_extractor_dict', {}))
        elif type == 'xpath':
            res = extract_xpath(extractor, item)
        elif type == 'json':
            res = extract_json(extractor, item)
    #     elif type == 'dsl':
    #         res = extract_dsl(extractor, resp_data)
        else:
            print(f"[-] 错误类型提取器 {type}")

    #     logger.debug(f'[+] {extractor} -> {res}')
        extractors_result['internal'].update(res['internal'])
        extractors_result['external'].update(res['external'])
        extractors_result['extra_info'] += res['extra_info']
    # print('\n\nextractors_result: ',extractors_result)
    return extractors_result

# 发送请求/匹配/提取
def execute_http_request(http_request,dynamic_values):
    results = {}
    results['extracts'] = []
    resp_data_all = {}
    match_results = []
    with requests.Session() as session:
        
        for (method, url,kwargs,current_index,payload) in http_request_generator(http_request,dynamic_values):
            print(f"Sending {method} request to: {url}")
            # print((method, url,kwargs))
            session.max_redirects = http_request.get('max-redirects',3)
            try:    
                response = session.request(method=method, url=url, timeout=10, verify=False, **kwargs)
                print(response)
            except Exception as e:
                print(e)
            if response:
                response.close()

            # 数据提取
            resp_data = http_response_to_dsl_map(response)
            extract_result = http_extract(http_request,resp_data)
            # 将internal提取的数据更新dynamic_values
            for k, v in extract_result['internal'].items():
                if v == UNRESOLVED_VARIABLE and k in dynamic_values:
                    continue
                else:
                    dynamic_values[k] = v
            
            # 存在匹配时
            if 'matchers' in http_request:
                if http_request.get('matchers-condition','or') == 'and':
                    # 如果判断条件需要结合多次响应,则需要将响应结果记录编号
                    resp_data_all.update(resp_data)
                    for k, v in resp_data.items():
                        resp_data_all[f'{k}_{current_index}'] = v
                match_res = http_match(http_request, resp_data)
                if  match_res:
                    match_results.append(match_res)
                    output = {}
                    output.update(extract_result['external'])
                    output['payload'] = payload
                    output['extra_info'] = extract_result['extra_info']
                    results['extracts'].append(output)
                    # print('\n\noutput: ',output)
                    # print('\n\nmatch_results: ',match_results)
                    if http_request.get('stop_at_first_match',False):
                        return results
            # 无匹配时
            else :
                output = {}
                output.update(extract_result['external'])
                output['payload'] = payload
                output['extra_info'] = extract_result['extra_info']
                results['extracts'].append(output)
                # print('\n\noutput: ',output)
                # print('\n\nmatch_results: ',match_results)
        if 'matchers' in http_request:
            # 最终结果判断matchers-condition
            if http_request.get('matchers-condition','or') == 'and':
                results['match'] = all(match_results)
            else:
                results['match'] = any(match_results)
    # results.append('hello')
    return results

def send_request_and_check_vulnerability(http_template, base_url):
    
    # 获取基本静态值包括变量variables
    # print(http_template)
    dynamic_base_values=get_base_dynamic_values(base_url,http_template)
    # print('\n\ndynamic_base_values: ',dynamic_base_values)
    results = []
    # 发送http请求并匹配结果
    for http_request in http_template.get("http",[]):
        method = http_request.get('method', '').upper()

        # 获取payloads
        if 'payloads' in http_request or 'attack' in http_request:
            dynamic_values = get_payloads(dynamic_base_values,http_request)
        
        result = execute_http_request(http_request,dynamic_values)
        if result:
            print('\n\nresult: ',result)
            yield result

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
        
