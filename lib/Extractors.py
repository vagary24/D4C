import re
from lxml import etree
import json
from lib.common import http_get_match_part,UNRESOLVED_VARIABLE,Marker
from lib.process import evaluate

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
    # print(corpus)
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

# dsl 提取器
def extract_dsl(e: dict, data: dict) -> dict:
    """Extract data from the response based on a DSL expressions
    """
    results = {'internal': {}, 'external': {}, 'extra_info': []}

    if e.get('internal',False) and e.get('name',''):
        results['internal'][e.get('name','')] = UNRESOLVED_VARIABLE

    for expression in e.get('dsl',[]):
        res = evaluate(f'{Marker.ParenthesisOpen}{expression}{Marker.ParenthesisClose}', data)
        if res == expression:
            continue
        if e.get('name',''):
            if e.internal:
                results['internal'][e.get('name','')] = res
            else:
                results['external'][e.get('name','')] = res
            return results
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
        elif type == 'dsl':
            res = extract_dsl(extractor, resp_data)
        else:
            print(f"[-] 错误类型提取器 {type}")

    #     logger.debug(f'[+] {extractor} -> {res}')
        extractors_result['internal'].update(res['internal'])
        extractors_result['external'].update(res['external'])
        extractors_result['extra_info'] += res['extra_info']
    # print('\n\nextractors_result: ',extractors_result)
    return extractors_result
