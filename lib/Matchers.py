import re
import binascii
from lib.common import http_get_match_part,UNRESOLVED_VARIABLE,Marker
from lib.process import evaluate
from lib.log import logger

# 匹配状态码
def match_status_code(matcher: dict, status_code: int):
    """Matches a status code check against a corpus
    """
    # print('\n\nmatch_status_code: ',status_code," ",matcher.get('status',[]))
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
    if matcher.get('case_insensitive',True):
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
        if matcher.get('case_insensitive',True):
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

# 二进制匹配
def match_binary(matcher: dict, corpus: bytes):
    """Matches a binary check against a corpus
    """
    matched_binary = []
    for i, binary in enumerate(matcher.get('binary',[])):
        binary = binascii.unhexlify(binary)
        if binary not in corpus:
            if matcher.get('condition','') == 'and':
                return False, []
            elif matcher.get('condition','') == 'or':
                continue

        if matcher.get('condition','') == 'or':
            return True, [binary]

        matched_binary.append(binary)
        if len(matcher.get('binary','')) - 1 == i:
            return True, matched_binary

    return False, []

# dls匹配
def match_dsl(matcher: dict, data: dict) -> bool:
    """Matches on a generic map result
    """
    for i, expression in enumerate(matcher.get('dsl',[])):
        result = evaluate(f'{Marker.ParenthesisOpen}{expression}{Marker.ParenthesisClose}', data)
        if not isinstance(result, bool):
            if matcher.get('condition','') == 'and':
                return False
            elif matcher.get('condition','') == 'or':
                continue

        if result is False:
            if matcher.get('condition','') == 'and':
                return False
            elif matcher.get('condition','') == 'or':
                continue

        if len(matcher.get('dsl',{})) - 1 == i:
            return True
    return False

# def match_favicon(matcher: dict, data: dict):
#     f_url = data.get("BaseURL")+"/favicon.ico"
#     for hash in matcher.get('hash',''):
#         f_hash = favicon_hash(f_url)
#         print(f_url)
#         print(f_hash)
#         if hash == f_hash:
#             return True
#     return False

# 匹配过程
def http_match(request: dict, resp_data: dict, interactsh=None):
    matchers = request.get('matchers',[])
    matchers_result = []
    result = {}
    result['matchers_result'] = False
    result['matchers'] = []

    # if 'interactsh_' in str(matchers) and isinstance(interactsh, InteractshClient):
    #     interactsh.poll()
    #     resp_data['interactsh_protocol'] = '\n'.join(interactsh.interactsh_protocol)
    #     resp_data['interactsh_request'] = '\n'.join(interactsh.interactsh_request)
    #     resp_data['interactsh_response'] = '\n'.join(interactsh.interactsh_response)
    # else:
    #     resp_data['interactsh_protocol'] = ''
    #     resp_data['interactsh_request'] = ''
    #     resp_data['interactsh_response'] = ''

    logger.debug(f"matchers_len: {len(matchers)}")
    for i, matcher in enumerate(matchers):
        matcher_res = False
        item = http_get_match_part(matcher.get('part',''), resp_data, matcher.get('type','') == matcher['type'])
        
        # print('\n\nrequest: ',request.get('path'))

        # print('\n\nresp_data: ',resp_data)
        if matcher['type'] == 'status':
            matcher_res = match_status_code(matcher, resp_data.get('status_code', 0))

        elif matcher['type'] == 'size':
            matcher_res = match_size(matcher, len(item))

        elif matcher['type'] == 'word':
            matcher_res, _ = match_words(matcher, item, resp_data)

        elif matcher['type'] == 'regex':
            matcher_res, _ = match_regex(matcher, item)

        elif matcher.get('type','') == 'binary':
            matcher_res, _ = match_binary(matcher, item)
        
        elif matcher.get('type','') == 'dsl':
            matcher_res = match_dsl(matcher, resp_data)

        # elif matcher.get('type','') == 'favicon':
        #     matcher_res = match_favicon(matcher, resp_data)

        if matcher.get('negative',False):
            matcher_res = not matcher_res
        
        # 记录匹配成功的匹配器
        if matcher_res:
            result['matchers'].append(matcher)
            logger.debug(f'Match: {matcher_res} {str(matcher["type"])}')

        if matcher_res:
            # 匹配成功并且matchers-condition是or
            if request.get('matchers-condition','') == 'or':
                result['matchers_result'] = True
                logger.debug(f'http_match:{str(result)}')
                return result
        else:
            # print(request.get('matchers-condition',''))
            if request.get('matchers-condition','') == 'and':
                result['matchers_result'] = False
                logger.debug(f'http_match:{str(result)}')
                return result
            elif request.get('matchers-condition','') == 'or':
                continue
            else:
                result['matchers_result'] = False
                logger.debug(f'http_match:{str(result)}')
                return result

        matchers_result.append(matcher_res)

        if len(matchers) - 1 == i:
            result['matchers_result'] = True
            logger.debug(f'http_match:{str(result)}')
            return result

    result['matchers_result'] = False
    logger.debug(f'http_match:{str(result)}')
    return result
