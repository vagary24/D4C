import os
import yaml
from tqdm import tqdm
import shutil
from colorama import Fore
import json
from tabulate import tabulate
from datetime import datetime
from lib.log import logger
from collections import OrderedDict
import config

def search_template_from_map(map_file,tag):
    filelist = []
    with open(map_file,'r',encoding='utf-8') as f:
        map = json.load(f)
    for t in map['tags'].keys():
        if tag == t:
            for info in map['tags'][t]['list']:
                filelist.append(info['dir'])
    return filelist

def search_template_by_id(map_file,template_id):
    with open(map_file,'r',encoding='utf-8') as f:
        map = json.load(f)
    for t in map['tags'].keys():
        for info in map['tags'][t]['list']:
            if info['id'] == template_id :
                return info['dir']
    return

def search_by_keyword(keyword,map_file=config.map_file):
    from tabulate import tabulate
    infolist = []
    with open(map_file,'r',encoding='utf-8') as f:
        map = json.load(f)
    for t in map['tags'].keys():
        for info in map['tags'][t]['list']:
            if keyword.lower() in str(info).lower():
                infolist.append(info)
    try:
        table_data = []
        headers = ["Id", "Detail","severity"]
        if infolist :
            for i in infolist:
                if i['severity'] == "high" or i['severity'] == "critical":
                    table_data.append([i['id'],i['name'],Fore.RED+i['severity']+Fore.RESET])
                elif i['severity'] == "medium":
                    table_data.append([i['id'],i['name'],Fore.YELLOW+i['severity']+Fore.RESET])
                else:
                    table_data.append([i['id'],i['name'],i['severity']])
            logger.success(f"找到{len(table_data)}个扫描模板")
            print(tabulate(table_data, headers, tablefmt="grid", colalign=('left', 'left','left')))
        else:
            logger.info("未找到相关模板")
    except Exception as e:
        logger.error(f"查询错误{str(e)}")
        pass
    # print(infolist)
    return infolist

def get_tag_from_fingerhub(fingerPrintHub_file,output_file):
    tag_set = set()
    with open(fingerPrintHub_file,'r',encoding='utf-8') as f:
        fingerhub = yaml.safe_load(f)

    pbar = tqdm(total=len(fingerhub['http'][0]['matchers']), desc="Get Tags From fingerhub",colour='green')

    with open(output_file,'w+',encoding='utf-8') as f:
        for match in fingerhub['http'][0]['matchers']:
            pbar.update(1)
            # 去重
            if match['name'] not in tag_set:
                tag_set.add(match['name'])
                f.write(match['name']+'\n')

def update_fingerPrintHub(fingerPrintHub_dir=config.fingerprinting_dir,fingerPrintHub_file=config.fingerprinting_file):
    # 处理傻逼pyyaml缩进问题
    class MyDumper(yaml.Dumper):
        def increase_indent(self, flow=False, indentless=False):
            return super(MyDumper, self).increase_indent(flow, False)

    update_count = 0
    try :
        with open(fingerPrintHub_file,'r',encoding='utf-8') as f:
            fp_all = yaml.safe_load(f)
        last_fp_file = "update_fp_file_"+datetime.now().strftime('%Y%m%d_%H%M%S')+".yaml"
        shutil.copyfile(fingerPrintHub_file,os.path.join(os.path.dirname(fingerPrintHub_file),last_fp_file))
        total_files = sum(len(files) for _, _, files in os.walk(fingerPrintHub_dir))
        pbar = tqdm(total=total_files, desc="Update fingerPrintHub",colour='green')
        for root, dirs, files in os.walk(fingerPrintHub_dir):
            for file in files:
                pbar.update(1)
                try:
                    if file.endswith(".yaml"):
                        file_path = os.path.join(root, file)
                        with open(file_path,'r',encoding='utf-8') as f:
                            fp = yaml.safe_load(f)
                        name = fp['info'].get('name','')
                        for http in fp['http']:
                            for path in http['path']:
                                if path not in fp_all['http'][0]['path']:
                                    fp_all['http'][0]['path'].append(path)
                            for matcher in http['matchers']:
                                if "name" not in matcher:
                                    matcher['name'] = name
                                if "case-insensitive" in matcher and matcher.get("case-insensitive",True):
                                    matcher.pop("case-insensitive")  
                                if matcher not in fp_all['http'][0]['matchers']:
                                    fp_all['http'][0]['matchers'].append(matcher)
                                    update_count += 1
                except Exception as e:
                    print(e)
                    pass
        pbar.close()
        http = OrderedDict([
            ('method', 'GET'),
            ('path', fp_all['http'][0]['path']),
            ('redirects',True),
            ('max-redirects',2),
            ('matchers-condition','or'),
            ('stop_at_first_match',True),
            ('matchers',fp_all['http'][0]['matchers'])
        ])   
        fp_new = OrderedDict([
            ('id', fp_all['id']),
            ('info', fp_all['info']),
            ('http', [dict(http)])
        ])
        with open(fingerPrintHub_file,'w',encoding='utf-8') as f:
            # ruamel.yaml.round_trip_dump(dict(fp_new), f,indent=4, block_seq_indent=2,explicit_start=True)
            yaml.dump(dict(fp_new),f,Dumper=MyDumper,sort_keys=False,allow_unicode=True,encoding='utf-8',default_flow_style=False,line_break=1)
        logger.success(f"本次共更新{update_count}条指纹更新共{len(fp_all['http'][0]['matchers'])}")
        # for i in update_fp:
        #     print(i)
    except Exception as e:
        print(e)
        raise Exception    

def mapping_by_tag(directory,tags_file,map_file):
    with open(tags_file,'r',encoding='utf-8') as f:
        tags = [line.strip() for line in f]

    matching_files = find_template_by_tag(directory, tags)
    if os.path.exists(map_file) :
        with open(map_file,"r",encoding="utf-8") as f:
            map = json.load(f)
    else:
        map = {}
        map['sum'] = 0
        map['tagCount'] = 0
        map['tags'] = {}
    
    sum = map['sum']
    tagCount = map['tagCount']

    for tag,infos in matching_files.items():
        if tag in map['tags'].keys():
            # 检测是否有更新
            if len(infos) > map['tags'][tag]["count"]:
                logger.info(f"{tag}更新"+str(len(infos) - map['tags'][tag]['count'])+"个模板")
                for info in infos:
                    if info not in map['tags'][tag]["list"]:
                        map['tags'][tag]["list"].append(info)
                        map['tags'][tag]["count"] += 1
                        map['sum'] += 1
                        logger.info(f'更新模板 {info.get("id","")}')

        else:
            logger.info(f"{tag}更新"+str(len(infos))+"个模板")
            tmp = {}
            tmp['count'] = len(infos)
            tmp['list'] = infos
            map['tags'][tag] = tmp
            map['tagCount'] += 1
            map['sum'] += len(infos)
            for info in infos:
                logger.info(f'更新模板 {info.get("id","")}')

    with open(map_file,'w',encoding='utf-8') as f:
        json.dump(map,f,ensure_ascii=False,indent=4)
    logger.success(f"本次共更新{str(map['sum']-sum)}个模板 {str(map['tagCount'] - tagCount)}个标签")
    logger.success(f"共{str(map['sum'])}个模板 {str(map['tagCount'])}个标签")
    # show_sum_tempalate(map_file)

def update_templates(fingerPrintHub_file=config.fingerprinting_file,tags_file=config.tags_file,
                     templates_dir=config.templates_dir,map_file=config.map_file):
    get_tag_from_fingerhub(fingerPrintHub_file,tags_file)
    mapping_by_tag(templates_dir,tags_file,map_file)

def find_template_by_tag(directory, tags):
    """
    Search for YAML files containing a specific tag in the given directory.

    :param directory: The directory to search in.
    :param tag: The tag to search for.
    :return: A list of paths to YAML files containing the tag.
    """
    matching_files = {}
    # Walk through all directories and files in the specified directory
    total_files = sum(len(files) for _, _, files in os.walk(directory))
    logger.info(f"ALL FILES: {total_files}")
    # 初始化tqdm进度条
    pbar = tqdm(total=total_files, desc="SEARCHING BY TAGS",colour='green')
    # Walk through all directories and files in the specified directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            pbar.update(1)
            if file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as stream:
                        yaml_content = yaml.safe_load(stream)
                        # Check if the tag is in the tags list of the YAML content
                        # print(yaml_content['info'].get('tags','').split(','))
                        for tag in yaml_content['info'].get('tags','').split(','):
                            if tag in tags:
                                # print(tag,'   ',matching_files.keys())
                                if tag in matching_files.keys():
                                    info = {}
                                    info['id']=yaml_content['id']
                                    info['name']=yaml_content['info']['name']
                                    info['severity']=yaml_content['info']['severity']
                                    info['dir']=os.path.abspath(file_path)
                                    matching_files[tag].append(info)
                                else:
                                    matching_files[tag]=[]
                                    info = {}
                                    info['id']=yaml_content['id']
                                    info['name']=yaml_content['info']['name']
                                    info['severity']=yaml_content['info']['severity']
                                    info['dir']=os.path.abspath(file_path)
                                    matching_files[tag].append(info)
                except yaml.YAMLError as exc:
                    logger.error(f"parsing YAML file {file_path}: {exc}")
    return matching_files
