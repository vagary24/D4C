import os
import yaml
from tqdm import tqdm
import shutil
from colorama import Fore
import json
from tabulate import tabulate
from datetime import datetime
# import pprint

# 处理傻逼pyyaml缩进问题
class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)
    
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
    print(Fore.BLUE+"[INFO] "+Fore.RESET+f"ALL FILES: {total_files}")
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
                    print(Fore.RED+f"[Error] parsing YAML file {file_path}: {exc}"+Fore.RESET)
    return matching_files

def show_sum_tempalate(mapfile,select_tag=None):
    if select_tag:
        try:
            table_data = []
            headers = ["Id", "Detail","severity"]
            with open(mapfile,'r',encoding='utf-8') as f:
                map = json.load(f)
            if select_tag in map['tags'].keys():
                for i in map['tags'][select_tag]['list']:
                    if i['severity'] == "high" or i['severity'] == "critical":
                        table_data.append([i['id'],i['name'],Fore.RED+i['severity']+Fore.RESET])
                    elif i['severity'] == "medium":
                        table_data.append([i['id'],i['name'],Fore.YELLOW+i['severity']+Fore.RESET])
                    else:
                        table_data.append([i['id'],i['name'],i['severity']])
            else:
                print(Fore.BLUE+"[INFO] "+Fore.RESET+"无指定tag对应模板")
            print(Fore.GREEN+"[SUCCESS] "+Fore.RESET+f"找到{len(table_data)}个扫描模板")
            print(tabulate(table_data, headers, tablefmt="grid", colalign=('left', 'left','left')))
            # root_dir = os.path.join(os.path.dirname(mapfile),select_tag.lower())
            # for file in os.listdir(root_dir):
            #     if file.endswith('.yaml'):
            #         with open(os.path.join(root_dir,file),'r',encoding='utf-8') as f:
            #             template = yaml.safe_load(f)
            #         table_data.append([template['id'],template['info']['name'],template['info']['severity']])
        except Exception as e:
            print(Fore.BLUE+"[INFO] "+Fore.RESET+"无指定tag模板")
            pass
    else:
        with open(mapfile,'r',encoding='utf-8') as f:
            map = json.load(f)

        # 准备表格数据
        table_data = []
        headers = ["Tag", "Count","Tag", "Count","Tag", "Count","Tag", "Count"]

        # 遍历字典，提取需要的信息，并构造六列的表格数据
        i = 0
        for tag, info in map['tags'].items():
            if i % 4 == 0:
                if i > 0:
                    table_data.append(half_row)
                    half_row = []
                half_row = [tag, str(info["count"])]
            else:
                half_row.extend([tag, str(info["count"])])
            i += 1

        # 添加最后一行数据
        if half_row:  # 确保不添加空行
            table_data.append(half_row)

        # 打印表格名称
        print(" "*16+f"Template Counts Table : In totle {map['sum']} Templates and {map['tagCount']} tags")

        # 打印表格
        print(tabulate(table_data, headers, tablefmt="grid", colalign=('left', 'right', 'left', 'right', 'left', 'right', 'left', 'right')))

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
                print(Fore.BLUE+"[INFO] "+Fore.RESET+f"{tag}更新"+str(len(infos) - map['tags'][tag]["count"])+"个模板")
                for info in infos:
                    if info not in map['tags'][tag]["list"]:
                        map['tags'][tag]["list"].append(info)
                        map['tags'][tag]["count"] += 1
                        map['sum'] += 1
                        print(Fore.BLUE+"[INFO] "+Fore.RESET+f'更新模板 {info.get("id","")}')
        else:
            print(Fore.BLUE+"[INFO] "+Fore.RESET+f"{tag}更新"+str(len(infos))+"个模板")
            tmp = {}
            tmp['count'] = len(infos)
            tmp['list'] = infos
            map['tags'][tag] = tmp
            map['tagCount'] += 1
            map['sum'] += len(infos)
            for info in infos:
                print(Fore.BLUE+"[INFO] "+Fore.RESET+f'更新模板 {info.get("id","")}')

    with open(map_file,'w',encoding='utf-8') as f:
        json.dump(map,f,ensure_ascii=False,indent=4)
    print(Fore.GREEN+"[SUCCESS] "+Fore.RESET+f"本次共更新{str(sum-map['sum'])}个模板 {str(tagCount - map['tagCount'])}个标签")
    # show_sum_tempalate(map_file)

def search_from_map(map_file,keyword):
    infolist = []
    with open(map_file,'r',encoding='utf-8') as f:
        map = json.load(f)
    for t in map['tags'].keys():
        for info in map['tags'][t]['list']:
            if keyword in str(info):
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
            print(Fore.GREEN+"[SUCCESS] "+Fore.RESET+f"找到{len(table_data)}个扫描模板")
            print(tabulate(table_data, headers, tablefmt="grid", colalign=('left', 'left','left')))
        else:
            print(Fore.BLUE+"[INFO] "+Fore.RESET+"未找到相关模板")
    except Exception as e:
        print(Fore.LIGHTRED_EX+"[ERROR] "+Fore.RESET+f"查询错误{str(e)}")
        pass
    # print(infolist)
    return infolist

'''
# def write_template_by_tag(directory,tags,write_root_dir):
#     matching_files = find_template_by_tag(directory, tags)
#     if os.path.exists(os.path.join(write_root_dir,"map.json")):
#         with open(os.path.join(write_root_dir,"map.json"),'r',encoding='utf-8') as f:
#             map = json.load(f)
#     else:
#         map = {}
#         map['sum']=0
#         map['tagsCount']=0

#     for tag in matching_files.keys():
#         write_tag_dir = os.path.join(write_root_dir,tag)
#         if not os.path.isdir(write_tag_dir):
#             try:
#                 os.mkdir(write_tag_dir)
#             except Exception as e:
#                 print(Fore.RED+"[ERROR] tag_dir 创建失败",e,Fore.RESET)
#             # print(write_directory)


        
#         # 更新tag映射表
#         if tag not in map.keys():
#             map[tag] = {}
#             map[tag]["tag_dir"] = write_tag_dir
#             map[tag]["count"] = len(matching_files[tag])
#             map["sum"] += len(matching_files[tag])
#             map['tagsCount'] += 1
#             print(Fore.BLUE+"[INFO] "+Fore.RESET+f"TAG:{tag} UPDATE {len(matching_files[tag])} FILES")
#         else:
#             update_count = len(matching_files[tag])-map[tag]["count"]
#             if update_count > 0 :
#                 print(Fore.BLUE+"[INFO] "+Fore.RESET+f"TAG:{tag} UPDATE {update_count} FILES")
#                 map["sum"] += update_count
#                 map[tag]["count"] += update_count

#         # 写入文件
#         for info in matching_files[tag]:
#             file = info['dir']
#             write_path = os.path.join(write_tag_dir,os.path.basename(file))
#             # 如果文件存在则跳过
#             if not os.path.exists(write_path):
#                 try:
#                     shutil.copy(file,write_path)
#                     print(Fore.BLUE+"[INFO] "+Fore.RESET+f"Writing {write_path}")
#                 except IOError as e:
#                     print(Fore.RED+f"[ERROR] 无法复制文件. {e}"+Fore.RESET)
#                 except:
#                     print(Fore.RED+"[ERROR] 无法复制文件，未知错误。"+Fore.RESET)
        
        
#     with open(os.path.join(write_root_dir,"map.json"),'w',encoding='utf-8') as f:
#         json.dump(map,f,indent=4,ensure_ascii=False)
#     print(Fore.GREEN+f'[SUCCESS] 更新tag映射表 {os.path.join(write_root_dir,"map.json")}'+Fore.RESET)
#     show_sum_tempalate(os.path.join(write_root_dir,"map.json"))
'''

# 从现有workflow中提取所有的tags
def extract_tags_from_yaml(folder_path, output_file):
    # 确保输出文件关闭后可以写入
    with open(output_file, 'w') as outfile:
        # 遍历指定文件夹
        for filename in os.listdir(folder_path):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                file_path = os.path.join(folder_path, filename)
                with open(file_path, 'r') as stream:
                    try:
                        # 加载YAML文件
                        yaml_content = yaml.safe_load(stream)
                        # 提取tags
                        if yaml_content and 'workflows' in yaml_content:
                            for workflow in yaml_content['workflows']:
                                if 'subtemplates' in workflow:
                                    for subtemplate in workflow['subtemplates']:
                                        if 'tags' in subtemplate:
                                            tags = subtemplate['tags']
                                            # 写入文件
                                            outfile.write(str(tags) + '\n')
                    except yaml.YAMLError as exc:
                        print(exc)

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
        
def update_templates(fingerPrintHub_file,tags_file,templates_dir,map_file):
    get_tag_from_fingerhub(fingerPrintHub_file,tags_file)
    mapping_by_tag(templates_dir,tags_file,map_file)
    
def update_fingerPrintHub(fingerPrintHub_dir,fingerPrintHub_file):
    from collections import OrderedDict
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
            ('host-redirects',True),
            ('max-redirects',2),
            ('matchers-condition','or'),
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
        print(Fore.GREEN+f"[SUCCESS] 本次共更新{update_count}条指纹更新"+Fore.RESET)
        # for i in update_fp:
        #     print(i)
    except Exception as e:
        print(e)
        raise Exception    
        
if __name__ == "__main__":
    # directory = 'template'  # Replace with your template folder path
    templates_dir = 'F:\\桌面\\CTF\\工具包\\yakit\\Yakit\\nuclei-templates'  # Replace with your template folder path
    # write_root_dir = 'F:\\桌面\\CTF\\工具包\\2024HW漏洞\\2024HWPOC_SCAN-main - 副本\\templates'
    map_file = 'F:\\桌面\\CTF\\工具包\\2024HW漏洞\\2024HWPOC_SCAN-main - 副本\\templates\\map.json'
    fingerPrintHub_file = 'templates\\fingerprinthub-web-fingerprints.yaml'
    # fingerPrintHub_file = 'templates\\new_fp2.yaml'
    tags_file = 'templates\\tags.txt'
    fingerPrintHub_dir= 'F:\\桌面\\CTF\\工具包\\2024HW漏洞\\FingerprintHub\\web-fingerprint'
    # search_from_map(map_file,'default')
    update_fingerPrintHub(fingerPrintHub_dir,fingerPrintHub_file)
    update_templates(fingerPrintHub_file,tags_file,templates_dir,map_file)

    # get_tag_from_fingerhub('templates\\fingerprinthub-web-fingerprints.yaml','templates\\tags2.txt')
    
    # search_from_map(map_file,'nacos')
        # tags = []
        # with open("templates\\tags.txt","r") as file:
        #     for tag in file.readlines():
        #         tags.append(tag.strip())
        # mapping_by_tag(directory, tags, map_file)
    # matching_files = find_template_by_tag(directory, tags)
        # print(matching_files)
    # write_template_by_tag(directory,tags,write_root_dir)
    # show_sum_tempalate('templates\map.json',"jenkins")
    # show_sum_tempalate('templates\map.json','nacos')
    # matching_files = find_template_by_tag(directory, tag)
    # print("Finish:")
    # for file_path in matching_files:
    #     print(file_path)

    # 提取tags
    # extract_tags_from_yaml('F:\\桌面\\CTF\\工具包\\yakit\\Yakit\\nuclei-templates\\workflows','./templates/tags.txt')