import argparse
import warnings
from datetime import datetime
from colorama import Fore
import yaml
import os
import config
import lib.Nuclei as Nuclei
from lib.common import clear_dir,send_QQ_email,banner
from lib.SurvivalScan import probe_ips,process_status_codes
from lib.log import logger,create_handler,set_log_level

warnings.filterwarnings("ignore")

# 线程池大小
THREAD_POOL_SIZE = config.defult_THREAD_POOL_SIZE

# 创建VulnScan解析器
def VulnScan_args(parser):
    parser.add_argument('-u', '--url', help='VulnScan 目标URL')
    parser.add_argument('-f', '--file', help='VulnScan 包含目标URL的文件')
    # parser.add_argument('-v', '--vulnerability', type=int, choices=range(1, len(vuln_scan_functions)+1), help='VulnScan 指定漏洞编号进行扫描')
    parser.add_argument('-o', '--outputfile', type=str, default="", help='VulnScan 指定输出文件，默认输出至.\\result的项目文件夹中文件名为启动时间')
    parser.add_argument('-t', '--threadings', type=int, default=5, help='VulnScan 指定线程数默认5线程')
    parser.add_argument('-p','--proxy', action='store_true', default=False, help='VulnScan 是否启用代理，如需使用代理在config.py文件下设置')
    parser.add_argument('-l','--list',action='store_true', default=False, help='VulnScan 列出收录的poc以及对应编号')
    # parser.add_argument('-tf','--tasksFile', help='VulnScan 计划任务文件')
    parser.add_argument('--nuclei',help="VulnScan 使用指定Nuclei-Yaml模板扫描,指定多个模板用','分隔")
    parser.add_argument('--workflow',help="VulnScan 使用指定Nuclei-workflow模板扫描")
    parser.add_argument('--taskfile',help="VulnScan 使用指定任务文件")
    parser.add_argument('-as','--autoscan',action='store_true', default=False,help="VulnScan 自动指纹识别并自动模板漏扫")
    # parser.add_argument('-oe','--nuclei_extracts_output',help="VulnScan 使用指定Nuclei-Yaml模板提取数据时的输出路径")
    # parser.add_argument('-oj','--outputjson',action='store_true', default=False,help="VulnScan 输出json格式")
    parser.add_argument('-ot','--outputtarget',action='store_true', default=False,help="VulnScan 输出结果提取出目标")
    parser.add_argument('-oh','--output_html_report',action='store_true', default=False, help="VulnScan 输出html报告")
    parser.add_argument('-st','--save_tmpfile',action='store_true', default=False, help="VulnScan 保存临时文件")
    parser.add_argument('--log_lever',type=str, choices=['debug','info','success','warning','error','critical'], default='info', help="设置日志等级默认为INFO")
    parser.add_argument('--send_email',action='store_true', default=False, help="VulnScan 扫描完成后发送报告到邮箱")
    parser.add_argument('--search',type=str, help="VulnScan 搜索模板")
    # parser.add_argument('',action='store_true', default=False, help="VulnScan 扫描完成后发送报告到邮箱")

# 创建SurvivalScan解析器
def SurvivalScan_args(parser):
    parser.add_argument("-f","--file", required=True,help="SurvivalScan 探活目标txt文件")
    parser.add_argument("-o","--outputfile", help="SurvivalScan 输出的Excel(.xlsx) 不指定输出文件时结果将保存至项目文件夹.\result中")
    parser.add_argument("-Sc","--SurvivalScan_statusCode", default = ["200-500"],nargs='+', help="SurvivalScan 标识存活的状态码 默认200-500 参数例子: 200-299,403")
    parser.add_argument("-Su","--SurvivalScan_baseurl", default = "",help="SurvivalScan 用于拼接的Base URL 例如：http://127.0.0.1:80{/index}")
    parser.add_argument("-St","--SurvivalScan_threads", type=int, default=30, help="SurvivalScan 探活线程数默认为30,线程太大容易漏报建议20-30")
    parser.add_argument("-Sb","--buffer_size", type=int, default=100, help="缓冲区大小用于优化内存")
    parser.add_argument("-p","--proxy", action='store_true', default = False, help="开启代理,代理位于配置文件config.py中" )
    parser.add_argument('--log_lever',type=str, choices=['debug','info','success','warning','error','critical'], default='info', help="设置日志等级默认为INFO")

# 创建主解析器
def create_parser():
    parser = argparse.ArgumentParser(description=Fore.YELLOW+r'''常用指令
    查看具体模块帮助: D4C.py <module> -h
    查看所有模块详细帮助: D4C.py -hh
    清理result: D4C.py -c -cs 1000
    '''+Fore.RESET,formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument("-hh","--visable_Help", action='store_true', default=False,help="输出详细输出信息")
    parser.add_argument("-c","--clear_result", action='store_true', default=False,help="清理result文件夹删除空文件")
    parser.add_argument("-cs","--clear_size", type=int, default=1000,help="清理result文件夹中小于clear_size 字节的文件默认值为1000,单位为KB")
    parser.add_argument('--update', action='store_true', default=False,help="更新指纹以及nuclei-template")
    
    subparsers = parser.add_subparsers(dest='module', help='可用的模块')
    # 创建VulnScan模块的解析器
    global parser_VulnScan
    parser_VulnScan = subparsers.add_parser('vulnscan', help='漏洞扫描器模块',description=Fore.YELLOW+r'''常用命令
    列出可用模板: D4C.py vulnscan -l
    搜索可用模板：D4C.py vulnscan -s keyword                                  
    指定nuclei模板测试指定url: D4C.py vulnscan -u <url> --nuclei <path2template> [-ot] [-p]
    指定nuclei模板扫描批量url: D4C.py vulnscan -f <urlfile> --nuclei <path2template_1>,<path2template_2> [-t 10] [-p] [-ot] [-oh] [--log_lever success][--send_email]
    '''+Fore.RESET,formatter_class=argparse.RawTextHelpFormatter)
    VulnScan_args(parser_VulnScan)

    # 创建SurvivalScan模块的解析器
    global parser_SurvivalScan
    parser_SurvivalScan = subparsers.add_parser('survivalscan', help='探活模块',description=Fore.YELLOW+r'''常用命令
    查看帮助: D4C.py survivalscan -h
    常用探活: D4C.py survivalscan -f <hostfile>
    详细探活: D4C.py survivalscan -f <hostfile> [-o <outputfile>] [-Sc 200,300,403] [-Su "/index"] [-St 50] [-Sb 100]'''+Fore.RESET,formatter_class=argparse.RawTextHelpFormatter)
    SurvivalScan_args(parser_SurvivalScan)

    return parser

# VulnScan运行函数
def VulnScan_run(args,project_file):
    THREAD_POOL_SIZE = args.threadings
    
    is_send_email = args.send_email

    # 通过关键词搜索模板
    if args.search :
        from lib.update import search_by_keyword
        search_by_keyword(args.search)
        return

    # 执行nuclei模板扫描
    if args.nuclei and (args.file or args.url) :
        logger.debug(args.nuclei.split(','))
        result = Nuclei.nuclei_run_threadings(args.nuclei.split(','),args.url,args.file,project_file,THREAD_POOL_SIZE,
                                     args.proxy,args.save_tmpfile,args.outputtarget,args.output_html_report)
        if not result:
            parser_VulnScan.print_help()
            return
    elif args.workflow and (args.file or args.url) :
        workflow_run(args.workflow,args.file,project_file,THREAD_POOL_SIZE,args.proxy,
                      args.save_tmpfile,args.outputtarget,args.output_html_report) 
    elif args.autoscan:
        Nuclei.AutoScan(config.fingerprinting_file,args.file,project_file,THREAD_POOL_SIZE,args.proxy,
                      args.save_tmpfile,args.outputtarget,args.output_html_report)
    elif args.taskfile :
        if not os.path.exists(args.taskfile):
            logger.error('taskfile不存在')
            return
        import json
        with open(args.taskfile,'r',encoding='utf-8') as f:
            task = json.load(f)
        urlfile = task.get('file','')
        is_send_email = task.get('send_email',False)
        if not os.path.exists(urlfile):
            logger.error('urlfile不存在')
            return
        THREAD_POOL_SIZE = int(task.get('threadings',config.defult_THREAD_POOL_SIZE))
        if task.get('autoscan',False):
            Nuclei.AutoScan(config.fingerprinting_file,urlfile,project_file,THREAD_POOL_SIZE,task.get('proxy',False),
                      task.get('save_tmpfile',False),task.get('outputtarget',False),task.get('output_html_report',False))
        elif task.get('nuclei',[]):
            Nuclei.nuclei_run_threadings(task.get('nuclei'),'',urlfile,project_file,THREAD_POOL_SIZE,
                                     task.get('proxy',False),task.get('save_tmpfile',False),task.get('outputtarget',False),task.get('output_html_report',False))
        else:
            logger.error('taskFile错误无法解析')
    else:
        parser_VulnScan.print_help()
        return

    # 扫描完成后将报告发送邮箱
    report_file = os.path.join(project_file,'VulnScan_report.html')
    if is_send_email and os.path.exists(report_file):
        project_name = os.path.basename(project_file)
        send_QQ_email(project_file,config.email_sender,config.email_passwd,config.email_team,f"Vulnerability Report:{project_name}")

# SurvivalScan运行函数
def SurvivalScan_run(args,project_file):
    if not args.outputfile:
        outputFile = os.path.join(project_file,'SurvivalScan_result.xlsx')
    else:
        outputFile = args.outputfile
    # print(outputFile)
    status_codes = process_status_codes(args.SurvivalScan_statusCode)
    probe_ips(args.file, outputFile, status_codes, args.SurvivalScan_baseurl, args.SurvivalScan_threads, args.buffer_size, args.proxy)

def workflow_run(workflow_template_dir,in_file='', project_file='', THREAD_POOL_SIZE=5, use_proxy = False, save_tmpfile=False, output_target=False, output_html_report = False):
    # set_log_level('debug')
    with open(workflow_template_dir,'r',encoding='utf-8') as f:
        workflow_template = yaml.safe_load(f)
    Nuclei.workflow(workflow_template,in_file, project_file, THREAD_POOL_SIZE, use_proxy, save_tmpfile, output_target, output_html_report)
    

if __name__ == "__main__":
    # print(os.path.dirname(__file__))
    # print(os.getcwd())
    os.chdir(os.path.dirname(__file__))
    # print(os.getcwd())
    global parser
    banner()
    parser = create_parser()
    args = parser.parse_args()

    if args.visable_Help:
        parser.print_help()
        print(Fore.GREEN+"\n\n"+"-"*50+"VulnScan Help"+"-"*50+"\n"+Fore.RESET)
        parser_VulnScan.print_help()
        print(Fore.GREEN+"\n\n"+"-"*50+"SurvivalScan Help"+"-"*50+"\n"+Fore.RESET)
        parser_SurvivalScan.print_help()
        exit()

    if args.clear_result:
        create_handler()
        result_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "result")
        logger.info(f'正在清理{result_dir}清理阈值为{args.clear_size}字节.......')
        clear_dir(result_dir,args.clear_size)
        logger.success("清理结束")
        exit()
    
    if args.update :
        import lib.update as update
        create_handler()
        logger.info("更新指纹")
        update.update_fingerPrintHub()
        logger.info("更新模板及模板映射")
        update.update_templates()
        logger.success("更新成功")
        exit()
        
    if args.module :
        # 创建项目文件夹
        if args.outputfile:
            project_file = args.outputfile
            if not os.path.exists(project_file):
                project_file = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), "result"),datetime.now().strftime('%Y%m%d_%H%M%S'))
                os.mkdir(project_file)
        else:
            project_file = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), "result"),datetime.now().strftime('%Y%m%d_%H%M%S'))
            os.mkdir(project_file)
        # 创建日志处理器和日志文件
        log_file = os.path.join(project_file,'log')
        create_handler(log_file)
        set_log_level(args.log_lever)
        # set_log_level('debug')
        logger.success(f"创建项目文件夹{project_file}")
        logger.success(f"创建日志文件夹{log_file}")

    if args.module == "vulnscan":
        VulnScan_run(args,project_file)
    elif args.module == "survivalscan":
        SurvivalScan_run(args,project_file)
    else:
        parser.print_help()