import colorlog
import logging

# 使用自定义的SUCCESS日志级别
def success_logger(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kwargs)

# 定义自定义日志级别SUCCESS
SUCCESS_LEVEL = 25  # 确保这个值在20(INFO)和30(WARNING)之间
logging.addLevelName(SUCCESS_LEVEL, 'SUCCESS')

# 配置日志记录器
logger = colorlog.getLogger("Main_logger")

# 将success_logger方法添加到Logger类
logging.Logger.success = success_logger.__get__(logger, logging.Logger)

def create_handler(log_file='app.log'):
    # 颜色输出处理
    handler = colorlog.StreamHandler()
    # 设置编码为UTF-8
    # handler.stream.encoding = 'utf-8'
    # print("\n\nhandler.stream.encoding",handler.stream.encoding)
    handler.setFormatter(colorlog.ColoredFormatter(
        '[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message_log_color)s%(message)s',
        log_colors={
            'DEBUG': 'blue',
            'INFO': 'light_blue',
            'WARNING': 'yellow',
            'ERROR': 'light_red',
            'CRITICAL': 'purple',
            'SUCCESS': 'bold_green'  # 为SUCCESS级别定义颜色
        },
        secondary_log_colors={
            'message': {
                'ERROR': 'light_red',
                'CRITICAL': 'purple',
                'SUCCESS': 'bold_green',
                'WARNING': 'yellow'
            }
        },
        datefmt='%Y-%m-%d %H:%M:%S',
        style='%'
    ))

    # 创建一个文件处理器，并设置格式
    file_handler = logging.FileHandler(log_file,encoding='utf-8')
    file_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'  # 定义时间格式
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)

# 设置日志级别的函数
def set_log_level(level='info'):
    level = level.lower()  # 将输入转换为小写，以避免大小写不匹配的问题
    if level == 'debug':
        logger.setLevel(logging.DEBUG)
    elif level == 'info':
        logger.setLevel(logging.INFO)
    elif level == 'warning':
        logger.setLevel(logging.WARNING)
    elif level == 'error':
        logger.setLevel(logging.ERROR)
    elif level == 'critical':
        logger.setLevel(logging.CRITICAL)
    elif level == 'success':  # 假设你已经定义了SUCCESS_LEVEL
        logger.setLevel(SUCCESS_LEVEL)
    else:
        logger.setLevel(logging.INFO)

if __name__ == "__main__":
    create_handler()
    set_log_level('debug')
    # 记录日志
    logger.debug('This is a debug message')
    logger.info('This is an info message')
    logger.success('This is a success message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
    logger.critical('This is a critical message')
