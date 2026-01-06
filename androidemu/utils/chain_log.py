class ChainLogger:
    """
    链式日志记录器。
    将输出同时写入到终端 (base_fd) 和指定的文件中。
    """

    def __init__(self, base_fd, path):
        self.terminal = base_fd
        self.path = path
        self.log = None

    def write(self, message):
        # 1. 写入到终端 (如果有)
        if self.terminal:
            self.terminal.write(message)

        # 2. 写入到文件 (懒加载打开)
        if self.log is None:
            # 使用 utf-8 编码打开文件
            self.log = open(self.path, "w", encoding="utf-8")

        self.log.write(message)

    def flush(self):
        # 兼容 Python 3 的 flush 接口

        # 刷新终端
        if self.terminal and hasattr(self.terminal, "flush"):
            self.terminal.flush()

        # 刷新文件
        if self.log:
            self.log.flush()

    def close(self):
        """显式关闭文件句柄"""
        if self.log:
            self.log.close()
            self.log = None
