from scapy.all import AsyncSniffer, get_windows_if_list
import tkinter as tk
import tkinter.ttk as ttk


class MySniffer():
    def __init__(self) -> None:
        self.filter = None
        self.iface = []
        self.packet_summary = []
        self.packet_detail = []
        self.interfaces = None
        self.asy_sniffer = None
        self.config = {
            'interface': '以太网',
            'filter': ''
        }
        self.port2protocol = {
            '443': 'HTTPS',
            '1900': 'SSDP',
            '80': 'HTTP',
            '3702': 'WS-Discovery',
            '2869': 'ICSLAP'
        }

    # 获取接口信息
    def get_interfaces(self):
        self.interfaces = get_windows_if_list()

    # 开始抓包
    def start_sniff(self):
        self.asy_sniffer = AsyncSniffer(prn=self.call_back, count=0, filter=self.config['filter'], iface=self.config['interface'])
        self.asy_sniffer.start()

    # 停止抓包
    def stop_sniff(self):
        self.asy_sniffer.stop()

    # 数据包处理
    def call_back(self, packet):
        # print(dir(packet))
        # print(packet.src, packet.dst)
        packet_detail_dict = {}
        packet_detail_dict['layers'] = [layer().name for layer in packet.layers()]
        temp_summary = packet.summary()
        for layer in packet.layers():
            # print(layer().name)
            # print(packet[layer().name].fields)
            packet_detail_dict[layer().name] = packet[layer().name].fields
        # 分析应用层协议
        if 'Raw' in packet_detail_dict['layers']:
            if 'UDP' in packet_detail_dict['layers'] or 'TCP' in packet_detail_dict['layers']:
                transmission_protocol = 'UDP' if 'UDP' in packet_detail_dict['layers'] else 'TCP'
                for port in self.port2protocol:
                    if packet_detail_dict[transmission_protocol]['sport'] == int(port) or packet_detail_dict[transmission_protocol]['dport'] == int(port):
                        temp_summary = temp_summary.replace('Raw', self.port2protocol[port])
                        packet_detail_dict['layers'][packet_detail_dict['layers'].index('Raw')] = self.port2protocol[port]
                        packet_detail_dict[self.port2protocol[port]] = packet_detail_dict['Raw']
        self.packet_summary.append(f'{len(self.packet_summary)} {temp_summary}')
        self.packet_detail.append(packet_detail_dict)


class SnifferGui(tk.Frame):
    def __init__(self, root: tk.Tk, sniffer: MySniffer) -> None:
        super().__init__(root)
        self.root = root
        self.sniffer = sniffer
        self.packet_data = tk.StringVar(value=self.sniffer.packet_summary)
        self.capture_flag = False

        self.select_if_button = tk.Button(self.root, text='选择网卡', command=self.create_if_frame)
        self.config_filter_button = tk.Button(self.root, text='设置过滤器', command=self.create_filter_frame)
        self.start_capture_button = tk.Button(self.root, text='开始捕获', command=self.start_capture)
        self.stop_capture_button = tk.Button(self.root, text='停止捕获', command=self.stop_capture)
        self.listbox_scrollbar = tk.Scrollbar(self.root)
        self.packet_listbox = tk.Listbox(self.root, listvariable=self.packet_data, width=100, height=25, yscrollcommand=self.listbox_scrollbar.set)
        self.listbox_scrollbar.config(command=self.packet_listbox.yview)
        self.packet_listbox.bind('<<ListboxSelect>>', func=self.create_packet_detail_frame)

        # 定时更新listbox
        self.packet_listbox.after(1000, func=self.packet_data_update)

        # 布局
        self.select_if_button.grid(row=0, column=0)
        self.config_filter_button.grid(row=0, column=1)
        self.start_capture_button.grid(row=0, column=2)
        self.stop_capture_button.grid(row=0, column=3)
        self.packet_listbox.grid(row=1, column=0, columnspan=4)
        self.listbox_scrollbar.grid(row=1, column=4, sticky='ns')

    def packet_data_update(self):
        if self.capture_flag is True:
            self.packet_data.set(self.sniffer.packet_summary)
            self.packet_listbox.see(tk.END)
        self.root.after(1000, func=self.packet_data_update)

    # 绘制 选择网卡 窗口
    def create_if_frame(self):
        # 获取接口信息
        self.sniffer.get_interfaces()

        # 创建控件
        select_if_frame = tk.Toplevel(self.root)
        interfaces_string = tk.StringVar()
        interfaces_string.set(self.sniffer.config['interface'])

        def if_button_callback():
            self.sniffer.config['interface'] = interfaces_string.get()
            select_if_frame.destroy()

        for interface in self.sniffer.interfaces:
            tk.Radiobutton(select_if_frame, text=f'{interface["name"]}', variable=interfaces_string, value=f'{interface["name"]}', ).pack(anchor='w')
        tk.Button(select_if_frame, text='确定', command=if_button_callback).pack()

    # 绘制 设置过滤器 窗口
    def create_filter_frame(self):
        config_filter_frame = tk.Toplevel(self.root)
        tk.Label(config_filter_frame, text='请输入BPF过滤规则').pack()
        filter_entry = tk.Entry(config_filter_frame)
        filter_entry.pack()

        def filter_button_callback():
            # print(filter_entry.get())
            self.sniffer.config['filter'] = filter_entry.get()
            config_filter_frame.destroy()
        tk.Button(config_filter_frame, text='确定', command=filter_button_callback).pack()

    # 绘制 数据包详细信息 窗口
    def create_packet_detail_frame(self, event):
        # 获取数据包序号
        w = event.widget
        index = int(w.curselection()[0])
        # print(index)
        # print(self.sniffer.packet_summary[index])
        # print(self.sniffer.packet_detail[index])

        # 绘制控件
        packet_detail_frame = tk.Toplevel(self.root)
        packet_detail_notebook = ttk.Notebook(packet_detail_frame)
        packet_detail_notebook.pack(fill=tk.BOTH, expand=True)
        for layer in self.sniffer.packet_detail[index]['layers']:
            frame = tk.Frame(packet_detail_frame)
            packet_detail_notebook.add(frame, text=layer)
            for item in self.sniffer.packet_detail[index][layer]:
                tk.Label(frame, text=f'{item}: {self.sniffer.packet_detail[index][layer][item]}', wraplength=500).pack(anchor='w')

    # 开始捕获数据包
    def start_capture(self):
        if self.capture_flag is False:
            self.capture_flag = True
            self.sniffer.start_sniff()

    # 停止捕获数据包
    def stop_capture(self):
        if self.capture_flag is True:
            self.capture_flag = False
            self.sniffer.stop_sniff()


def main():
    sniffer = MySniffer()
    root = tk.Tk()
    root.title('Sniffer')
    SnifferGui(root, sniffer)
    root.mainloop()


if __name__ == '__main__':
    main()
