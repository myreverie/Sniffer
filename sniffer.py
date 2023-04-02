from scapy.all import AsyncSniffer, get_windows_if_list
import tkinter as tk


class MySniffer():
    def __init__(self) -> None:
        self.filter = None
        self.iface = []
        self.packet_data = ['123']
        self.interfaces = None
        self.asy_sniffer = None
        self.config = {
            'interface': '以太网',
            'filter': ''
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
        self.packet_data.append(packet.summary())
        print(packet.summary())
        for layer in packet.layers():
            print(layer().name)
            print(packet[layer().name].fields)


class SnifferGui(tk.Frame):
    def __init__(self, root: tk.Tk, sniffer: MySniffer) -> None:
        super().__init__(root)
        self.root = root
        self.sniffer = sniffer
        self.packet_data = tk.StringVar(value=self.sniffer.packet_data)

        self.select_if_button = tk.Button(self.root, text='选择网卡', command=self.create_if_frame)
        self.config_filter_button = tk.Button(self.root, text='设置过滤器', command=self.create_filter_frame)
        self.start_capture_button = tk.Button(self.root, text='开始捕获', command=self.start_capture)
        self.stop_capture_button = tk.Button(self.root, text='停止捕获', command=self.stop_capture)
        self.listbox_scrollbar = tk.Scrollbar(self.root)
        self.packet_listbox = tk.Listbox(self.root, listvariable=self.packet_data, width=100, height=50, yscrollcommand=self.listbox_scrollbar.set)
        self.listbox_scrollbar.config(command=self.packet_listbox.yview)
        # self.packet_listbox.bind('<<ListboxSelect>>', func=)

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
        self.packet_data.set(self.sniffer.packet_data)
        self.root.after(1000, func=self.packet_data_update)
        self.packet_listbox.see(tk.END)

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
            print(filter_entry.get())
            self.sniffer.config['filter'] = filter_entry.get()
            config_filter_frame.destroy()
        tk.Button(config_filter_frame, text='确定', command=filter_button_callback).pack()

    # 开始捕获数据包
    def start_capture(self):
        self.sniffer.start_sniff()

    # 停止捕获数据包
    def stop_capture(self):
        self.sniffer.stop_sniff()


def test():
    sniffer = MySniffer()
    root = tk.Tk()
    root.title('Sniffer')
    SnifferGui(root, sniffer)
    root.mainloop()


if __name__ == '__main__':
    test()
