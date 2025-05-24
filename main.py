import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess, time, ctypes, os, re, threading, webbrowser, win32con

PAGE_READABLE = (0x02 | 0x04 | 0x20 | 0x40)          # R, RW, RX, RWX

# Utility
def enum_memory(proc):
    mbi = ctypes.create_string_buffer(48)            # works for 32 and 64 bits
    addr = 0
    while ctypes.windll.kernel32.VirtualQueryEx(proc, ctypes.c_void_p(addr),
                                                mbi, 48):
        base     = ctypes.c_void_p.from_buffer(mbi).value
        size     = int.from_bytes(mbi.raw[24:32], 'little')
        state    = int.from_bytes(mbi.raw[32:36], 'little')
        protect  = int.from_bytes(mbi.raw[36:40], 'little')
        yield base, size, state, protect
        addr += size

def read_region(proc, base, size):
    buf = ctypes.create_string_buffer(size)
    br  = ctypes.c_size_t(0)
    if ctypes.windll.kernel32.ReadProcessMemory(proc, ctypes.c_void_p(base),
                                               buf, size, ctypes.byref(br)):
        return buf.raw[:br.value]
    return b''

# Extraction
def extract_scripts(pid, out_dir, progress=None):
    os.makedirs(out_dir, exist_ok=True)
    hproc = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not hproc:
        return 0

    total = scripts = 0
    for base, size, state, prot in enum_memory(hproc):
        if state != win32con.MEM_COMMIT or not (prot & PAGE_READABLE):
            continue
        blob = read_region(hproc, base, size)
        if not blob or b'COMPILER' not in blob:
            total += size
            if progress: progress(total)
            continue

        # find start and end of script
        for m in re.finditer(b'COMPILER', blob):
            start = blob.rfind(b'\n', 0, m.start()) + 1
            end   = blob.find(b'\x00\x00', m.end())
            if end == -1: continue
            data  = blob[start:end].decode('utf-8', 'ignore').strip()
            if '::' in data:                                 # minimum heuristic
                scripts += 1
                with open(f'{out_dir}/script_{scripts}.ahk', 'w',
                          encoding='utf-8') as f:
                    f.write(data)
        total += size
        if progress: progress(total)

    ctypes.windll.kernel32.CloseHandle(hproc)
    return scripts

# GUI
class DumpGUI:
    def __init__(self, root):
        self.root = root;  root.title('AHK Decompiler')
        self.exe   = None
        f = tk.Frame(root, padx=20, pady=20); f.pack()
        tk.Button(f, text='Select EXE', command=self.pick).pack(pady=6)
        self.pb = ttk.Progressbar(f, length=280); self.pb.pack(pady=4)
        self.msg = tk.Label(f, text='No file selected'); self.msg.pack(pady=6)
        self.run = tk.Button(f, text='Dump', state='disabled',
                             command=self.start); self.run.pack(pady=6)
        self.open = tk.Button(f, text='Open folder', state='disabled',
                              command=lambda: webbrowser.open('dump_scripts'))
        self.open.pack()

    def pick(self):
        p = filedialog.askopenfilename(filetypes=[('EXE', '*.exe')])
        if p:
            self.exe = p; self.msg.config(text=p); self.run.config(state='normal')

    def start(self):
        self.run.config(state='disabled'); self.pb['value']=0
        threading.Thread(target=self.dump).start()

    def dump(self):
        try:
            proc = subprocess.Popen(self.exe)

            # Wait until the executable has been fully unpacked
            self.msg.config(text='Waiting for unpack...')
            ok = wait_for_unpack(proc.pid)
            if not ok:
                raise RuntimeError('Timeout waiting for unpack')

            mem_total = 0x7FFFFFFF if not ctypes.sizeof(ctypes.c_void_p)==8 else 0x7FFFFFFFFFFF
            self.max_bytes = mem_total
            n = extract_scripts(proc.pid, 'dump_scripts',
                                progress=lambda done: self.pb.step(done*100/mem_total))
            proc.terminate()
            self.msg.config(text=f'{n} script(s) extracted.')
            self.open.config(state='normal')
        except Exception as e:
            self.msg.config(text=f'Error: {e}')
            self.run.config(state='normal')

# Wait for unpack of MPRESS in memory
def wait_for_unpack(pid, timeout=60, check_interval=1):
    hproc = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not hproc:
        return False

    t0 = time.time()
    try:
        while time.time() - t0 < timeout:
            for base, size, state, prot in enum_memory(hproc):
                if state != win32con.MEM_COMMIT or not (prot & PAGE_READABLE):
                    continue
                blob = read_region(hproc, base, size)
                if b'COMPILER' in blob:
                    return True                 # Unpacked
            time.sleep(check_interval)
    finally:
        ctypes.windll.kernel32.CloseHandle(hproc)
    return False

if __name__ == '__main__':
    root = tk.Tk()
    DumpGUI(root)
    root.mainloop()