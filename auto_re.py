# -*- coding: utf-8 -*-
import idaapi, idautils, idc, ida_hexrays, ida_funcs, ida_name, ida_segment
import json, os, re, time, threading, queue
from collections import deque

try:
    import requests
    HAS_REQUESTS = True
    SESSION = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=30, pool_maxsize=30, max_retries=2, pool_block=False)
    SESSION.mount('http://', adapter)
    SESSION.mount('https://', adapter)
except ImportError:
    HAS_REQUESTS = False
    SESSION = None

import urllib.request, urllib.error

if idaapi.IDA_SDK_VERSION >= 920:
    from PySide6.QtWidgets import *
    from PySide6.QtGui import QFont
    from PySide6.QtCore import Qt, Signal, QTimer, QAbstractTableModel, QModelIndex, QThread
else:
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import QFont
    from PyQt5.QtCore import Qt, QTimer, QAbstractTableModel, QModelIndex, QThread
    Signal = __import__('PyQt5.QtCore', fromlist=['pyqtSignal']).pyqtSignal

CONFIG_FILE = os.path.join(idaapi.get_user_idadir(), 'ai_rename_config.json')

STYLES = """
QWidget{background:#1a1a1a;color:#e0e0e0;font:9pt 'Segoe UI'}
QDialog{background:#1a1a1a}
QGroupBox{font-weight:600;border:2px solid #2d2d2d;border-radius:6px;margin-top:16px;padding:12px 8px 8px 8px;background:#212121}
QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 8px;color:#4fc3f7;font-weight:600}
QLineEdit,QTextEdit{background:#2d2d2d;border:2px solid #3d3d3d;border-radius:4px;padding:6px 8px;color:#e0e0e0}
QLineEdit:focus,QTextEdit:focus{border:2px solid #1e88e5;background:#333}
QLineEdit:disabled{background:#252525;color:#666}
QPushButton{background:#1e88e5;color:#fff;border:none;border-radius:4px;padding:8px 16px;font-weight:600}
QPushButton:hover{background:#2196f3}
QPushButton:pressed{background:#1565c0}
QPushButton:disabled{background:#2d2d2d;color:#666}
QPushButton#stop{background:#d32f2f}
QPushButton#stop:hover{background:#e53935}
QPushButton#apply{background:#388e3c}
QPushButton#apply:hover{background:#43a047}
QPushButton#preset{background:#2d2d2d;border:1px solid #3d3d3d;padding:6px 12px;font-weight:normal}
QPushButton#preset:hover{background:#3d3d3d;border:1px solid #1e88e5}
QPushButton#secondary{background:#424242;font-weight:normal}
QPushButton#secondary:hover{background:#505050}
QTableView{background:#1e1e1e;alternate-background-color:#242424;border:2px solid #2d2d2d;border-radius:4px;gridline-color:#2d2d2d;selection-background-color:#1565c0}
QTableView::item{padding:4px}
QTableView::item:selected{background:#1565c0;color:#fff}
QHeaderView::section{background:#252525;padding:8px 6px;border:none;border-right:1px solid #2d2d2d;border-bottom:2px solid #1e88e5;font-weight:600;color:#4fc3f7}
QProgressBar{border:2px solid #2d2d2d;border-radius:4px;text-align:center;background:#2d2d2d;color:#fff;font-weight:600}
QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #1e88e5,stop:1 #42a5f5);border-radius:2px}
QLabel{color:#b0b0b0}
QScrollBar:vertical{background:#2d2d2d;width:12px;border-radius:6px}
QScrollBar::handle:vertical{background:#424242;border-radius:6px;min-height:20px}
QScrollBar::handle:vertical:hover{background:#4fc3f7}
QSpinBox{background:#2d2d2d;border:2px solid #3d3d3d;border-radius:4px;padding:4px 8px;color:#e0e0e0}
QSpinBox:focus{border:2px solid #1e88e5}
QCheckBox{spacing:6px}
QCheckBox::indicator{width:16px;height:16px;border-radius:3px;border:2px solid #3d3d3d;background:#2d2d2d}
QCheckBox::indicator:checked{background:#1e88e5;border-color:#1e88e5}
"""

SKIP_SEGS = {'.plt','.plt.got','.plt.sec','extern','.extern','.got','.got.plt','.init','.fini','.dynsym','.dynstr','LOAD','.interp','.rela.dyn','.rela.plt','.hash','.gnu.hash','.note','.note.gnu.build-id','.note.ABI-tag'}
SYS_PREFIX = ('__cxa_','__gxx_','__gnu_','__libc_','__ctype_','_GLOBAL_','_init','_fini','_start','atexit','malloc','free','memcpy','memset','strlen','printf','scanf','fprintf','sprintf','operator','std::','boost::','__stack_chk','__security','_security','__report','__except','__imp_','__x86.','__do_global')
SYS_MODULES = ('kernel32.','ntdll.','user32.','advapi32.','msvcrt.','ucrtbase.','ws2_32.','libc.so','libm.so','libpthread','foundation.','corefoundation.','uikit.')

DEFAULT_PROMPT = """You are an expert reverse engineer. Analyze the decompiled code and suggest a descriptive function name.

Rules:
- Use snake_case format
- Be specific and descriptive (e.g., parse_user_config, validate_license_key, decrypt_network_packet)
- Focus on what the function DOES, not how
- Use common prefixes: init_, parse_, validate_, process_, handle_, send_, recv_, encrypt_, decrypt_, load_, save_, get_, set_, create_, destroy_, check_, is_, has_
- Keep names 3-40 characters
- NO generic names like: func1, do_something, process_data, handle_stuff

Output ONLY the function name, nothing else."""

DEFAULT_BATCH_PROMPT = """You are an expert reverse engineer. For each function below, suggest a descriptive snake_case name.

Rules:
- snake_case format only
- Be specific: parse_config_file, validate_user_token, send_heartbeat_packet
- Focus on WHAT function does
- Common prefixes: init_, parse_, validate_, process_, handle_, send_, recv_, encrypt_, decrypt_, load_, save_, get_, set_, create_, destroy_, check_, is_, has_
- 3-40 chars per name
- NO generic names

Output format - exactly one name per line, numbered:
1. suggested_name_one
2. suggested_name_two
..."""

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            c = json.load(open(CONFIG_FILE))
            c.setdefault('batch_size', 20)
            c.setdefault('parallel_workers', 10)
            c.setdefault('filter_system', True)
            c.setdefault('filter_empty', True)
            c.setdefault('min_func_size', 10)
            c.setdefault('max_xrefs', 100)
            c.setdefault('custom_prompt', '')
            c.setdefault('use_custom_prompt', False)
            return c
    except: pass
    return {'api_url':'','api_key':'','model':'','batch_size':20,'parallel_workers':10,'filter_system':True,'filter_empty':True,'min_func_size':10,'max_xrefs':100,'custom_prompt':'','use_custom_prompt':False}

def save_config(c):
    try: json.dump(c, open(CONFIG_FILE,'w'), indent=2)
    except: pass

def is_valid_seg(ea):
    seg = idaapi.getseg(ea)
    if not seg: return False
    name = idaapi.get_segm_name(seg)
    if not name or name in SKIP_SEGS: return False
    return name.startswith('.text') or name in ('CODE','.code') or ('.' not in name and seg.perm & idaapi.SEGPERM_EXEC)

def is_sys_func(name):
    nl = name.lower()
    for p in SYS_PREFIX:
        if name.startswith(p) or nl.startswith(p.lower()): return True
    for m in SYS_MODULES:
        if m in nl: return True
    return False

def get_func_size(ea):
    f = ida_funcs.get_func(ea)
    return (f.end_ea - f.start_ea) if f else 0

def get_xref_count(ea):
    c = 0
    for _ in idautils.CodeRefsTo(ea, True):
        c += 1
        if c > 150: break
    return c

def get_code_fast(ea, max_len=1200):
    result = [None]
    def _get_code():
        try:
            cf = ida_hexrays.decompile(ea)
            if cf:
                result[0] = str(cf)[:max_len]
                return
        except: pass
        f = ida_funcs.get_func(ea)
        if not f:
            result[0] = None
            return
        lines = []
        cur = f.start_ea
        while cur < f.end_ea and len(lines) < 25:
            lines.append(idc.GetDisasm(cur))
            cur = idc.next_head(cur, f.end_ea)
        result[0] = '\n'.join(lines)[:max_len]
    idaapi.execute_sync(_get_code, idaapi.MFF_READ)
    return result[0]

def get_strings_fast(ea):
    result = [[]]
    def _get_strings():
        r = []
        try:
            for item in idautils.FuncItems(ea):
                for xref in idautils.DataRefsFrom(item):
                    s = idc.get_strlit_contents(xref)
                    if s:
                        try:
                            s = s.decode() if isinstance(s, bytes) else s
                            if 2 < len(s) < 60: r.append(s[:50])
                        except: pass
                if len(r) >= 4: break
        except: pass
        result[0] = list(set(r))[:4]
    idaapi.execute_sync(_get_strings, idaapi.MFF_READ)
    return result[0]

def get_calls_fast(ea):
    result = [[]]
    def _get_calls():
        r = []
        try:
            for item in idautils.FuncItems(ea):
                for xref in idautils.CodeRefsFrom(item, False):
                    n = idc.get_func_name(xref)
                    if n and not n.startswith('sub_'): r.append(n)
                if len(r) >= 5: break
        except: pass
        result[0] = list(set(r))[:5]
    idaapi.execute_sync(_get_calls, idaapi.MFF_READ)
    return result[0]

def ai_request(cfg, prompt, sys_prompt):
    url, key, model = cfg['api_url'], cfg['api_key'], cfg['model']
    hdrs = {'Content-Type': 'application/json'}
    is_ollama = 'localhost:11434' in url or '127.0.0.1:11434' in url
    is_anthropic = 'anthropic.com' in url
    is_ollama_native = is_ollama and '/api/' in url
    
    if is_ollama_native:
        data = {'model':model,'messages':[{'role':'system','content':sys_prompt},{'role':'user','content':prompt}],'stream':False,'options':{'temperature':0.1,'num_predict':500}}
    elif is_anthropic:
        hdrs['x-api-key'] = key
        hdrs['anthropic-version'] = '2023-06-01'
        data = {'model':model,'max_tokens':500,'messages':[{'role':'user','content':sys_prompt+'\n\n'+prompt}],'temperature':0.1}
    else:
        if key: hdrs['Authorization'] = f'Bearer {key}'
        data = {'model':model,'messages':[{'role':'system','content':sys_prompt},{'role':'user','content':prompt}],'max_tokens':500,'temperature':0.1}
    
    if HAS_REQUESTS and SESSION:
        r = SESSION.post(url, headers=hdrs, json=data, timeout=120)
        r.raise_for_status()
        res = r.json()
    else:
        req = urllib.request.Request(url, json.dumps(data).encode(), hdrs)
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.loads(r.read().decode())
    
    if is_ollama_native: return res.get('message',{}).get('content','').strip()
    elif is_anthropic: return res['content'][0]['text'].strip()
    return res['choices'][0]['message']['content'].strip()

def clean_name(name, existing=None):
    if not name: return None
    name = re.sub(r'[`"\'\n\r\t]', '', name)
    name = name.split('(')[0].split(':')[-1].strip()
    name = re.sub(r'^[\d\.\-\*\s]+', '', name)
    m = re.search(r'\b([a-z][a-z0-9_]*[a-z0-9])\b', name.lower())
    if m:
        name = m.group(1)
    else:
        name = re.sub(r'_+', '_', re.sub(r'[^a-zA-Z0-9_]', '_', name)).strip('_').lower()
    name = re.sub(r'^[0-9_]+', '', name)[:50]
    if not name or len(name) < 3: return None
    if name in ('function','func','sub','unknown','unnamed','noname'): return None
    if existing:
        orig, cnt = name, 1
        while name in existing:
            name = f"{orig}_{cnt}"
            cnt += 1
            if cnt > 99: return None
    return name

class FuncData:
    __slots__ = ['ea','name','suggested','status','checked','code','strings','calls']
    def __init__(self, ea, name):
        self.ea, self.name, self.suggested, self.status, self.checked = ea, name, '', 'Pending', True
        self.code = self.strings = self.calls = None

class ResultSignal(QThread):
    result = Signal(list)
    def __init__(self): super().__init__()

class VirtualFuncModel(QAbstractTableModel):
    HEADERS = ['','Address','Current','Suggested','Status']
    def __init__(self, parent=None):
        super().__init__(parent)
        self.funcs, self.filtered, self.filter_text = [], [], ''
    
    def set_data(self, funcs):
        self.beginResetModel()
        self.funcs = funcs
        self._apply_filter()
        self.endResetModel()
    
    def clear(self):
        self.beginResetModel()
        self.funcs, self.filtered = [], []
        self.endResetModel()
    
    def _apply_filter(self):
        if not self.filter_text:
            self.filtered = list(range(len(self.funcs)))
        else:
            ft = self.filter_text.lower()
            self.filtered = [i for i,f in enumerate(self.funcs) if ft in f.name.lower() or ft in f'{f.ea:x}' or (f.suggested and ft in f.suggested.lower())]
    
    def set_filter(self, t):
        self.beginResetModel()
        self.filter_text = t
        self._apply_filter()
        self.endResetModel()
    
    def rowCount(self, p=QModelIndex()): return len(self.filtered)
    def columnCount(self, p=QModelIndex()): return 5
    def headerData(self, s, o, r=Qt.DisplayRole): return self.HEADERS[s] if r==Qt.DisplayRole and o==Qt.Horizontal else None
    
    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid() or idx.row() >= len(self.filtered): return None
        f = self.funcs[self.filtered[idx.row()]]
        c = idx.column()
        if role == Qt.DisplayRole:
            if c==0: return 'X' if f.checked else ''
            elif c==1: return f'{f.ea:X}'
            elif c==2: return f.name
            elif c==3: return f.suggested
            elif c==4: return f.status
        elif role == Qt.TextAlignmentRole and c==0: return Qt.AlignCenter
        return None
    
    def flags(self, idx): return Qt.ItemIsEnabled | Qt.ItemIsSelectable
    def get_func(self, row): return self.funcs[self.filtered[row]] if 0<=row<len(self.filtered) else None
    def get_func_idx(self, row): return self.filtered[row] if 0<=row<len(self.filtered) else -1
    
    def refresh_rows(self, indices):
        if not indices: return
        rows = [self.filtered.index(i) for i in indices if i in self.filtered]
        if rows:
            self.dataChanged.emit(self.index(min(rows),0), self.index(max(rows),4))
    
    def toggle_all(self, chk):
        for f in self.funcs: f.checked = chk
        if self.filtered: self.dataChanged.emit(self.index(0,0), self.index(len(self.filtered)-1,0))
    
    def get_checked(self): return [(i,f) for i,f in enumerate(self.funcs) if f.checked]
    def get_with_suggestions(self): return [(i,f) for i,f in enumerate(self.funcs) if f.checked and f.suggested]
    def total(self): return len(self.funcs)

class AnalyzeWorker(QThread):
    batch_done = Signal(list)
    progress = Signal(int, int)
    finished = Signal(int)
    log = Signal(str, str)
    
    def __init__(self, cfg, items, existing, sys_prompt, batch_size):
        super().__init__()
        self.cfg = cfg
        self.items = items
        self.existing = set(existing)
        self.sys_prompt = sys_prompt
        self.batch_size = batch_size
        self.running = True
    
    def stop(self):
        self.running = False
    
    def run(self):
        done = 0
        total = len(self.items)
        batches = [self.items[i:i+self.batch_size] for i in range(0, total, self.batch_size)]
        
        for batch in batches:
            if not self.running: break
            results = self.process_batch(batch)
            for idx, func, name in results:
                if name:
                    self.existing.add(name)
            self.batch_done.emit(results)
            done += len(batch)
            self.progress.emit(done, total)
        
        self.finished.emit(done)
    
    def process_batch(self, batch):
        results = []
        valid = []
        
        for idx, func in batch:
            if not func.code:
                func.code = get_code_fast(func.ea, 800)
                func.strings = get_strings_fast(func.ea)
                func.calls = get_calls_fast(func.ea)
            if func.code:
                valid.append((idx, func))
            else:
                results.append((idx, func, None))
        
        if not valid:
            return results
        
        try:
            if len(valid) == 1:
                idx, f = valid[0]
                prompt = f"Code:\n```\n{f.code}\n```"
                if f.strings: prompt += f"\nStrings found: {f.strings}"
                if f.calls: prompt += f"\nCalled functions: {f.calls}"
                resp = ai_request(self.cfg, prompt, self.sys_prompt)
                name = clean_name(resp, self.existing)
                results.append((idx, f, name))
            else:
                prompt = "Functions to name:\n\n"
                for i, (idx, f) in enumerate(valid):
                    prompt += f"[{i+1}]\n```\n{f.code[:600]}\n```\n"
                    if f.strings: prompt += f"Strings: {f.strings[:3]}\n"
                    if f.calls: prompt += f"Calls: {f.calls[:3]}\n"
                    prompt += "\n"
                
                resp = ai_request(self.cfg, prompt, self.sys_prompt)
                names = self.parse_batch_response(resp, len(valid))
                
                for i, (idx, f) in enumerate(valid):
                    name = clean_name(names[i], self.existing) if i < len(names) else None
                    if name:
                        self.existing.add(name)
                    results.append((idx, f, name))
                    
        except Exception as e:
            self.log.emit(f'API Error: {str(e)[:80]}', 'err')
            for idx, f in valid:
                results.append((idx, f, None))
        
        return results
    
    def parse_batch_response(self, resp, expected):
        names = []
        for line in resp.split('\n'):
            line = line.strip()
            if not line or '```' in line: continue
            line = re.sub(r'^[\d\.\)\-\*\s]+', '', line).strip()
            if line and 2 < len(line) < 60:
                parts = line.split()
                nm = parts[0] if parts else line
                nm = re.sub(r'[^a-zA-Z0-9_]', '', nm)
                if nm and len(nm) >= 3:
                    names.append(nm)
        while len(names) < expected:
            names.append(None)
        return names[:expected]

class AIRenameDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.model = None
        self.is_loading = False
        self.load_timer = None
        self.func_iter = None
        self.temp_funcs = []
        self.scanned = 0
        self.workers = []
        self.existing_names = set()
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle('AI Rename Ultra v6.0 - High Performance')
        self.setMinimumSize(1150, 850)
        self.setStyleSheet(STYLES)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(10,10,10,10)
        
        api = QGroupBox('API Configuration')
        al = QVBoxLayout(api)
        al.setSpacing(6)
        
        pr = QHBoxLayout()
        for n,p in [('Ollama','ollama'),('OpenAI','openai'),('Claude','claude'),('OpenRouter','openrouter')]:
            b = QPushButton(n)
            b.setObjectName('preset')
            b.clicked.connect(lambda c,x=p: self.set_preset(x))
            pr.addWidget(b)
        pr.addStretch()
        self.toggle_btn = QPushButton('Collapse')
        self.toggle_btn.setObjectName('secondary')
        self.toggle_btn.clicked.connect(self.toggle_api)
        pr.addWidget(self.toggle_btn)
        al.addLayout(pr)
        
        self.api_content = QWidget()
        acl = QVBoxLayout(self.api_content)
        acl.setContentsMargins(0,0,0,0)
        acl.setSpacing(6)
        
        gl = QGridLayout()
        gl.setSpacing(6)
        self.url_edit = QLineEdit(self.cfg.get('api_url',''))
        self.url_edit.setPlaceholderText('http://localhost:11434/v1/chat/completions')
        self.key_edit = QLineEdit(self.cfg.get('api_key',''))
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText('Optional for local Ollama')
        self.model_edit = QLineEdit(self.cfg.get('model',''))
        self.model_edit.setPlaceholderText('qwen2.5-coder:14b')
        gl.addWidget(QLabel('URL:'),0,0)
        gl.addWidget(self.url_edit,0,1)
        gl.addWidget(QLabel('Key:'),1,0)
        gl.addWidget(self.key_edit,1,1)
        gl.addWidget(QLabel('Model:'),2,0)
        gl.addWidget(self.model_edit,2,1)
        acl.addLayout(gl)
        
        self.custom_prompt_cb = QCheckBox('Use Custom Prompt')
        self.custom_prompt_cb.setChecked(self.cfg.get('use_custom_prompt', False))
        acl.addWidget(self.custom_prompt_cb)
        
        self.custom_prompt_edit = QTextEdit()
        self.custom_prompt_edit.setPlaceholderText('Custom system prompt (leave empty to use default optimized prompt)')
        self.custom_prompt_edit.setText(self.cfg.get('custom_prompt', ''))
        self.custom_prompt_edit.setMaximumHeight(80)
        acl.addWidget(self.custom_prompt_edit)
        
        br = QHBoxLayout()
        sb = QPushButton('Save Config')
        sb.clicked.connect(self.save_cfg)
        br.addWidget(sb)
        tb = QPushButton('Test API')
        tb.clicked.connect(self.test_api)
        br.addWidget(tb)
        db = QPushButton('Show Default Prompt')
        db.setObjectName('secondary')
        db.clicked.connect(self.show_default_prompt)
        br.addWidget(db)
        br.addStretch()
        acl.addLayout(br)
        al.addWidget(self.api_content)
        layout.addWidget(api)
        self.api_group = api
        
        perf = QGroupBox('Performance Settings')
        pl = QGridLayout(perf)
        pl.setSpacing(8)
        
        self.batch_spin = QSpinBox()
        self.batch_spin.setRange(1,50)
        self.batch_spin.setValue(self.cfg.get('batch_size',20))
        self.batch_spin.setToolTip('Functions per API call (15-25 optimal for Qwen)')
        pl.addWidget(QLabel('Batch Size:'),0,0)
        pl.addWidget(self.batch_spin,0,1)
        
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1,20)
        self.workers_spin.setValue(self.cfg.get('parallel_workers',10))
        self.workers_spin.setToolTip('Parallel workers (8-12 for local, 3-5 for cloud)')
        pl.addWidget(QLabel('Workers:'),0,2)
        pl.addWidget(self.workers_spin,0,3)
        
        self.min_size_spin = QSpinBox()
        self.min_size_spin.setRange(0,1000)
        self.min_size_spin.setValue(self.cfg.get('min_func_size',10))
        pl.addWidget(QLabel('Min Size (bytes):'),0,4)
        pl.addWidget(self.min_size_spin,0,5)
        
        self.max_xref_spin = QSpinBox()
        self.max_xref_spin.setRange(0,500)
        self.max_xref_spin.setValue(self.cfg.get('max_xrefs',100))
        pl.addWidget(QLabel('Max XRefs:'),0,6)
        pl.addWidget(self.max_xref_spin,0,7)
        
        self.speed_lbl = QLabel('')
        self.speed_lbl.setStyleSheet('color:#4fc3f7;font-style:italic')
        self.batch_spin.valueChanged.connect(self.update_speed)
        self.workers_spin.valueChanged.connect(self.update_speed)
        self.update_speed()
        pl.addWidget(self.speed_lbl,1,0,1,4)
        
        self.filter_sys_cb = QCheckBox('Skip System Functions')
        self.filter_sys_cb.setChecked(self.cfg.get('filter_system',True))
        pl.addWidget(self.filter_sys_cb,1,4,1,2)
        
        self.filter_empty_cb = QCheckBox('Skip Tiny Functions')
        self.filter_empty_cb.setChecked(self.cfg.get('filter_empty',True))
        pl.addWidget(self.filter_empty_cb,1,6,1,2)
        
        layout.addWidget(perf)
        self.perf_group = perf
        
        tb = QHBoxLayout()
        self.load_btn = QPushButton('Load All sub_*')
        self.load_btn.clicked.connect(self.load_funcs)
        tb.addWidget(self.load_btn)
        lb = QPushButton('Load Current')
        lb.setObjectName('secondary')
        lb.clicked.connect(self.load_current)
        tb.addWidget(lb)
        rlb = QPushButton('Load Range')
        rlb.setObjectName('secondary')
        rlb.clicked.connect(self.load_range)
        tb.addWidget(rlb)
        tb.addWidget(QLabel('|'))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Filter by name/address...')
        self.filter_edit.setFixedWidth(200)
        self.filter_edit.textChanged.connect(lambda t: self.model.set_filter(t) or self.update_count())
        tb.addWidget(self.filter_edit)
        tb.addStretch()
        self.count_lbl = QLabel('0 functions')
        self.count_lbl.setStyleSheet('color:#4fc3f7;font-weight:600;font-size:10pt')
        tb.addWidget(self.count_lbl)
        layout.addLayout(tb)
        
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        self.table.doubleClicked.connect(self.jump_to)
        self.table.clicked.connect(self.on_click)
        self.table.setShowGrid(False)
        self.table.setColumnWidth(0,35)
        self.table.setColumnWidth(1,95)
        self.table.setColumnWidth(4,75)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        layout.addWidget(self.table)
        
        pl = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(20)
        pl.addWidget(self.progress)
        self.status_lbl = QLabel('Ready')
        self.status_lbl.setStyleSheet('color:#4fc3f7;font-weight:600')
        self.status_lbl.setMinimumWidth(250)
        pl.addWidget(self.status_lbl)
        layout.addLayout(pl)
        
        ll = QHBoxLayout()
        ll.addWidget(QLabel('Log:'))
        ll.addStretch()
        cb = QPushButton('Clear')
        cb.setObjectName('secondary')
        cb.setFixedWidth(70)
        cb.clicked.connect(lambda: self.log.clear())
        ll.addWidget(cb)
        layout.addLayout(ll)
        
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(80)
        layout.addWidget(self.log)
        self.add_log(f'HTTP: {"requests+connection_pool" if HAS_REQUESTS else "urllib"}', 'info')
        
        ar = QHBoxLayout()
        self.analyze_btn = QPushButton('Analyze Selected')
        self.analyze_btn.setMinimumWidth(140)
        self.analyze_btn.clicked.connect(self.start_analyze)
        ar.addWidget(self.analyze_btn)
        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName('stop')
        self.stop_btn.setMinimumWidth(80)
        self.stop_btn.clicked.connect(self.stop_all)
        self.stop_btn.setEnabled(False)
        ar.addWidget(self.stop_btn)
        ar.addStretch()
        ab = QPushButton('Select All')
        ab.setObjectName('secondary')
        ab.setFixedWidth(80)
        ab.clicked.connect(lambda: self.model.toggle_all(True))
        ar.addWidget(ab)
        nb = QPushButton('Select None')
        nb.setObjectName('secondary')
        nb.setFixedWidth(80)
        nb.clicked.connect(lambda: self.model.toggle_all(False))
        ar.addWidget(nb)
        self.apply_btn = QPushButton('Apply Renames')
        self.apply_btn.setObjectName('apply')
        self.apply_btn.setMinimumWidth(140)
        self.apply_btn.clicked.connect(self.apply_renames)
        ar.addWidget(self.apply_btn)
        layout.addLayout(ar)
    
    def update_speed(self):
        b, w = self.batch_spin.value(), self.workers_spin.value()
        fps = (b * w) / 2.0
        self.speed_lbl.setText(f'Est. ~{fps:.0f} func/s | 1K: {1000/fps/60:.1f}m | 10K: {10000/fps/60:.0f}m | 100K: {100000/fps/3600:.1f}h')
    
    def toggle_api(self):
        v = self.api_content.isVisible()
        self.api_content.setVisible(not v)
        self.toggle_btn.setText('Expand' if v else 'Collapse')
    
    def set_preset(self, p):
        presets = {
            'ollama': ('http://localhost:11434/v1/chat/completions','','qwen2.5-coder:14b'),
            'openai': ('https://api.openai.com/v1/chat/completions','','gpt-4o-mini'),
            'claude': ('https://api.anthropic.com/v1/messages','','claude-sonnet-4-20250514'),
            'openrouter': ('https://openrouter.ai/api/v1/chat/completions','','qwen/qwen-2.5-coder-32b-instruct'),
        }
        if p in presets:
            u,k,m = presets[p]
            self.url_edit.setText(u)
            self.model_edit.setText(m)
            if p == 'ollama':
                self.workers_spin.setValue(10)
                self.batch_spin.setValue(20)
            else:
                self.workers_spin.setValue(5)
                self.batch_spin.setValue(15)
            self.add_log(f'Preset applied: {p}', 'ok')
    
    def show_default_prompt(self):
        QMessageBox.information(self, 'Default Prompts', f'Single Function:\n{DEFAULT_PROMPT}\n\n---\n\nBatch:\n{DEFAULT_BATCH_PROMPT}')
    
    def on_click(self, idx):
        if idx.column() == 0:
            f = self.model.get_func(idx.row())
            if f:
                f.checked = not f.checked
                self.model.dataChanged.emit(idx, idx)
    
    def save_cfg(self):
        self.cfg = {
            'api_url': self.url_edit.text().strip(),
            'api_key': self.key_edit.text().strip(),
            'model': self.model_edit.text().strip(),
            'batch_size': self.batch_spin.value(),
            'parallel_workers': self.workers_spin.value(),
            'filter_system': self.filter_sys_cb.isChecked(),
            'filter_empty': self.filter_empty_cb.isChecked(),
            'min_func_size': self.min_size_spin.value(),
            'max_xrefs': self.max_xref_spin.value(),
            'custom_prompt': self.custom_prompt_edit.toPlainText(),
            'use_custom_prompt': self.custom_prompt_cb.isChecked()
        }
        save_config(self.cfg)
        self.add_log('Configuration saved', 'ok')
    
    def add_log(self, msg, lv='info'):
        colors = {'info':'#aaa','ok':'#4ec9b0','err':'#f14c4c','warn':'#dcdcaa'}
        self.log.append(f'<span style="color:{colors.get(lv,"#aaa")}">[{time.strftime("%H:%M:%S")}] {msg}</span>')
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())
    
    def update_count(self):
        v, t = self.model.rowCount(), self.model.total()
        sug = sum(1 for f in self.model.funcs if f.suggested)
        txt = f'{v:,}/{t:,}' if v!=t else f'{t:,}'
        if sug: txt += f' ({sug} suggestions)'
        self.count_lbl.setText(txt)
    
    def test_api(self):
        self.save_cfg()
        if not self.cfg['api_url'] or not self.cfg['model']:
            QMessageBox.warning(self, 'Warning', 'Please enter API URL and Model')
            return
        self.add_log('Testing API connection...', 'info')
        self.status_lbl.setText('Testing...')
        self.test_result = None
        
        def do_test():
            try:
                st = time.time()
                prompt = 'int add(int a, int b){return a+b;}'
                r = ai_request(self.cfg, prompt, 'Reply with only a snake_case function name for this code.')
                self.test_result = (True, r.strip(), time.time()-st)
            except Exception as e:
                self.test_result = (False, str(e), 0)
        
        t = threading.Thread(target=do_test, daemon=True)
        t.start()
        
        def check():
            if self.test_result:
                ok, r, el = self.test_result
                if ok:
                    self.add_log(f'API OK: "{r}" ({el:.2f}s)', 'ok')
                    self.status_lbl.setText(f'API OK ({el:.2f}s)')
                else:
                    self.add_log(f'API Error: {r[:100]}', 'err')
                    self.status_lbl.setText('API Error')
            else:
                QTimer.singleShot(100, check)
        QTimer.singleShot(100, check)
    
    def load_funcs(self):
        self.model.clear()
        self.temp_funcs = []
        self.scanned = 0
        self.is_loading = True
        self.progress.setVisible(True)
        self.progress.setRange(0,0)
        self.status_lbl.setText('Scanning functions...')
        self.load_btn.setEnabled(False)
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.func_iter = iter(idautils.Functions())
        self.load_timer = QTimer(self)
        self.load_timer.timeout.connect(self.load_batch)
        self.load_timer.start(1)
    
    def load_batch(self):
        if not self.is_loading:
            self.finish_load()
            return
        
        min_size = self.min_size_spin.value()
        max_xrefs = self.max_xref_spin.value()
        filter_sys = self.filter_sys_cb.isChecked()
        filter_empty = self.filter_empty_cb.isChecked()
        
        for _ in range(2000):
            try:
                ea = next(self.func_iter)
                self.scanned += 1
                name = idc.get_func_name(ea)
                if not name or not name.startswith('sub_'): continue
                if not is_valid_seg(ea): continue
                if filter_sys and is_sys_func(name): continue
                if filter_empty:
                    sz = get_func_size(ea)
                    if sz < min_size: continue
                    if max_xrefs > 0 and get_xref_count(ea) > max_xrefs: continue
                self.temp_funcs.append(FuncData(ea, name))
            except StopIteration:
                self.finish_load()
                return
        
        if self.scanned % 10000 < 2000:
            self.status_lbl.setText(f'Scanned {self.scanned:,} | Found {len(self.temp_funcs):,}')
    
    def finish_load(self):
        self.is_loading = False
        if self.load_timer:
            self.load_timer.stop()
            self.load_timer = None
        self.model.set_data(self.temp_funcs)
        self.temp_funcs = []
        self.progress.setVisible(False)
        self.update_count()
        self.add_log(f'Loaded {self.model.total():,} functions', 'ok')
        self.status_lbl.setText(f'Loaded {self.model.total():,} functions')
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def load_current(self):
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            name = idc.get_func_name(f.start_ea)
            fd = FuncData(f.start_ea, name)
            fd.code = get_code_fast(f.start_ea)
            fd.strings = get_strings_fast(f.start_ea)
            fd.calls = get_calls_fast(f.start_ea)
            self.model.set_data([fd])
            self.update_count()
            self.add_log(f'Loaded current: {name}', 'ok')
    
    def load_range(self):
        start, ok1 = QInputDialog.getText(self, 'Range', 'Start address (hex):')
        if not ok1: return
        end, ok2 = QInputDialog.getText(self, 'Range', 'End address (hex):')
        if not ok2: return
        try:
            start_ea = int(start, 16)
            end_ea = int(end, 16)
        except:
            QMessageBox.warning(self, 'Error', 'Invalid hex address')
            return
        
        funcs = []
        for ea in idautils.Functions(start_ea, end_ea):
            name = idc.get_func_name(ea)
            if name and name.startswith('sub_'):
                funcs.append(FuncData(ea, name))
        
        self.model.set_data(funcs)
        self.update_count()
        self.add_log(f'Loaded {len(funcs)} functions in range', 'ok')
    
    def get_existing(self):
        ex = set()
        for ea in idautils.Functions():
            n = idc.get_func_name(ea)
            if n and not n.startswith('sub_'): ex.add(n)
        for f in self.model.funcs:
            if f.suggested: ex.add(f.suggested)
        return ex
    
    def get_system_prompt(self, is_batch=False):
        if self.custom_prompt_cb.isChecked() and self.custom_prompt_edit.toPlainText().strip():
            return self.custom_prompt_edit.toPlainText().strip()
        return DEFAULT_BATCH_PROMPT if is_batch else DEFAULT_PROMPT
    
    def start_analyze(self):
        if not self.model.total():
            QMessageBox.warning(self, 'Warning', 'Load functions first')
            return
        self.save_cfg()
        if not self.cfg['api_url'] or not self.cfg['model']:
            QMessageBox.warning(self, 'Warning', 'Please configure API settings')
            return
        
        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return
        
        count = len(items)
        if count > 500:
            choices = []
            for n in [100, 500, 1000, 2000, 5000, 10000, 50000, count]:
                if n <= count:
                    choices.append(str(n) if n < 10000 else f'{n//1000}K')
            choice, ok = QInputDialog.getItem(self, 'Select Count', f'{count:,} functions selected. Analyze how many?', choices, 0, False)
            if not ok: return
            sel = int(choice.replace('K','000'))
            items = items[:sel]
        
        for w in self.workers:
            w.stop()
        self.workers = []
        
        self.existing_names = self.get_existing()
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(items))
        self.progress.setValue(0)
        
        batch_size = self.batch_spin.value()
        num_workers = self.workers_spin.value()
        sys_prompt = self.get_system_prompt(batch_size > 1)
        
        chunk_size = max(1, len(items) // num_workers)
        chunks = [items[i:i+chunk_size] for i in range(0, len(items), chunk_size)]
        
        self.add_log(f'Starting analysis: {len(items):,} functions, {len(chunks)} workers, batch={batch_size}', 'info')
        self.completed = 0
        self.total_items = len(items)
        
        for chunk in chunks:
            worker = AnalyzeWorker(self.cfg, chunk, self.existing_names, sys_prompt, batch_size)
            worker.batch_done.connect(self.on_batch_done)
            worker.progress.connect(self.on_progress)
            worker.finished.connect(self.on_worker_finished)
            worker.log.connect(self.add_log)
            self.workers.append(worker)
            worker.start()
    
    def on_batch_done(self, results):
        indices = []
        for idx, func, name in results:
            if name:
                func.suggested = name
                func.status = 'OK'
                self.existing_names.add(name)
            else:
                func.status = 'Skip'
            indices.append(idx)
        self.model.refresh_rows(indices)
        self.update_count()
    
    def on_progress(self, done, total):
        self.completed += done - getattr(self, '_last_done', 0)
        self._last_done = done
        self.progress.setValue(min(self.completed, self.total_items))
        self.status_lbl.setText(f'Analyzing: {self.completed:,}/{self.total_items:,}')
    
    def on_worker_finished(self, count):
        active = sum(1 for w in self.workers if w.isRunning())
        if active == 0:
            self.finish_analyze()
    
    def finish_analyze(self):
        self.progress.setVisible(False)
        suggestions = sum(1 for f in self.model.funcs if f.suggested)
        self.status_lbl.setText(f'Done: {suggestions:,} suggestions')
        self.add_log(f'Analysis complete: {suggestions:,} suggestions', 'ok')
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.workers = []
        self._last_done = 0
    
    def stop_all(self):
        self.is_loading = False
        if self.load_timer:
            self.load_timer.stop()
            self.load_timer = None
        
        for w in self.workers:
            w.stop()
        
        if self.temp_funcs:
            self.model.set_data(self.temp_funcs)
            self.temp_funcs = []
        
        self.add_log('Stopped', 'warn')
        self.progress.setVisible(False)
        self.update_count()
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def jump_to(self, idx):
        f = self.model.get_func(idx.row())
        if f: idaapi.jumpto(f.ea)
    
    def apply_renames(self):
        items = self.model.get_with_suggestions()
        if not items:
            self.add_log('No functions with suggestions to apply', 'warn')
            return
        
        applied = 0
        indices = []
        for i, f in items:
            if ida_name.set_name(f.ea, f.suggested, ida_name.SN_NOWARN|ida_name.SN_FORCE):
                applied += 1
                f.name = f.suggested
                f.suggested = ''
                f.status = 'Applied'
                f.checked = False
                indices.append(i)
        
        self.model.refresh_rows(indices)
        self.update_count()
        self.add_log(f'Applied {applied:,} renames', 'ok')
        self.status_lbl.setText(f'Applied {applied:,} renames')

class AIRenamePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "AI-powered function renaming"
    help = ""
    wanted_name = "AI Rename Ultra"
    wanted_hotkey = "Ctrl+Shift+R"
    
    def __init__(self): self.dlg = None
    def init(self): return idaapi.PLUGIN_KEEP
    def run(self, arg):
        try: ida_hexrays.init_hexrays_plugin()
        except: pass
        if self.dlg is None or not self.dlg.isVisible():
            self.dlg = AIRenameDialog()
        self.dlg.show()
        self.dlg.raise_()
    def term(self): pass

def PLUGIN_ENTRY():
    return AIRenamePlugin()

if __name__ == '__main__':
    try: _ai_dlg.close()
    except: pass
    _ai_dlg = AIRenameDialog()
    _ai_dlg.show()
