# -*- coding: utf-8 -*-
import idaapi, idautils, idc, ida_hexrays, ida_funcs, ida_name, ida_segment
import json, os, re, time, threading, queue, concurrent.futures

try:
    import requests
    HAS_REQUESTS = True
    SESSION = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=3)
    SESSION.mount('http://', adapter)
    SESSION.mount('https://', adapter)
except ImportError:
    HAS_REQUESTS = False
    SESSION = None

import urllib.request, urllib.error

if idaapi.IDA_SDK_VERSION >= 920:
    from PySide6.QtWidgets import *
    from PySide6.QtGui import QFont
    from PySide6.QtCore import Qt, Signal, QTimer, QAbstractTableModel, QModelIndex
else:
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import QFont
    from PyQt5.QtCore import Qt, QTimer, QAbstractTableModel, QModelIndex
    Signal = __import__('PyQt5.QtCore', fromlist=['pyqtSignal']).pyqtSignal

CONFIG_FILE = os.path.join(idaapi.get_user_idadir(), 'ai_rename_config.json')

STYLES = """
QWidget{background:#1a1a1a;color:#e0e0e0;font:9pt 'Segoe UI'}
QDialog{background:#1a1a1a}
QGroupBox{font-weight:600;border:2px solid #2d2d2d;border-radius:6px;margin-top:16px;padding:12px 8px 8px 8px;background:#212121}
QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 8px;color:#4fc3f7;font-weight:600}
QLineEdit{background:#2d2d2d;border:2px solid #3d3d3d;border-radius:4px;padding:8px 10px;color:#e0e0e0}
QLineEdit:focus{border:2px solid #1e88e5;background:#333}
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
QTextEdit{background:#1e1e1e;border:2px solid #2d2d2d;border-radius:4px;font:8pt 'Consolas';color:#e0e0e0;padding:4px}
QLabel{color:#b0b0b0}
QScrollBar:vertical{background:#2d2d2d;width:12px;border-radius:6px}
QScrollBar::handle:vertical{background:#424242;border-radius:6px;min-height:20px}
QScrollBar::handle:vertical:hover{background:#4fc3f7}
QSpinBox{background:#2d2d2d;border:2px solid #3d3d3d;border-radius:4px;padding:4px 8px;color:#e0e0e0}
QSpinBox:focus{border:2px solid #1e88e5}
"""

SKIP_SEGS = {'.plt','.plt.got','.plt.sec','extern','.extern','.got','.got.plt','.init','.fini','.dynsym','.dynstr','LOAD','.interp','.rela.dyn','.rela.plt','.hash','.gnu.hash','.note','.note.gnu.build-id','.note.ABI-tag'}
SYS_PREFIX = ('__cxa_','__gxx_','__gnu_','__libc_','__ctype_','_GLOBAL_','_init','_fini','_start','atexit','malloc','free','memcpy','memset','strlen','printf','scanf','fprintf','sprintf','operator','std::','boost::','__stack_chk','__security','_security','__report','__except','__imp_','__x86.','__do_global')
SYS_MODULES = ('kernel32.','ntdll.','user32.','advapi32.','msvcrt.','ucrtbase.','ws2_32.','libc.so','libm.so','libpthread','foundation.','corefoundation.','uikit.')

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            c = json.load(open(CONFIG_FILE))
            c.setdefault('batch_size', 15)
            c.setdefault('parallel_workers', 8)
            c.setdefault('filter_system', True)
            c.setdefault('filter_empty', True)
            c.setdefault('min_func_size', 10)
            c.setdefault('max_xrefs', 100)
            return c
    except: pass
    return {'api_url':'','api_key':'','model':'','batch_size':15,'parallel_workers':8,'filter_system':True,'filter_empty':True,'min_func_size':10,'max_xrefs':100}

def save_config(c):
    try: json.dump(c, open(CONFIG_FILE,'w'))
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

def get_code_fast(ea, max_len=1500):
    try:
        cf = ida_hexrays.decompile(ea)
        if cf: return str(cf)[:max_len]
    except: pass
    f = ida_funcs.get_func(ea)
    if not f: return None
    lines = []
    cur = f.start_ea
    while cur < f.end_ea and len(lines) < 30:
        lines.append(idc.GetDisasm(cur))
        cur = idc.next_head(cur, f.end_ea)
    return '\n'.join(lines)[:max_len]

def get_strings_fast(ea):
    r = []
    try:
        for item in idautils.FuncItems(ea):
            for xref in idautils.DataRefsFrom(item):
                s = idc.get_strlit_contents(xref)
                if s:
                    try:
                        s = s.decode() if isinstance(s, bytes) else s
                        if 2 < len(s) < 80: r.append(s)
                    except: pass
            if len(r) >= 5: break
    except: pass
    return list(set(r))[:5]

def get_calls_fast(ea):
    r = []
    try:
        for item in idautils.FuncItems(ea):
            for xref in idautils.CodeRefsFrom(item, False):
                n = idc.get_func_name(xref)
                if n and not n.startswith('sub_'): r.append(n)
            if len(r) >= 6: break
    except: pass
    return list(set(r))[:6]

def ai_request(cfg, prompt):
    url, key, model = cfg['api_url'], cfg['api_key'], cfg['model']
    hdrs = {'Content-Type': 'application/json'}
    is_ollama = 'localhost:11434' in url or '127.0.0.1:11434' in url
    is_anthropic = 'anthropic.com' in url
    is_ollama_native = is_ollama and '/api/' in url
    
    sys_prompt = 'You are a reverse engineer. Reply with ONLY unique snake_case function names, one per line. No explanations.'
    
    if is_ollama_native:
        data = {'model':model,'messages':[{'role':'system','content':sys_prompt},{'role':'user','content':prompt}],'stream':False}
    elif is_anthropic:
        hdrs['x-api-key'] = key
        hdrs['anthropic-version'] = '2023-06-01'
        data = {'model':model,'max_tokens':300,'messages':[{'role':'user','content':sys_prompt+'\n\n'+prompt}]}
    else:
        if key: hdrs['Authorization'] = f'Bearer {key}'
        data = {'model':model,'messages':[{'role':'system','content':sys_prompt},{'role':'user','content':prompt}],'max_tokens':300,'temperature':0.1}
    
    if HAS_REQUESTS and SESSION:
        r = SESSION.post(url, headers=hdrs, json=data, timeout=180)
        r.raise_for_status()
        res = r.json()
    else:
        req = urllib.request.Request(url, json.dumps(data).encode(), hdrs)
        with urllib.request.urlopen(req, timeout=180) as r:
            res = json.loads(r.read().decode())
    
    if is_ollama_native: return res.get('message',{}).get('content','').strip()
    elif is_anthropic: return res['content'][0]['text'].strip()
    return res['choices'][0]['message']['content'].strip()

def clean_name(name, existing=None):
    if not name: return None
    name = re.sub(r'[`"\'\n]', '', name)
    name = name.split('(')[0].split(':')[-1].strip()
    m = re.search(r'\b([a-z][a-z0-9_]*[a-z0-9])\b', name.lower())
    name = m.group(1) if m else re.sub(r'_+', '_', re.sub(r'[^a-zA-Z0-9_]', '_', name)).strip('_').lower()
    name = re.sub(r'^[0-9]+', '', name)[:55]
    if not name or len(name) < 2: return None
    if existing:
        orig, cnt = name, 1
        while name in existing:
            name = f"{orig}_{cnt}"
            cnt += 1
            if cnt > 50: return None
    return name

class FuncData:
    __slots__ = ['ea','name','suggested','status','checked','code','strings','calls']
    def __init__(self, ea, name):
        self.ea, self.name, self.suggested, self.status, self.checked = ea, name, '', 'Pending', True
        self.code = self.strings = self.calls = None

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
            self.filtered = [i for i,f in enumerate(self.funcs) if ft in f.name.lower() or ft in f'{f.ea:x}']
    
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
            if c==0: return '[X]' if f.checked else '[ ]'
            elif c==1: return f'{f.ea:X}'
            elif c==2: return f.name
            elif c==3: return f.suggested
            elif c==4: return f.status
        elif role == Qt.TextAlignmentRole and c==0: return Qt.AlignCenter
        return None
    
    def flags(self, idx): return Qt.ItemIsEnabled | Qt.ItemIsSelectable
    def get_func(self, row): return self.funcs[self.filtered[row]] if 0<=row<len(self.filtered) else None
    def refresh_row(self, idx):
        if idx in self.filtered:
            row = self.filtered.index(idx)
            self.dataChanged.emit(self.index(row,0), self.index(row,4))
    def toggle_all(self, chk):
        for f in self.funcs: f.checked = chk
        if self.filtered: self.dataChanged.emit(self.index(0,0), self.index(len(self.filtered)-1,0))
    def get_checked(self): return [(i,f) for i,f in enumerate(self.funcs) if f.checked]
    def total(self): return len(self.funcs)

class AIRenameDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.model = None
        self.is_loading = self.is_analyzing = False
        self.load_timer = self.analyze_timer = None
        self.func_iter = None
        self.temp_funcs = []
        self.scanned = 0
        self.analyze_queue = []
        self.analyze_idx = 0
        self.workers = {}
        self.active_workers = 0
        self.existing_names = set()
        self.code_cache = {}
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle('AI Rename Ultra v5.0 - 200K Functions')
        self.setMinimumSize(1100, 800)
        self.setStyleSheet(STYLES)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(10,10,10,10)
        
        api = QGroupBox('API')
        al = QVBoxLayout(api)
        al.setSpacing(8)
        
        pr = QHBoxLayout()
        for n,p in [('Ollama','ollama'),('OpenAI','openai'),('Claude','claude'),('OpenRouter','openrouter')]:
            b = QPushButton(n)
            b.setObjectName('preset')
            b.clicked.connect(lambda c,x=p: self.set_preset(x))
            pr.addWidget(b)
        pr.addStretch()
        al.addLayout(pr)
        
        gl = QGridLayout()
        gl.setSpacing(8)
        self.url_edit = QLineEdit(self.cfg.get('api_url',''))
        self.url_edit.setPlaceholderText('http://localhost:11434/v1/chat/completions')
        self.key_edit = QLineEdit(self.cfg.get('api_key',''))
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText('Optional for Ollama')
        self.model_edit = QLineEdit(self.cfg.get('model',''))
        self.model_edit.setPlaceholderText('qwen2.5-coder:14b')
        gl.addWidget(QLabel('URL:'),0,0)
        gl.addWidget(self.url_edit,0,1)
        gl.addWidget(QLabel('Key:'),1,0)
        gl.addWidget(self.key_edit,1,1)
        gl.addWidget(QLabel('Model:'),2,0)
        gl.addWidget(self.model_edit,2,1)
        al.addLayout(gl)
        
        br = QHBoxLayout()
        sb = QPushButton('Save')
        sb.clicked.connect(self.save_cfg)
        br.addWidget(sb)
        tb = QPushButton('Test')
        tb.clicked.connect(self.test_api)
        br.addWidget(tb)
        br.addStretch()
        self.toggle_btn = QPushButton('Hide')
        self.toggle_btn.setObjectName('secondary')
        self.toggle_btn.clicked.connect(self.toggle_api)
        br.addWidget(self.toggle_btn)
        al.addLayout(br)
        layout.addWidget(api)
        self.api_group = api
        
        perf = QGroupBox('Performance (200K Mode)')
        pl = QGridLayout(perf)
        pl.setSpacing(8)
        
        self.batch_spin = QSpinBox()
        self.batch_spin.setRange(1,50)
        self.batch_spin.setValue(self.cfg.get('batch_size',15))
        self.batch_spin.setToolTip('Functions per API call (15-30 recommended)')
        pl.addWidget(QLabel('Batch:'),0,0)
        pl.addWidget(self.batch_spin,0,1)
        
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1,20)
        self.workers_spin.setValue(self.cfg.get('parallel_workers',8))
        self.workers_spin.setToolTip('Parallel API requests (8-15 recommended)')
        pl.addWidget(QLabel('Workers:'),0,2)
        pl.addWidget(self.workers_spin,0,3)
        
        self.min_size_spin = QSpinBox()
        self.min_size_spin.setRange(0,1000)
        self.min_size_spin.setValue(self.cfg.get('min_func_size',10))
        self.min_size_spin.setToolTip('Skip functions smaller than N bytes')
        pl.addWidget(QLabel('Min Size:'),0,4)
        pl.addWidget(self.min_size_spin,0,5)
        
        self.max_xref_spin = QSpinBox()
        self.max_xref_spin.setRange(0,500)
        self.max_xref_spin.setValue(self.cfg.get('max_xrefs',100))
        self.max_xref_spin.setToolTip('Skip functions with >N xrefs (likely stdlib)')
        pl.addWidget(QLabel('Max XRefs:'),0,6)
        pl.addWidget(self.max_xref_spin,0,7)
        
        self.speed_lbl = QLabel('')
        self.speed_lbl.setStyleSheet('color:#4fc3f7;font-style:italic')
        self.batch_spin.valueChanged.connect(self.update_speed)
        self.workers_spin.valueChanged.connect(self.update_speed)
        self.update_speed()
        pl.addWidget(self.speed_lbl,1,0,1,8)
        layout.addWidget(perf)
        self.perf_group = perf
        
        filt = QGroupBox('Smart Filter')
        fl = QHBoxLayout(filt)
        self.filter_sys_cb = QCheckBox('Skip System')
        self.filter_sys_cb.setChecked(self.cfg.get('filter_system',True))
        fl.addWidget(self.filter_sys_cb)
        self.filter_empty_cb = QCheckBox('Skip Empty/Tiny')
        self.filter_empty_cb.setChecked(self.cfg.get('filter_empty',True))
        fl.addWidget(self.filter_empty_cb)
        self.preload_cb = QCheckBox('Preload Code (RAM↑ Speed↑)')
        self.preload_cb.setChecked(True)
        fl.addWidget(self.preload_cb)
        fl.addStretch()
        layout.addWidget(filt)
        
        tb = QHBoxLayout()
        self.load_btn = QPushButton('Load All sub_*')
        self.load_btn.clicked.connect(self.load_funcs)
        tb.addWidget(self.load_btn)
        lb = QPushButton('Current')
        lb.setObjectName('secondary')
        lb.clicked.connect(self.load_current)
        tb.addWidget(lb)
        tb.addWidget(QLabel('|'))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Filter...')
        self.filter_edit.setFixedWidth(180)
        self.filter_edit.textChanged.connect(lambda t: self.model.set_filter(t) or self.update_count())
        tb.addWidget(self.filter_edit)
        tb.addStretch()
        self.count_lbl = QLabel('0')
        self.count_lbl.setStyleSheet('color:#4fc3f7;font-weight:600;font-size:10pt')
        tb.addWidget(self.count_lbl)
        layout.addLayout(tb)
        
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.doubleClicked.connect(self.jump_to)
        self.table.clicked.connect(self.on_click)
        self.table.setShowGrid(False)
        self.table.setColumnWidth(0,40)
        self.table.setColumnWidth(1,100)
        self.table.setColumnWidth(4,80)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        layout.addWidget(self.table)
        
        pl = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(22)
        pl.addWidget(self.progress)
        self.status_lbl = QLabel('')
        self.status_lbl.setStyleSheet('color:#4fc3f7;font-weight:600')
        self.status_lbl.setMinimumWidth(200)
        pl.addWidget(self.status_lbl)
        layout.addLayout(pl)
        
        ll = QHBoxLayout()
        ll.addWidget(QLabel('Log:'))
        ll.addStretch()
        cb = QPushButton('Clear')
        cb.setObjectName('secondary')
        cb.setFixedWidth(80)
        cb.clicked.connect(lambda: self.log.clear())
        ll.addWidget(cb)
        layout.addLayout(ll)
        
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(90)
        layout.addWidget(self.log)
        self.add_log(f'HTTP: {"requests+pool" if HAS_REQUESTS else "urllib"}', 'info')
        
        ar = QHBoxLayout()
        self.analyze_btn = QPushButton('Analyze')
        self.analyze_btn.setMinimumWidth(120)
        self.analyze_btn.clicked.connect(self.start_analyze)
        ar.addWidget(self.analyze_btn)
        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName('stop')
        self.stop_btn.setMinimumWidth(80)
        self.stop_btn.clicked.connect(self.stop_all)
        self.stop_btn.setEnabled(False)
        ar.addWidget(self.stop_btn)
        ar.addStretch()
        ab = QPushButton('All')
        ab.setObjectName('secondary')
        ab.setFixedWidth(50)
        ab.clicked.connect(lambda: self.model.toggle_all(True))
        ar.addWidget(ab)
        nb = QPushButton('None')
        nb.setObjectName('secondary')
        nb.setFixedWidth(50)
        nb.clicked.connect(lambda: self.model.toggle_all(False))
        ar.addWidget(nb)
        self.apply_btn = QPushButton('Apply')
        self.apply_btn.setObjectName('apply')
        self.apply_btn.setMinimumWidth(120)
        self.apply_btn.clicked.connect(self.apply_renames)
        self.apply_btn.setEnabled(False)
        ar.addWidget(self.apply_btn)
        layout.addLayout(ar)
    
    def update_speed(self):
        b, w = self.batch_spin.value(), self.workers_spin.value()
        fps = (b * w) / 2.5
        t100 = 100/fps
        t1k = 1000/fps
        t10k = 10000/fps
        t200k = 200000/fps
        self.speed_lbl.setText(f'~{fps:.0f} func/s | 1K:{t1k/60:.0f}m | 10K:{t10k/60:.0f}m | 200K:{t200k/3600:.1f}h')
    
    def toggle_api(self):
        v = self.api_group.isVisible()
        self.api_group.setVisible(not v)
        self.perf_group.setVisible(not v)
        self.toggle_btn.setText('Show' if v else 'Hide')
    
    def set_preset(self, p):
        presets = {
            'ollama': ('http://localhost:11434/v1/chat/completions','','qwen2.5-coder:14b'),
            'openai': ('https://api.openai.com/v1/chat/completions','','gpt-4o-mini'),
            'claude': ('https://api.anthropic.com/v1/messages','','claude-sonnet-4-20250514'),
            'openrouter': ('https://openrouter.ai/api/v1/chat/completions','','openai/gpt-4o-mini'),
        }
        if p in presets:
            u,k,m = presets[p]
            self.url_edit.setText(u)
            self.model_edit.setText(m)
            self.add_log(f'Preset: {p}', 'ok')
    
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
            'max_xrefs': self.max_xref_spin.value()
        }
        save_config(self.cfg)
        self.add_log('Saved', 'ok')
    
    def add_log(self, msg, lv='info'):
        colors = {'info':'#aaa','ok':'#4ec9b0','err':'#f14c4c','warn':'#dcdcaa'}
        self.log.append(f'<span style="color:{colors.get(lv,"#aaa")}">[{time.strftime("%H:%M:%S")}] {msg}</span>')
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())
    
    def update_count(self):
        v, t = self.model.rowCount(), self.model.total()
        self.count_lbl.setText(f'{v:,}/{t:,}' if v!=t else f'{t:,}')
    
    def test_api(self):
        self.save_cfg()
        if not self.cfg['api_url'] or not self.cfg['model']:
            QMessageBox.warning(self, 'Warning', 'Enter URL & Model')
            return
        self.add_log('Testing...', 'info')
        self.status_lbl.setText('Testing...')
        self.test_result = None
        def do_test():
            try:
                st = time.time()
                r = ai_request(self.cfg, 'int add(int a, int b){return a+b;}\nName?')
                self.test_result = (True, r, time.time()-st)
            except Exception as e:
                self.test_result = (False, str(e), 0)
        t = threading.Thread(target=do_test, daemon=True)
        t.start()
        def check():
            if self.test_result:
                ok, r, el = self.test_result
                if ok:
                    self.add_log(f'OK: "{r}" ({el:.1f}s)', 'ok')
                    self.status_lbl.setText(f'OK ({el:.1f}s)')
                else:
                    self.add_log(f'Error: {r}', 'err')
                    self.status_lbl.setText('Error')
            else:
                QTimer.singleShot(100, check)
        QTimer.singleShot(100, check)
    
    def load_funcs(self):
        self.model.clear()
        self.temp_funcs = []
        self.scanned = 0
        self.is_loading = True
        self.code_cache = {}
        self.progress.setVisible(True)
        self.progress.setRange(0,0)
        self.status_lbl.setText('Scanning...')
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
        preload = self.preload_cb.isChecked()
        
        for _ in range(1000):
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
                fd = FuncData(ea, name)
                if preload:
                    fd.code = get_code_fast(ea, 800)
                    if not fd.code: continue
                    fd.strings = get_strings_fast(ea)
                    fd.calls = get_calls_fast(ea)
                self.temp_funcs.append(fd)
            except StopIteration:
                self.finish_load()
                return
        self.status_lbl.setText(f'Scanned {self.scanned:,} | Found {len(self.temp_funcs):,}')
    
    def finish_load(self):
        self.is_loading = False
        if self.load_timer: self.load_timer.stop()
        self.model.set_data(self.temp_funcs)
        self.temp_funcs = []
        self.progress.setVisible(False)
        self.update_count()
        self.add_log(f'Loaded {self.model.total():,}', 'ok')
        self.status_lbl.setText(f'Loaded {self.model.total():,}')
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
            self.add_log(f'Loaded: {name}', 'ok')
    
    def get_existing(self):
        ex = set()
        for ea in idautils.Functions():
            n = idc.get_func_name(ea)
            if n and not n.startswith('sub_'): ex.add(n)
        for f in self.model.funcs:
            if f.suggested: ex.add(f.suggested)
        return ex
    
    def start_analyze(self):
        if not self.model.total():
            QMessageBox.warning(self, 'Warning', 'Load functions first')
            return
        self.save_cfg()
        if not self.cfg['api_url'] or not self.cfg['model']:
            QMessageBox.warning(self, 'Warning', 'Enter API URL and Model')
            return
        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return
        
        if len(items) > 100:
            msg = QMessageBox(self)
            msg.setWindowTitle('Select Count')
            msg.setText(f'{len(items):,} functions. How many?')
            btns = [(100,'100'),(500,'500'),(1000,'1K'),(5000,'5K'),(10000,'10K'),(50000,'50K'),(len(items),f'All {len(items):,}')]
            created = []
            for cnt,txt in btns:
                if cnt <= len(items):
                    b = msg.addButton(txt, QMessageBox.ActionRole)
                    created.append((b,cnt))
            msg.addButton('Cancel', QMessageBox.RejectRole)
            msg.exec_()
            clicked = msg.clickedButton()
            sel = None
            for b,c in created:
                if b == clicked: sel = c; break
            if sel is None: return
            items = items[:sel]
        
        self.analyze_queue = items
        self.analyze_idx = 0
        self.is_analyzing = True
        self.workers = {}
        self.active_workers = 0
        self.existing_names = self.get_existing()
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.apply_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(items))
        self.progress.setValue(0)
        self.add_log(f'Analyzing {len(items):,} (batch={self.batch_spin.value()}, workers={self.workers_spin.value()})...', 'info')
        self.analyze_timer = QTimer(self)
        self.analyze_timer.timeout.connect(self.analyze_tick)
        self.analyze_timer.start(30)
    
    def analyze_tick(self):
        if not self.is_analyzing:
            self.finish_analyze()
            return
        
        for wid in list(self.workers.keys()):
            w = self.workers[wid]
            if w.get('done'):
                for idx, func, suggested, err, el in w['results']:
                    if suggested:
                        func.suggested = suggested
                        func.status = 'OK'
                        self.existing_names.add(suggested)
                    else:
                        func.status = 'ERR' if err else 'SKIP'
                        func.checked = False
                    self.model.refresh_row(idx)
                self.progress.setValue(self.progress.value() + len(w['results']))
                self.active_workers -= 1
                del self.workers[wid]
        
        queued = sum(len(w.get('batch',[])) for w in self.workers.values() if not w.get('done'))
        start_idx = self.analyze_idx + queued
        
        if start_idx >= len(self.analyze_queue) and self.active_workers == 0:
            self.finish_analyze()
            return
        
        batch_size = self.batch_spin.value()
        max_workers = self.workers_spin.value()
        
        while self.active_workers < max_workers and start_idx < len(self.analyze_queue):
            batch = []
            for i in range(batch_size):
                if start_idx + i >= len(self.analyze_queue): break
                idx, func = self.analyze_queue[start_idx + i]
                if not func.code:
                    func.code = get_code_fast(func.ea, 800)
                    func.strings = get_strings_fast(func.ea)
                    func.calls = get_calls_fast(func.ea)
                batch.append((idx, func))
            
            if not batch: break
            
            wid = f'w{len(self.workers)}'
            self.workers[wid] = {'done':False,'batch':batch,'results':[]}
            self.active_workers += 1
            start_idx += len(batch)
            self.analyze_idx += len(batch)
            
            self.status_lbl.setText(f'{self.progress.value()}/{len(self.analyze_queue)} [{self.active_workers}w]')
            
            existing_copy = set(self.existing_names)
            t = threading.Thread(target=self.worker_run, args=(wid, batch, existing_copy), daemon=True)
            t.start()
    
    def worker_run(self, wid, batch, existing):
        results = []
        try:
            valid = [(idx,f) for idx,f in batch if f.code]
            if not valid:
                for idx,f in batch:
                    results.append((idx, f, None, 'No code', 0))
            elif len(valid) == 1:
                idx, f = valid[0]
                st = time.time()
                prompt = f"```\n{f.code}\n```\n"
                if f.strings: prompt += f"Strings: {f.strings}\n"
                if f.calls: prompt += f"Calls: {f.calls}\n"
                prompt += "Function name?"
                resp = ai_request(self.cfg, prompt)
                name = clean_name(resp, existing)
                results.append((idx, f, name, None, time.time()-st))
            else:
                st = time.time()
                prompt = "Name these functions (snake_case, one per line):\n\n"
                for i,(idx,f) in enumerate(valid):
                    prompt += f"{i+1}. ```\n{f.code[:500]}\n```\n"
                    if f.strings: prompt += f"   Strings: {f.strings[:3]}\n"
                prompt += f"\nProvide {len(valid)} unique names:"
                
                resp = ai_request(self.cfg, prompt)
                names = []
                for line in resp.split('\n'):
                    line = line.strip()
                    if line and len(line)<60 and ':' not in line and '```' not in line:
                        parts = line.split()
                        if parts:
                            nm = parts[-1] if len(parts)>1 and parts[0].replace('.','').isdigit() else parts[0]
                            if 2<=len(nm)<=55: names.append(nm)
                
                el = time.time() - st
                avg = el / len(valid)
                for i,(idx,f) in enumerate(valid):
                    nm = clean_name(names[i], existing) if i<len(names) else None
                    if nm: existing.add(nm)
                    results.append((idx, f, nm, None, avg))
        except Exception as e:
            for idx,f in batch:
                results.append((idx, f, None, str(e)[:50], 0))
        
        self.workers[wid]['results'] = results
        self.workers[wid]['done'] = True
    
    def finish_analyze(self):
        self.is_analyzing = False
        if self.analyze_timer: self.analyze_timer.stop()
        self.progress.setVisible(False)
        done = sum(1 for f in self.model.funcs if f.suggested)
        self.status_lbl.setText(f'Done: {done} suggestions')
        self.add_log(f'Complete: {done} suggestions', 'ok')
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.apply_btn.setEnabled(True)
    
    def stop_all(self):
        self.is_loading = self.is_analyzing = False
        if self.load_timer: self.load_timer.stop()
        if self.analyze_timer: self.analyze_timer.stop()
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
        applied = 0
        for i,f in self.model.get_checked():
            if f.suggested:
                if ida_name.set_name(f.ea, f.suggested, ida_name.SN_NOWARN|ida_name.SN_FORCE):
                    applied += 1
                    f.name = f.suggested
                    f.suggested = ''
                    f.status = 'Applied'
                    self.model.refresh_row(i)
        self.add_log(f'Applied {applied}', 'ok')
        QMessageBox.information(self, 'Done', f'Applied {applied} renames')

class AIRenamePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "AI function renaming"
    help = ""
    wanted_name = "AI Rename"
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
