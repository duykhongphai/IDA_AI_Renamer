# -*- coding: utf-8 -*-
"""
AI Function Renamer for IDA Pro
Version: 4.2 - Fixed Ollama support
"""

import idaapi
import idautils
import idc
import ida_hexrays
import ida_funcs
import ida_name
import json
import os
import re
import time
import threading

# Try requests, fallback to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

import urllib.request
import urllib.error

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
QWidget { 
    background-color: #1a1a1a; 
    color: #e0e0e0; 
    font-size: 9pt;
    font-family: 'Segoe UI', Arial, sans-serif;
}

QDialog {
    background-color: #1a1a1a;
}

/* GroupBox Styling */
QGroupBox { 
    font-weight: 600; 
    border: 2px solid #2d2d2d; 
    border-radius: 6px; 
    margin-top: 16px; 
    padding: 12px 8px 8px 8px;
    background-color: #212121;
}
QGroupBox::title { 
    subcontrol-origin: margin;
    left: 12px; 
    padding: 0 8px;
    color: #4fc3f7;
    font-size: 9pt;
    font-weight: 600;
}

/* Input Fields */
QLineEdit { 
    background-color: #2d2d2d; 
    border: 2px solid #3d3d3d; 
    border-radius: 4px; 
    padding: 8px 10px;
    color: #e0e0e0;
    selection-background-color: #0d47a1;
}
QLineEdit:focus { 
    border: 2px solid #1e88e5;
    background-color: #333333;
}
QLineEdit:disabled {
    background-color: #252525;
    color: #666666;
}

/* Button Styling */
QPushButton { 
    background-color: #1e88e5; 
    color: white; 
    border: none; 
    border-radius: 4px; 
    padding: 8px 16px;
    font-weight: 600;
    font-size: 9pt;
}
QPushButton:hover { 
    background-color: #2196f3;
}
QPushButton:pressed {
    background-color: #1565c0;
}
QPushButton:disabled { 
    background-color: #2d2d2d; 
    color: #666666;
}

/* Specific Button Types */
QPushButton#stop { 
    background-color: #d32f2f;
}
QPushButton#stop:hover { 
    background-color: #e53935;
}

QPushButton#apply { 
    background-color: #388e3c;
}
QPushButton#apply:hover { 
    background-color: #43a047;
}

QPushButton#preset { 
    background-color: #2d2d2d; 
    border: 1px solid #3d3d3d; 
    padding: 6px 12px;
    font-weight: normal;
}
QPushButton#preset:hover { 
    background-color: #3d3d3d; 
    border: 1px solid #1e88e5;
}

QPushButton#secondary {
    background-color: #424242;
    font-weight: normal;
}
QPushButton#secondary:hover {
    background-color: #505050;
}

/* Table Styling */
QTableView { 
    background-color: #1e1e1e; 
    alternate-background-color: #242424; 
    border: 2px solid #2d2d2d;
    border-radius: 4px;
    gridline-color: #2d2d2d;
    selection-background-color: #1565c0;
}
QTableView::item { 
    padding: 4px;
}
QTableView::item:selected { 
    background-color: #1565c0;
    color: white;
}
QTableView::item:hover {
    background-color: #2d2d2d;
}

QHeaderView::section { 
    background-color: #252525; 
    padding: 8px 6px;
    border: none;
    border-right: 1px solid #2d2d2d;
    border-bottom: 2px solid #1e88e5;
    font-weight: 600;
    color: #4fc3f7;
}

/* Progress Bar */
QProgressBar { 
    border: 2px solid #2d2d2d; 
    border-radius: 4px; 
    text-align: center; 
    background: #2d2d2d;
    color: white;
    font-weight: 600;
}
QProgressBar::chunk { 
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                stop:0 #1e88e5, stop:1 #42a5f5);
    border-radius: 2px;
}

/* Text Edit / Log */
QTextEdit { 
    background-color: #1e1e1e; 
    border: 2px solid #2d2d2d;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt;
    color: #e0e0e0;
    padding: 4px;
}

/* Labels */
QLabel {
    color: #b0b0b0;
}

/* Scrollbar */
QScrollBar:vertical {
    background: #2d2d2d;
    width: 12px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #424242;
    border-radius: 6px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #4fc3f7;
}

QScrollBar:horizontal {
    background: #2d2d2d;
    height: 12px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #424242;
    border-radius: 6px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover {
    background: #4fc3f7;
}

/* Tooltip */
QToolTip {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #1e88e5;
    border-radius: 4px;
    padding: 4px;
}
"""

SKIP_SEGMENTS = {
    '.plt', '.plt.got', '.plt.sec', 'extern', '.extern', 
    '.got', '.got.plt', '.init', '.fini', '.dynsym', '.dynstr',
    'LOAD', '.interp', '.rela.dyn', '.rela.plt', '.hash', '.gnu.hash',
    '.note', '.note.gnu.build-id', '.note.ABI-tag',
}


def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                # Set defaults for new config options
                cfg.setdefault('batch_size', 5)
                cfg.setdefault('parallel_workers', 3)
                return cfg
    except:
        pass
    return {'api_url': '', 'api_key': '', 'model': '', 'batch_size': 5, 'parallel_workers': 3}


def save_config(cfg):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(cfg, f)
    except:
        pass


def is_valid_segment(ea):
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    seg_name = idaapi.get_segm_name(seg)
    if not seg_name or seg_name in SKIP_SEGMENTS:
        return False
    if seg_name.startswith('.text') or seg_name in ('CODE', '.code'):
        return True
    if '.' not in seg_name and seg.perm & idaapi.SEGPERM_EXEC:
        return True
    return False


def get_code(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)[:3000]
    except:
        pass
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    lines = []
    cur = func.start_ea
    while cur < func.end_ea and len(lines) < 50:
        lines.append(idc.GetDisasm(cur))
        cur = idc.next_head(cur, func.end_ea)
    return '\n'.join(lines)


def get_strings(ea):
    result = []
    try:
        for item in idautils.FuncItems(ea):
            for xref in idautils.DataRefsFrom(item):
                s = idc.get_strlit_contents(xref)
                if s:
                    try:
                        s = s.decode() if isinstance(s, bytes) else s
                        if 2 < len(s) < 100:
                            result.append(s)
                    except:
                        pass
    except:
        pass
    return list(set(result))[:8]


def get_calls(ea):
    result = []
    try:
        for item in idautils.FuncItems(ea):
            for xref in idautils.CodeRefsFrom(item, False):
                name = idc.get_func_name(xref)
                if name and not name.startswith('sub_'):
                    result.append(name)
    except:
        pass
    return list(set(result))[:10]


def ai_request(cfg, prompt, existing_names=None):
    """Make AI API request with context about existing names"""
    url = cfg['api_url']
    headers = {'Content-Type': 'application/json'}
    
    # Detect API type
    is_ollama = 'localhost:11434' in url or '127.0.0.1:11434' in url
    is_anthropic = 'anthropic.com' in url
    is_ollama_native = is_ollama and '/api/' in url  # Native /api/chat endpoint
    
    system_prompt = '''You are a reverse engineer analyzing binary code.
Suggest descriptive function names based on code behavior.
IMPORTANT RULES:
- Reply with ONLY function names in snake_case, one per line
- Each name must be UNIQUE and NOT conflict with existing functions
- Use descriptive prefixes: process_, handle_, init_, check_, get_, set_, validate_, etc.
- DO NOT use generic names like: func, function, sub, routine, etc.
- If analyzing multiple functions, provide one name per function in order'''
    
    if is_ollama_native:
        # Native Ollama /api/chat
        data = {
            'model': cfg['model'],
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            'stream': False
        }
    elif is_anthropic:
        headers['x-api-key'] = cfg['api_key']
        headers['anthropic-version'] = '2023-06-01'
        data = {
            'model': cfg['model'],
            'max_tokens': 150,
            'messages': [{'role': 'user', 'content': system_prompt + '\n\n' + prompt}]
        }
    else:
        # OpenAI-compatible (includes Ollama /v1/chat/completions)
        if cfg['api_key']:
            headers['Authorization'] = f"Bearer {cfg['api_key']}"
        data = {
            'model': cfg['model'],
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 150,
            'temperature': 0.2
        }
    
    # Make request
    json_data = json.dumps(data).encode('utf-8')
    
    if HAS_REQUESTS:
        r = requests.post(url, headers=headers, json=data, timeout=120)
        r.raise_for_status()
        res = r.json()
    else:
        req = urllib.request.Request(url, json_data, headers)
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.loads(r.read().decode('utf-8'))
    
    # Parse response
    if is_ollama_native:
        # Native Ollama /api/chat response
        return res.get('message', {}).get('content', '').strip()
    elif is_anthropic:
        return res['content'][0]['text'].strip()
    else:
        # OpenAI-compatible (includes Ollama /v1/chat/completions)
        return res['choices'][0]['message']['content'].strip()


def clean_name(name, existing_names=None):
    """Clean and validate function name, ensuring uniqueness"""
    if not name:
        return None
    
    # Extract just the function name
    name = re.sub(r'[`"\'\n]', '', name)
    name = name.split('(')[0].split(':')[-1].strip()
    
    # Find snake_case word
    match = re.search(r'\b([a-z][a-z0-9_]*[a-z0-9])\b', name.lower())
    if match:
        name = match.group(1)
    else:
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        name = re.sub(r'_+', '_', name).strip('_').lower()
    
    # Remove leading numbers
    name = re.sub(r'^[0-9]+', '', name)
    
    # Truncate if too long
    name = name[:60] if len(name) >= 2 else None
    
    if not name:
        return None
    
    # Check for duplicates and add suffix if needed
    if existing_names:
        original_name = name
        counter = 1
        while name in existing_names:
            name = f"{original_name}_{counter}"
            counter += 1
            if counter > 100:  # Safety limit
                return None
    
    return name


class FuncData:
    __slots__ = ['ea', 'name', 'suggested', 'status', 'checked']
    def __init__(self, ea, name):
        self.ea = ea
        self.name = name
        self.suggested = ''
        self.status = 'Pending'
        self.checked = True


class VirtualFuncModel(QAbstractTableModel):
    HEADERS = ['', 'Address', 'Current', 'Suggested', 'Status']
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.funcs = []
        self.filtered = []
        self.filter_text = ''
    
    def set_data(self, funcs):
        self.beginResetModel()
        self.funcs = funcs
        self._apply_filter()
        self.endResetModel()
    
    def clear(self):
        self.beginResetModel()
        self.funcs = []
        self.filtered = []
        self.endResetModel()
    
    def _apply_filter(self):
        if not self.filter_text:
            self.filtered = list(range(len(self.funcs)))
        else:
            ft = self.filter_text.lower()
            self.filtered = [i for i, f in enumerate(self.funcs) 
                           if ft in f.name.lower() or ft in f'{f.ea:x}']
    
    def set_filter(self, text):
        self.beginResetModel()
        self.filter_text = text
        self._apply_filter()
        self.endResetModel()
    
    def rowCount(self, parent=QModelIndex()):
        return len(self.filtered)
    
    def columnCount(self, parent=QModelIndex()):
        return 5
    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return None
    
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.filtered):
            return None
        func = self.funcs[self.filtered[index.row()]]
        col = index.column()
        if role == Qt.DisplayRole:
            if col == 0: return '[X]' if func.checked else '[ ]'
            elif col == 1: return f'{func.ea:X}'
            elif col == 2: return func.name
            elif col == 3: return func.suggested
            elif col == 4: return func.status
        elif role == Qt.TextAlignmentRole and col == 0:
            return Qt.AlignCenter
        return None
    
    def flags(self, index):
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable
    
    def get_func(self, row):
        if 0 <= row < len(self.filtered):
            return self.funcs[self.filtered[row]]
        return None
    
    def get_func_by_index(self, idx):
        if 0 <= idx < len(self.funcs):
            return self.funcs[idx]
        return None
    
    def refresh_row(self, idx):
        if idx in self.filtered:
            row = self.filtered.index(idx)
            self.dataChanged.emit(self.index(row, 0), self.index(row, 4))
    
    def toggle_all(self, checked):
        for f in self.funcs:
            f.checked = checked
        if self.filtered:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.filtered)-1, 0))
    
    def get_checked_items(self):
        return [(i, f) for i, f in enumerate(self.funcs) if f.checked]
    
    def total_count(self):
        return len(self.funcs)


class AIRenameDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.model = None
        self.load_timer = None
        self.func_iterator = None
        self.temp_funcs = []
        self.scanned_count = 0
        self.is_loading = False
        self.analyze_timer = None
        self.analyze_queue = []
        self.analyze_index = 0
        self.is_analyzing = False
        self.pending_request = False
        self.existing_names = set()  # Track all existing function names
        
        # Performance optimization settings
        self.batch_size = self.cfg.get('batch_size', 5)
        self.parallel_workers = self.cfg.get('parallel_workers', 3)
        self.active_workers = 0
        self.worker_results = {}  # Store results from parallel workers
        
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle('AI Function Renamer v4.2')
        self.setMinimumSize(1000, 750)
        self.setStyleSheet(STYLES)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # ==================== API SETTINGS ====================
        api_group = QGroupBox('API Configuration')
        api_layout = QVBoxLayout(api_group)
        api_layout.setSpacing(10)
        
        # Presets Row
        preset_label = QLabel('Quick Presets:')
        preset_label.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        api_layout.addWidget(preset_label)
        
        preset_row = QHBoxLayout()
        preset_row.setSpacing(8)
        for name, preset in [('Ollama', 'ollama'), ('OpenAI', 'openai'), 
                             ('Claude', 'claude'), ('OpenRouter', 'openrouter')]:
            btn = QPushButton(name)
            btn.setObjectName('preset')
            btn.setToolTip(f'Load {name} preset configuration')
            btn.clicked.connect(lambda c, p=preset: self.set_preset(p))
            preset_row.addWidget(btn)
        preset_row.addStretch()
        api_layout.addLayout(preset_row)
        
        # Separator
        separator = QLabel()
        separator.setFixedHeight(1)
        separator.setStyleSheet('background-color: #2d2d2d;')
        api_layout.addWidget(separator)
        
        # Configuration Grid
        config_grid = QGridLayout()
        config_grid.setSpacing(10)
        config_grid.setColumnStretch(1, 1)
        
        # URL
        url_label = QLabel('API URL:')
        url_label.setStyleSheet('font-weight: 600;')
        self.url_edit = QLineEdit(self.cfg.get('api_url', ''))
        self.url_edit.setPlaceholderText('http://localhost:11434/v1/chat/completions')
        self.url_edit.setToolTip('Enter your API endpoint URL')
        config_grid.addWidget(url_label, 0, 0)
        config_grid.addWidget(self.url_edit, 0, 1)
        
        # API Key
        key_label = QLabel('API Key:')
        key_label.setStyleSheet('font-weight: 600;')
        self.key_edit = QLineEdit(self.cfg.get('api_key', ''))
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText('Optional for local models (Ollama)')
        self.key_edit.setToolTip('Enter your API key (not required for Ollama)')
        config_grid.addWidget(key_label, 1, 0)
        config_grid.addWidget(self.key_edit, 1, 1)
        
        # Model
        model_label = QLabel('Model:')
        model_label.setStyleSheet('font-weight: 600;')
        self.model_edit = QLineEdit(self.cfg.get('model', ''))
        self.model_edit.setPlaceholderText('qwen2.5-coder:7b')
        self.model_edit.setToolTip('Specify the model name')
        config_grid.addWidget(model_label, 2, 0)
        config_grid.addWidget(self.model_edit, 2, 1)
        
        api_layout.addLayout(config_grid)
        
        # API Action Buttons
        api_btn_row = QHBoxLayout()
        api_btn_row.setSpacing(8)
        
        save_btn = QPushButton('Save Configuration')
        save_btn.setToolTip('Save API settings')
        save_btn.clicked.connect(self.save_cfg)
        api_btn_row.addWidget(save_btn)
        
        test_btn = QPushButton('Test Connection')
        test_btn.setToolTip('Test API connection with a sample request')
        test_btn.clicked.connect(self.test_api)
        api_btn_row.addWidget(test_btn)
        
        api_btn_row.addStretch()
        
        # Toggle button for collapsing
        self.toggle_api_btn = QPushButton('Hide Settings')
        self.toggle_api_btn.setObjectName('secondary')
        self.toggle_api_btn.setFixedWidth(120)
        self.toggle_api_btn.clicked.connect(self.toggle_api_settings)
        api_btn_row.addWidget(self.toggle_api_btn)
        
        api_layout.addLayout(api_btn_row)
        
        layout.addWidget(api_group)
        self.api_group = api_group
        
        # ==================== PERFORMANCE SETTINGS ====================
        perf_group = QGroupBox('Performance Settings')
        perf_layout = QGridLayout(perf_group)
        perf_layout.setSpacing(10)
        
        # Batch Size
        batch_label = QLabel('Batch Size:')
        batch_label.setStyleSheet('font-weight: 600;')
        batch_label.setToolTip('Number of functions to analyze in one API request (higher = faster but less accurate)')
        self.batch_spin = QSpinBox()
        self.batch_spin.setRange(1, 20)
        self.batch_spin.setValue(self.batch_size)
        self.batch_spin.setToolTip('1 = Most accurate, slow | 5-10 = Balanced | 10+ = Fastest, less accurate')
        perf_layout.addWidget(batch_label, 0, 0)
        perf_layout.addWidget(self.batch_spin, 0, 1)
        
        # Parallel Workers
        workers_label = QLabel('Parallel Workers:')
        workers_label.setStyleSheet('font-weight: 600;')
        workers_label.setToolTip('Number of simultaneous API requests (higher = faster but more API load)')
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 10)
        self.workers_spin.setValue(self.parallel_workers)
        self.workers_spin.setToolTip('1 = Sequential | 3-5 = Recommended | 10 = Maximum')
        perf_layout.addWidget(workers_label, 0, 2)
        perf_layout.addWidget(self.workers_spin, 0, 3)
        
        # Speed estimate
        self.speed_estimate = QLabel('')
        self.speed_estimate.setStyleSheet('color: #4fc3f7; font-style: italic;')
        self.batch_spin.valueChanged.connect(self.update_speed_estimate)
        self.workers_spin.valueChanged.connect(self.update_speed_estimate)
        perf_layout.addWidget(self.speed_estimate, 1, 0, 1, 4)
        self.update_speed_estimate()
        
        layout.addWidget(perf_group)
        self.perf_group = perf_group
        
        # ==================== TOOLBAR ====================
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        
        # Load Section
        load_section = QHBoxLayout()
        load_section.setSpacing(6)
        
        load_label = QLabel('Load:')
        load_label.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        load_section.addWidget(load_label)
        
        self.load_btn = QPushButton('All sub_* Functions')
        self.load_btn.setToolTip('Scan and load all functions starting with sub_')
        self.load_btn.clicked.connect(self.load_functions)
        load_section.addWidget(self.load_btn)
        
        load_cur = QPushButton('Current Function')
        load_cur.setObjectName('secondary')
        load_cur.setToolTip('Load only the current function at cursor')
        load_cur.clicked.connect(self.load_current)
        load_section.addWidget(load_cur)
        
        toolbar.addLayout(load_section)
        
        # Separator
        toolbar.addWidget(QLabel('|'))
        
        # Filter Section
        filter_label = QLabel('Filter:')
        filter_label.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        toolbar.addWidget(filter_label)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Search by name or address...')
        self.filter_edit.setFixedWidth(200)
        self.filter_edit.textChanged.connect(self.apply_filter)
        toolbar.addWidget(self.filter_edit)
        
        toolbar.addStretch()
        
        # Count Label
        self.count_lbl = QLabel('0 functions')
        self.count_lbl.setStyleSheet('color: #4fc3f7; font-weight: 600; font-size: 10pt;')
        toolbar.addWidget(self.count_lbl)
        
        layout.addLayout(toolbar)
        
        # ==================== TABLE ====================
        table_container = QVBoxLayout()
        table_container.setSpacing(8)
        
        table_label = QLabel('Functions:')
        table_label.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        table_container.addWidget(table_label)
        
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.doubleClicked.connect(self.jump_to)
        self.table.clicked.connect(self.on_cell_clicked)
        self.table.setShowGrid(False)
        
        # Column widths
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(4, 80)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        
        table_container.addWidget(self.table)
        layout.addLayout(table_container)
        
        # ==================== PROGRESS ====================
        progress_layout = QHBoxLayout()
        progress_layout.setSpacing(10)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(24)
        progress_layout.addWidget(self.progress)
        
        self.status_lbl = QLabel('')
        self.status_lbl.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        self.status_lbl.setMinimumWidth(150)
        progress_layout.addWidget(self.status_lbl)
        
        layout.addLayout(progress_layout)
        
        # ==================== LOG ====================
        log_container = QVBoxLayout()
        log_container.setSpacing(6)
        
        log_header = QHBoxLayout()
        log_label = QLabel('Activity Log:')
        log_label.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        log_header.addWidget(log_label)
        log_header.addStretch()
        
        clear_btn = QPushButton('Clear Log')
        clear_btn.setObjectName('secondary')
        clear_btn.setFixedWidth(100)
        clear_btn.clicked.connect(lambda: self.log.clear())
        log_header.addWidget(clear_btn)
        
        log_container.addLayout(log_header)
        
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(100)
        log_container.addWidget(self.log)
        
        layout.addLayout(log_container)
        
        self.add_log(f'Library Status: {("requests" if HAS_REQUESTS else "urllib (fallback)")}', 'info')
        
        # ==================== ACTION BUTTONS ====================
        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        
        # Left side - Main actions
        self.analyze_btn = QPushButton('Analyze Selected')
        self.analyze_btn.setToolTip('Start AI analysis on selected functions')
        self.analyze_btn.setMinimumWidth(140)
        self.analyze_btn.clicked.connect(self.start_analyze)
        action_row.addWidget(self.analyze_btn)
        
        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName('stop')
        self.stop_btn.setToolTip('Stop current operation')
        self.stop_btn.setMinimumWidth(100)
        self.stop_btn.clicked.connect(self.stop_all)
        self.stop_btn.setEnabled(False)
        action_row.addWidget(self.stop_btn)
        
        action_row.addStretch()
        
        # Right side - Selection and apply
        select_label = QLabel('Selection:')
        select_label.setStyleSheet('color: #4fc3f7; font-weight: 600;')
        action_row.addWidget(select_label)
        
        all_btn = QPushButton('All')
        all_btn.setObjectName('secondary')
        all_btn.setToolTip('Select all functions')
        all_btn.setFixedWidth(60)
        all_btn.clicked.connect(lambda: self.model.toggle_all(True))
        action_row.addWidget(all_btn)
        
        none_btn = QPushButton('None')
        none_btn.setObjectName('secondary')
        none_btn.setToolTip('Deselect all functions')
        none_btn.setFixedWidth(60)
        none_btn.clicked.connect(lambda: self.model.toggle_all(False))
        action_row.addWidget(none_btn)
        
        # Apply button
        self.apply_btn = QPushButton('Apply Renames')
        self.apply_btn.setObjectName('apply')
        self.apply_btn.setToolTip('Apply suggested names to selected functions')
        self.apply_btn.setMinimumWidth(140)
        self.apply_btn.clicked.connect(self.apply_renames)
        self.apply_btn.setEnabled(False)
        action_row.addWidget(self.apply_btn)
        
        layout.addLayout(action_row)
    
    def update_speed_estimate(self):
        """Update speed estimate based on current settings"""
        batch = self.batch_spin.value()
        workers = self.workers_spin.value()
        
        # Estimate: 3s per API call (average)
        # With batching: analyze (batch) functions per call
        # With parallel: (workers) calls at once
        
        funcs_per_sec = (batch * workers) / 3.0
        
        # Examples for different scales
        time_100 = 100 / funcs_per_sec
        time_1k = 1000 / funcs_per_sec
        time_10k = 10000 / funcs_per_sec
        
        if time_100 < 60:
            est_100 = f"{time_100:.0f}s"
        else:
            est_100 = f"{time_100/60:.1f}min"
            
        if time_1k < 60:
            est_1k = f"{time_1k:.0f}s"
        else:
            est_1k = f"{time_1k/60:.1f}min"
            
        if time_10k < 3600:
            est_10k = f"{time_10k/60:.0f}min"
        else:
            est_10k = f"{time_10k/3600:.1f}hr"
        
        self.speed_estimate.setText(
            f"Estimated speed: ~{funcs_per_sec:.1f} functions/sec | "
            f"100 funcs: {est_100} | 1K: {est_1k} | 10K: {est_10k}"
        )
    
    def toggle_api_settings(self):
        """Toggle API settings panel visibility"""
        is_visible = self.api_group.isVisible()
        self.api_group.setVisible(not is_visible)
        self.perf_group.setVisible(not is_visible)  # Toggle performance settings too
        self.toggle_api_btn.setText('Show Settings' if is_visible else 'Hide Settings')
    
    def set_preset(self, preset):
        presets = {
            'ollama': ('http://localhost:11434/v1/chat/completions', '', 'qwen2.5-coder:7b'),
            'openai': ('https://api.openai.com/v1/chat/completions', '', 'gpt-4o-mini'),
            'claude': ('https://api.anthropic.com/v1/messages', '', 'claude-3-5-sonnet-20241022'),
            'openrouter': ('https://openrouter.ai/api/v1/chat/completions', '', 'openai/gpt-4o-mini'),
        }
        if preset in presets:
            url, key, model = presets[preset]
            self.url_edit.setText(url)
            if not self.key_edit.text():
                self.key_edit.setText(key)
            self.model_edit.setText(model)
            self.add_log(f'Preset: {preset}', 'ok')
    
    def on_cell_clicked(self, index):
        if index.column() == 0:
            func = self.model.get_func(index.row())
            if func:
                func.checked = not func.checked
                self.model.dataChanged.emit(index, index)
    
    def save_cfg(self):
        self.cfg = {
            'api_url': self.url_edit.text().strip(),
            'api_key': self.key_edit.text().strip(),
            'model': self.model_edit.text().strip(),
            'batch_size': self.batch_spin.value(),
            'parallel_workers': self.workers_spin.value()
        }
        save_config(self.cfg)
        self.batch_size = self.cfg['batch_size']
        self.parallel_workers = self.cfg['parallel_workers']
        self.add_log('Saved', 'ok')
    
    def add_log(self, msg, level='info'):
        colors = {'info': '#aaa', 'ok': '#4ec9b0', 'err': '#f14c4c', 'warn': '#dcdcaa'}
        self.log.append(f'<span style="color:{colors.get(level, "#aaa")}">[{time.strftime("%H:%M:%S")}] {msg}</span>')
        # Auto scroll to bottom
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())
    
    def apply_filter(self, text):
        self.model.set_filter(text)
        self.update_count()
    
    def update_count(self):
        visible = self.model.rowCount()
        total = self.model.total_count()
        self.count_lbl.setText(f'{visible:,} / {total:,}' if visible != total else f'{total:,} functions')
    
    def test_api(self):
        self.save_cfg()
        if not self.cfg['api_url'] or not self.cfg['model']:
            QMessageBox.warning(self, 'Warning', 'Enter API URL and Model')
            return
        
        self.add_log(f'URL: {self.cfg["api_url"]}', 'info')
        self.add_log(f'Model: {self.cfg["model"]}', 'info')
        self.add_log('Sending request...', 'info')
        self.status_lbl.setText('Testing...')
        
        # Store result in instance variable
        self.test_result = None
        self.test_done = False
        
        def do_test():
            try:
                start = time.time()
                resp = ai_request(self.cfg, 'int double_value(int x) { return x * 2; }\nFunction name?')
                elapsed = time.time() - start
                self.test_result = (True, resp, elapsed)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.test_result = (False, f'{type(e).__name__}: {e}', 0)
            self.test_done = True
        
        t = threading.Thread(target=do_test, daemon=True)
        t.start()
        
        # Poll for result
        def check_result():
            if self.test_done:
                ok, result, elapsed = self.test_result
                if ok:
                    self.add_log(f'[OK] Response: "{result}" ({elapsed:.1f}s)', 'ok')
                    self.status_lbl.setText(f'OK ({elapsed:.1f}s)')
                else:
                    self.add_log(f'[ERROR] {result}', 'err')
                    self.status_lbl.setText('Error')
            else:
                QTimer.singleShot(100, check_result)
        
        QTimer.singleShot(100, check_result)
    
    # Loading
    def load_functions(self):
        self.model.clear()
        self.temp_funcs = []
        self.scanned_count = 0
        self.is_loading = True
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.status_lbl.setText('Scanning...')
        self.load_btn.setEnabled(False)
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.func_iterator = iter(idautils.Functions())
        self.load_timer = QTimer(self)
        self.load_timer.timeout.connect(self.load_batch)
        self.load_timer.start(1)
    
    def load_batch(self):
        if not self.is_loading:
            self.finish_loading()
            return
        for _ in range(500):
            try:
                ea = next(self.func_iterator)
                self.scanned_count += 1
                name = idc.get_func_name(ea)
                if name and name.startswith('sub_') and is_valid_segment(ea):
                    self.temp_funcs.append(FuncData(ea, name))
            except StopIteration:
                self.finish_loading()
                return
        self.status_lbl.setText(f'Scanned {self.scanned_count:,} | Found {len(self.temp_funcs):,}')
    
    def finish_loading(self):
        self.is_loading = False
        if self.load_timer:
            self.load_timer.stop()
        self.model.set_data(self.temp_funcs)
        self.temp_funcs = []
        self.progress.setVisible(False)
        self.update_count()
        self.add_log(f'Loaded {self.model.total_count():,} functions', 'ok')
        self.status_lbl.setText(f'Loaded {self.model.total_count():,}')
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def load_current(self):
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            name = idc.get_func_name(func.start_ea)
            self.model.set_data([FuncData(func.start_ea, name)])
            self.update_count()
            self.add_log(f'Loaded: {name}', 'ok')
    
    def get_existing_names(self):
        """Get all existing function names from IDA and current suggestions"""
        existing = set()
        
        # Get all function names from IDA database
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if name and not name.startswith('sub_'):
                existing.add(name)
        
        # Add already suggested names from current session
        for func in self.model.funcs:
            if func.suggested:
                existing.add(func.suggested)
        
        return existing
    
    # Analysis
    def start_analyze(self):
        if self.model.total_count() == 0:
            QMessageBox.warning(self, 'Warning', 'Load functions first')
            return
        self.save_cfg()
        if not self.cfg['api_url'] or not self.cfg['model']:
            QMessageBox.warning(self, 'Warning', 'Enter API URL and Model')
            return
        items = self.model.get_checked_items()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return
        
        # Limit selection
        if len(items) > 20:
            msg = QMessageBox(self)
            msg.setWindowTitle('Chọn số lượng')
            msg.setText(f'Có {len(items):,} functions. Chọn bao nhiêu?')
            btn10 = msg.addButton('10', QMessageBox.ActionRole)
            btn50 = msg.addButton('50', QMessageBox.ActionRole)
            btn100 = msg.addButton('100', QMessageBox.ActionRole)
            btnAll = msg.addButton(f'All {len(items)}', QMessageBox.ActionRole)
            msg.addButton('Cancel', QMessageBox.RejectRole)
            msg.exec_()
            clicked = msg.clickedButton()
            if clicked == btn10: items = items[:10]
            elif clicked == btn50: items = items[:50]
            elif clicked == btn100: items = items[:100]
            elif clicked != btnAll: return
        
        self.analyze_queue = items
        self.analyze_index = 0
        self.is_analyzing = True
        self.pending_request = False
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.apply_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(items))
        self.progress.setValue(0)
        self.add_log(f'Analyzing {len(items)} functions...', 'info')
        self.analyze_timer = QTimer(self)
        self.analyze_timer.timeout.connect(self.analyze_next)
        self.analyze_timer.start(50)
    
    def analyze_next(self):
        """OPTIMIZED: Batch + Parallel processing (IDA-thread-safe)"""
        if not self.is_analyzing:
            self.finish_analyze()
            return
        
        # Process completed workers
        if self.worker_results:
            for worker_id in list(self.worker_results.keys()):
                result = self.worker_results[worker_id]
                if result.get('done'):
                    for idx, func, suggested, error, elapsed in result['results']:
                        if suggested:
                            func.suggested = suggested
                            func.status = 'OK'
                            self.add_log(f'{func.name} -> {suggested} ({elapsed:.1f}s)', 'ok')
                        else:
                            func.status = 'ERROR'
                            func.checked = False
                            if error:
                                self.add_log(f'{func.name}: {error}', 'err')
                        self.model.refresh_row(idx)
                        self.analyze_index += 1
                        self.progress.setValue(self.analyze_index)
                    self.active_workers -= 1
                    del self.worker_results[worker_id]
        
        # All done?
        if self.analyze_index >= len(self.analyze_queue) and self.active_workers == 0:
            self.finish_analyze()
            return
        
        # Launch new workers (up to parallel_workers limit)
        while self.active_workers < self.parallel_workers and self.analyze_index < len(self.analyze_queue):
            # Calculate batch starting index
            batch = []
            start_idx = self.analyze_index + sum(len(w.get('batch', [])) for w in self.worker_results.values() if not w.get('done'))
            
            # CRITICAL: Prepare IDA data in MAIN THREAD before worker
            batch_data = []
            for i in range(self.batch_size):
                if start_idx + i >= len(self.analyze_queue):
                    break
                idx, func = self.analyze_queue[start_idx + i]
                
                # Get IDA data NOW (in main thread)
                code = get_code(func.ea)
                if not code:
                    batch_data.append((idx, func, None, None, None))
                    continue
                    
                strings = get_strings(func.ea)
                calls = get_calls(func.ea)
                batch_data.append((idx, func, code, strings, calls))
            
            if not batch_data:
                break
            
            # Get existing names NOW (in main thread)
            existing = self.get_existing_names()
            
            # Create worker
            worker_id = f'w{len(self.worker_results)}'
            self.worker_results[worker_id] = {'done': False, 'batch': batch_data, 'results': []}
            self.active_workers += 1
            
            # Update UI
            first = batch_data[0][1].name
            last_idx = start_idx + len(batch_data)
            self.status_lbl.setText(f'{start_idx+1}-{last_idx}/{len(self.analyze_queue)}: {first}... [{self.active_workers} workers]')
            self.add_log(f'[Worker {worker_id}] Batch of {len(batch_data)} functions...', 'info')
            
            # Launch thread (NO IDA calls in worker!)
            t = threading.Thread(target=self.worker_process_batch, args=(worker_id, batch_data, existing), daemon=True)
            t.start()
    
    def worker_process_batch(self, worker_id, batch_data, existing):
        """Worker thread - NO IDA API calls! Only AI requests"""
        results = []
        try:
            if len(batch_data) == 1:
                # Single function mode
                idx, func, code, strings, calls = batch_data[0]
                if code is None:
                    results.append((idx, func, None, 'No code', 0))
                else:
                    start = time.time()
                    prompt = f"```\n{code[:1500]}\n```\n"
                    if strings:
                        prompt += f"Strings: {strings[:5]}\n"
                    if calls:
                        prompt += f"Calls: {calls[:5]}\n"
                    prompt += "\nFunction name?"
                    
                    resp = ai_request(self.cfg, prompt, existing)
                    suggested = clean_name(resp, existing)
                    elapsed = time.time() - start
                    results.append((idx, func, suggested, None, elapsed))
            else:
                # Batch mode
                start = time.time()
                prompt = "Suggest function names (one per line):\n\n"
                valid_batch = []
                
                for idx, func, code, strings, calls in batch_data:
                    if code:
                        prompt += f"{len(valid_batch)+1}. ```\n{code[:600]}\n```\n"
                        valid_batch.append((idx, func))
                
                if valid_batch:
                    prompt += f"\nProvide {len(valid_batch)} unique names (snake_case, one per line):"
                    resp = ai_request(self.cfg, prompt, existing)
                    
                    # Parse response
                    names = []
                    for line in resp.split('\n'):
                        line = line.strip()
                        if line and len(line) < 60 and ':' not in line and '```' not in line:
                            parts = line.split()
                            if parts:
                                name = parts[-1] if len(parts) > 1 and parts[0].replace('.', '').isdigit() else parts[0]
                                if 2 <= len(name) <= 60:
                                    names.append(name)
                    
                    elapsed = time.time() - start
                    avg_time = elapsed / len(valid_batch)
                    
                    for i, (idx, func) in enumerate(valid_batch):
                        suggested = clean_name(names[i], existing) if i < len(names) else None
                        if suggested:
                            existing.add(suggested)
                        results.append((idx, func, suggested, None, avg_time))
        except Exception as e:
            for idx, func, _, _, _ in batch_data:
                results.append((idx, func, None, str(e), 0))
        
        self.worker_results[worker_id]['results'] = results
        self.worker_results[worker_id]['done'] = True

    def finish_analyze(self):
        self.is_analyzing = False
        if self.analyze_timer:
            self.analyze_timer.stop()
        self.progress.setVisible(False)
        self.status_lbl.setText('Done')
        self.add_log('Analysis complete', 'ok')
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.apply_btn.setEnabled(True)
    
    def stop_all(self):
        self.is_loading = False
        self.is_analyzing = False
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
    
    def jump_to(self, index):
        func = self.model.get_func(index.row())
        if func:
            idaapi.jumpto(func.ea)
    
    def apply_renames(self):
        applied = 0
        for idx, func in self.model.get_checked_items():
            if func.suggested:
                if ida_name.set_name(func.ea, func.suggested, ida_name.SN_NOWARN | ida_name.SN_FORCE):
                    applied += 1
                    func.name = func.suggested
                    func.suggested = ''
                    func.status = 'Applied'
                    self.model.refresh_row(idx)
        self.add_log(f'Applied {applied} renames', 'ok')
        QMessageBox.information(self, 'Done', f'Applied {applied} renames')


class AIRenamePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "AI function renaming"
    help = ""
    wanted_name = "AI Rename"
    wanted_hotkey = "Ctrl+Shift+R"
    
    def __init__(self):
        self.dlg = None
    
    def init(self):
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        try:
            ida_hexrays.init_hexrays_plugin()
        except:
            pass
        if self.dlg is None or not self.dlg.isVisible():
            self.dlg = AIRenameDialog()
        self.dlg.show()
        self.dlg.raise_()
    
    def term(self):
        pass


def PLUGIN_ENTRY():
    return AIRenamePlugin()


if __name__ == '__main__':
    try:
        _ai_dlg.close()
    except:
        pass
    _ai_dlg = AIRenameDialog()
    _ai_dlg.show()