# -*- coding: utf-8 -*-
# Copyright (c) CHENDIYAO. All rights reserved.
# Author: CHENDIYAO
# 声明: 本插件由 CHENDIYAO 编写维护，转发、引用或二次分发请务必注明作者 CHENDIYAO。

import functools
import json
import os
import re

import ida_diskio
import ida_idaapi
import ida_kernwin

__author__ = "CHENDIYAO"
__copyright__ = "Copyright (c) CHENDIYAO. 转发请注明出处。"

try:
    _HERE = os.path.dirname(os.path.abspath(__file__))
except Exception:
    _HERE = ""

QtCore = None
QtGui = None
QtWidgets = None
Shiboken = None

ROLE_ORIG = 0x017A

RE_LOAD_AS = re.compile(r"^Load file\s+(.+?)\s+as:?$", re.I)
RE_LINE_OF = re.compile(r"^Line\s+(\d+)\s+of\s+(\d+)(.*)$", re.I)
RE_DISK = re.compile(r"^Disk:\s*(.+)$", re.I)
RE_AU = re.compile(r"^AU:\s*(.+)$", re.I)
RE_NAV_SCALE = re.compile(r"^Navigator Scale:\s*(\d+)\s*pixel\s*=\s*(\d+)\s*bytes?;\s*Range:\s*(.+)$", re.I)
RE_SYNC = re.compile(r"^\(Synchronized with\s+(.+)\)$", re.I)
RE_FONT = re.compile(r"^Select font for:\s*(.+)$", re.I)
RE_SEG_VIS = re.compile(r"^Segments visible from\s+(.+)$", re.I)
RE_NEW_VAL = re.compile(r"^New value of\s+(.+)$", re.I)
RE_EXT_ASSOC = re.compile(r"^Edit file extension\s+'(.+?)'\s+association$", re.I)
RE_CONV_MASSE = re.compile(r'^Convert to\s+"(.+?)"\s+en masse$', re.I)
RE_CHUNK = re.compile(r"^Chunk\s+(\d+)\s+Start$", re.I)

ANCHOR_ACTIONS = {
    "Rename": "Re~n~ame 重命名",
    "OpenStrings": "Strin~g~s 字符串",
    "OpenSegments": "~S~egments 段",
    "OpenBookmarks": "Bookmar~k~s 书签",
    "DumpView": "~H~ex dump 十六进制视图",
    "OpenClasses": "Classes 类视图",
    "JumpEnter": "Jump to ~a~ddress... 跳转到地址...",
    "JumpName": "Jump by ~n~ame... 按名称跳转...",
    "JumpSegment": "Jump by ~s~elector... 按选择子跳转...",
    "ClearMark": "Clear ~m~ark... 清除书签...",
    "FindAllErrors": "All error operands 所有错误操作数",
    "MakeComment": "Enter ~c~omment... 输入注释...",
    "ExportData": "E~x~port data... 导出数据...",
    "ToggleBorder": "Toggle ~b~order 切换边界线",
    "MakeAlignment": "Create ~a~lignment directive... 创建对齐伪指令...",
    "ProduceHtml": "Create ~H~TML file... 创建 HTML 文件...",
    "ProduceDiff": "Create ~D~IF file... 创建 DIF 差异文件...",
    "CheckFreeUpdate": "Check for free update... 检查免费更新...",
    "DebuggerRunTo": "Run to ~c~ursor 运行到光标处",
    "ManualMemoryRegions": "~M~anual memory regions... 手动内存区域...",
    "ProcessOptions": "Process ~o~ptions... 进程选项...",
    "StackTrace": "~S~tack trace 调用栈追踪",
    "Debugger": "~D~ebugger window 调试器窗口",
    "TakeSnapshot": "Take ~m~emory snapshot... 获取内存快照...",
    "OpOffset": "~O~ffset 偏移量",
    "OpNumber": "~N~umber 数值格式",
}

TOOLBAR_MAP = {
    "Navigator": "导航栏",
    "Navigation dock": "导航停靠栏",
    "File": "文件",
    "Jump": "跳转",
    "Search": "搜索",
    "Hide/Unhide": "隐藏/取消隐藏",
    "Analysis": "分析",
    "Views": "视图",
    "Graph view": "图形视图",
    "Lists": "列表",
    "Signatures/Types": "签名/类型",
    "Types": "类型",
    "Cross references": "交叉引用",
    "Segments": "段",
    "Edit": "编辑",
    "Operand type": "操作数类型",
    "Utilities": "实用工具",
    "Functions": "函数",
    "Local Types": "本地类型",
    "Comments": "注释",
    "Debug": "调试",
    "Debugger commands": "调试器命令",
    "Breakpoints": "断点",
    "Watches": "监视",
    "Tracing": "追踪",
    "Merge": "合并",
    "Diff": "差异对比",
}

SAFE_COMBOS = ("DebuggerList", "comboBkgColor", "comboColor")
DBG_MENU_NAMES = ("DebuggerSelected", "DebuggerUnselected", "DebuggerRunToAndAttach")


def _guard(fn):
    @functools.wraps(fn)
    def _wrap(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None
    return _wrap


def _has_cjk(s):
    if not s:
        return False
    for ch in s:
        if "\u4e00" <= ch <= "\u9fff":
            return True
    return False


def _strip_accel(s):
    if not s:
        return ""
    out = s.replace("&&", "\x00")
    out = re.sub(r"~([A-Za-z0-9])~", r"\1", out)
    out = re.sub(r"\(&+[A-Za-z0-9]\)", "", out)
    out = re.sub(r"&(?=\S)", "", out)
    return out.replace("\x00", "&").strip()


def _strip_zh_tail(s):
    if not s:
        return ""
    m = re.match(r"^(.*?)\s*\([^()]*[\u4e00-\u9fff][^()]*\)\s*$", s)
    if m and m.group(1).strip():
        return m.group(1).strip()
    m2 = re.match(r"^([A-Za-z0-9_&\-\./\s\?\+:]+?)\s+[\u4e00-\u9fff].*$", s)
    if m2 and m2.group(1).strip():
        return m2.group(1).strip()
    return s


def _build_clean_map(raw_dict):
    res = {}
    for k, v in raw_dict.items():
        if not k:
            continue
        ck = _strip_accel(k).strip().lower()
        res[ck] = v
        if ck.endswith(":"):
            bare = ck[:-1].strip()
            if bare and bare not in res:
                res[bare] = _strip_accel(v).rstrip(":：").strip()
    return res


def _find_dict_file():
    paths = []
    if _HERE:
        paths.append(os.path.join(_HERE, "ida_zh_cn_dict.json"))
    for getter in (
        lambda: ida_diskio.getsysfile("ida_zh_cn_dict.json", ida_diskio.PLG_SUBDIR),
        lambda: os.path.join(ida_diskio.get_user_idadir(), "plugins", "ida_zh_cn_dict.json"),
        lambda: os.path.join(ida_diskio.get_user_idadir(), "ida_zh_cn_dict.json"),
        lambda: os.path.join(ida_diskio.idadir(ida_diskio.PLG_SUBDIR), "ida_zh_cn_dict.json"),
    ):
        try:
            p = getter()
            if p:
                paths.append(p)
        except Exception:
            pass
    paths.append(os.path.expanduser("~/.idapro/plugins/ida_zh_cn_dict.json"))
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return paths[0]


def _get_state_file():
    try:
        ud = ida_diskio.get_user_idadir()
        if ud:
            return os.path.join(ud, "ida_zh_cn_state.json")
    except Exception:
        pass
    return os.path.expanduser("~/.idapro/ida_zh_cn_state.json")


def _init_qt():
    global QtCore, QtGui, QtWidgets, Shiboken
    if QtWidgets is not None:
        return True
    try:
        from PySide6 import QtCore as _QC, QtGui as _QG, QtWidgets as _QW
        from shiboken6 import Shiboken as _SB
        QtCore, QtGui, QtWidgets, Shiboken = _QC, _QG, _QW, _SB
        return True
    except Exception:
        return False


def _alive(obj):
    if obj is None:
        return False
    if Shiboken is not None:
        try:
            return bool(Shiboken.isValid(obj))
        except Exception:
            return False
    return True


def _make_qt_proxy(mgr):
    if not _init_qt():
        return None

    class _QtProxy(QtCore.QObject):
        def __init__(self, owner):
            super().__init__()
            self.owner = owner
            self._t1 = QtCore.QTimer(self)
            self._t1.setSingleShot(True)
            self._t1.timeout.connect(self.on_timer)
            self._t2 = QtCore.QTimer(self)
            self._t2.setSingleShot(True)
            self._t2.timeout.connect(self.on_timer)

        @_guard
        def defer_refresh(self, ms=30):
            if not self.owner or not self.owner.initialized:
                return
            if _alive(self._t1):
                self._t1.start(ms)
            if _alive(self._t2):
                self._t2.start(max(ms + 100, 140))

        @_guard
        def stop_timers(self):
            if _alive(self._t1):
                self._t1.stop()
            if _alive(self._t2):
                self._t2.stop()

        @_guard
        def on_timer(self):
            if not self.owner or not self.owner.initialized or not self.owner.enabled:
                return
            self.owner._patch_toolbars()
            self.owner._patch_tabbars()
            self.owner._patch_dialogs()

        @_guard
        def on_focus_change(self, old_w, new_w):
            if self.owner and self.owner.initialized:
                self.owner._on_focus_changed(old_w, new_w)

        @_guard
        def on_window_change(self, _win=None):
            if not self.owner or not self.owner.initialized or not self.owner.enabled:
                return
            self.owner._patch_dialogs()
            self.defer_refresh(25)

        @_guard
        def on_btn_click(self, *_args):
            if self.owner and self.owner.initialized and self.owner.enabled:
                self.defer_refresh(20)

        @_guard
        def on_status_msg(self, msg=""):
            if not self.owner or not self.owner.initialized or not self.owner.enabled:
                return
            sb = self.sender()
            if _alive(sb) and isinstance(sb, QtWidgets.QStatusBar):
                self.owner._patch_statusbar(sb, msg)

        @_guard
        def on_tab_change(self, _idx=0):
            if not self.owner or not self.owner.initialized:
                return
            sender = self.sender()
            if _alive(sender) and isinstance(sender, QtWidgets.QTabBar):
                self.owner._patch_tabbar(sender)
            self.owner._patch_dialogs()
            self.defer_refresh(20)

    return _QtProxy(mgr)


class _UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, mgr):
        super().__init__()
        self.mgr = mgr

    @_guard
    def ready_to_run(self):
        if self.mgr:
            self.mgr.apply_all()

    @_guard
    def database_inited(self, is_new, script):
        if self.mgr:
            self.mgr.apply_all()

    @_guard
    def debugger_menu_change(self, enable):
        if self.mgr:
            self.mgr.apply_all()

    @_guard
    def plugin_loaded(self, info):
        if self.mgr:
            self.mgr.apply_all()

    @_guard
    def desktop_applied(self, name, from_idb, dt_type):
        if self.mgr:
            self.mgr.on_widget_event()

    @_guard
    def widget_visible(self, widget):
        if self.mgr:
            self.mgr.on_widget_event()

    @_guard
    def current_widget_changed(self, widget, prev):
        if self.mgr:
            self.mgr.on_widget_event()

    @_guard
    def preprocess_action(self, name):
        if self.mgr:
            self.mgr.on_action_event()
        return 0

    @_guard
    def postprocess_action(self):
        if self.mgr:
            self.mgr.on_action_event()

    @_guard
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if self.mgr:
            self.mgr.on_popup_ready()

    @_guard
    def about_to_exit(self):
        if self.mgr:
            self.mgr.stop()


class ZhLocalizer:
    TOGGLE_ACT = "ida_zh_cn:toggle_language"

    def __init__(self):
        self.dict_path = _find_dict_file()
        self.state_path = _get_state_file()
        self.enabled = True
        self.initialized = False
        self._proxy = None
        self._hooks = None
        self._act_registered = False

        self.top_menus = {}
        self.top_menus_lower = {}
        self.submenus_closed = {}
        self.act_labels = {}
        self.act_tooltips = {}
        self.act_text_zh = {}
        self.act_text_zh_lower = {}
        self.qt_tr = {}
        self.qt_tr_clean = {}
        self.dlg_text = {}
        self.dlg_text_lower = {}
        self.tab_titles = {}
        self.tab_titles_lower = {}
        self.tab_prefixes = []

        self._orig_labels = {}
        self._orig_tips = {}
        self._patched_acts = set()
        self._zh_to_en_tabs = {}

    @_guard
    def load_dict(self):
        self.dict_path = _find_dict_file()
        self.state_path = _get_state_file()

        if os.path.isfile(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    self.enabled = bool(json.load(f).get("enabled", True))
            except Exception:
                self.enabled = True

        if not os.path.isfile(self.dict_path):
            ida_kernwin.msg(f"[IDA-ZH] 未找到词典文件: {self.dict_path}\n")
            return False

        with open(self.dict_path, "r", encoding="utf-8") as f:
            d = json.load(f)

        self.top_menus = d.get("top_level_menus", {})
        self.top_menus_lower = {k.lower(): v for k, v in self.top_menus.items()}
        self.submenus_closed = d.get("submenu_clean_to_closed", {})
        self.act_labels = d.get("actions_label", {})
        self.act_tooltips = d.get("actions_tooltip", {})
        self.act_text_zh = d.get("action_text_to_zh", {})
        self.act_text_zh_lower = {
            _strip_accel(k).lower(): v for k, v in self.act_text_zh.items() if k
        }
        self.qt_tr = d.get("qt_translate", {})
        self.qt_tr_clean = _build_clean_map(self.qt_tr)
        self.dlg_text = d.get("dialog_text", {})
        self.dlg_text_lower = _build_clean_map(self.dlg_text)
        self.tab_titles = d.get("tab_titles", {})
        self.tab_titles_lower = {k.lower(): v for k, v in self.tab_titles.items()}
        self.tab_prefixes = d.get("tab_prefixes", [])
        self._zh_to_en_tabs = {v: k for k, v in self.tab_titles.items()}
        return True

    @_guard
    def save_state(self):
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({"enabled": self.enabled}, f, indent=2)
        except Exception:
            pass

    @_guard
    def start(self):
        if self.initialized:
            return True
        if not ida_kernwin.is_idaq() or not _init_qt() or not self.load_dict():
            return False

        app = QtWidgets.QApplication.instance()
        if app is None:
            return False

        if self._proxy is None:
            self._proxy = _make_qt_proxy(self)
            if self._proxy is not None:
                for sig, slot in (
                    (app.focusChanged, self._proxy.on_focus_change),
                    (app.focusWindowChanged, self._proxy.on_window_change),
                ):
                    try:
                        sig.connect(slot)
                    except Exception:
                        pass

        if self._hooks is None:
            self._hooks = _UIHooks(self)
            self._hooks.hook()

        self._reg_hotkey_action()
        self.initialized = True
        self.apply_all()
        ida_kernwin.msg(
            "[IDA-ZH] IDA 简体中文插件已加载 | Author: CHENDIYAO (转发请注明出处) | Ctrl+Alt+L 切换中英文\n"
        )
        return True

    @_guard
    def stop(self):
        if not self.initialized and self._hooks is None and self._proxy is None:
            return
        self.initialized = False

        if self._hooks is not None:
            try:
                self._hooks.unhook()
            except Exception:
                pass
            self._hooks = None

        if self._proxy is not None:
            try:
                self._proxy.stop_timers()
                if QtWidgets is not None:
                    app = QtWidgets.QApplication.instance()
                    if app is not None:
                        for sig, slot in (
                            (app.focusChanged, self._proxy.on_focus_change),
                            (app.focusWindowChanged, self._proxy.on_window_change),
                        ):
                            try:
                                sig.disconnect(slot)
                            except Exception:
                                pass
                if _alive(self._proxy):
                    Shiboken.delete(self._proxy)
            except Exception:
                pass
            self._proxy = None

        if self._act_registered:
            try:
                ida_kernwin.unregister_action(self.TOGGLE_ACT)
            except Exception:
                pass
            self._act_registered = False

    @_guard
    def _reg_hotkey_action(self):
        if self._act_registered:
            return
        owner = self

        class _ToggleHandler(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                owner.toggle_language()
                return 1

            def update(self, ctx):
                return ida_kernwin.AST_ENABLE_ALWAYS

        desc = ida_kernwin.action_desc_t(
            self.TOGGLE_ACT,
            "切换中英文界面 (Toggle Chinese/English UI)",
            _ToggleHandler(),
            "Ctrl+Alt+L",
            "在中文与英文界面之间切换",
            -1,
        )
        if ida_kernwin.register_action(desc):
            self._act_registered = True
            ida_kernwin.attach_action_to_menu("Options/", self.TOGGLE_ACT, ida_kernwin.SETMENU_APP)

    @_guard
    def toggle_language(self):
        self.enabled = not self.enabled
        self.save_state()
        if self.enabled:
            self._patched_acts.clear()
            self.apply_all()
            ida_kernwin.msg("[IDA-ZH] 已切换为中文界面 (Ctrl+Alt+L)\n")
        else:
            self.restore_english()
            ida_kernwin.msg("[IDA-ZH] Switched to English UI (Ctrl+Alt+L)\n")

    @_guard
    def apply_all(self):
        if not self.initialized or not self.enabled or not _init_qt():
            return
        self._patch_actions()
        self._patch_toolbars()
        self._patch_menus()
        self._patch_tabbars()
        self._patch_dialogs()
        if self._proxy is not None:
            self._proxy.defer_refresh(30)

    @_guard
    def restore_english(self):
        if not _init_qt():
            return
        self._patched_acts.clear()
        for name, lbl in list(self._orig_labels.items()):
            try:
                ida_kernwin.update_action_label(name, lbl)
            except Exception:
                pass
        for name, tip in list(self._orig_tips.items()):
            try:
                ida_kernwin.update_action_tooltip(name, tip)
            except Exception:
                pass

        app = QtWidgets.QApplication.instance()
        if app is None:
            return

        for w in list(app.allWidgets()):
            if not _alive(w):
                continue
            if isinstance(w, QtWidgets.QMenu):
                name = w.objectName() or ""
                if name in DBG_MENU_NAMES:
                    ma = w.menuAction()
                    vis = bool(_alive(ma) and ma.isVisible())
                    w.setTitle("Deb&ugger" if vis else name)
                else:
                    orig = w.property("_ida_zh_orig_title")
                    if orig:
                        w.setTitle(str(orig))
                for act in w.actions():
                    if _alive(act):
                        orig_t = act.property("_ida_zh_orig_text")
                        if orig_t:
                            act.setText(str(orig_t))
            elif isinstance(w, (QtWidgets.QToolBar, QtWidgets.QDockWidget)):
                orig = w.property("_ida_zh_orig_title")
                if orig:
                    w.setWindowTitle(str(orig))
                ta = w.toggleViewAction()
                if _alive(ta):
                    orig_t = ta.property("_ida_zh_orig_text")
                    if orig_t:
                        ta.setText(str(orig_t))
            elif isinstance(w, QtWidgets.QComboBox):
                if (w.objectName() or "") in SAFE_COMBOS:
                    self._restore_combo(w)
            elif isinstance(w, QtWidgets.QTabBar):
                self._restore_tabbar(w)
            elif isinstance(w, (QtWidgets.QDialog, QtWidgets.QMainWindow)):
                self._restore_form(w)

    @_guard
    def _patch_actions(self):
        for name, zh_lbl in self.act_labels.items():
            if not zh_lbl or name in self._patched_acts:
                continue
            try:
                if name not in self._orig_labels:
                    cur = ida_kernwin.get_action_label(name)
                    if not cur:
                        continue
                    self._orig_labels[name] = cur
                    tip = ida_kernwin.get_action_tooltip(name)
                    if tip is not None:
                        self._orig_tips[name] = tip

                target = ANCHOR_ACTIONS.get(name, _strip_accel(zh_lbl))
                if ida_kernwin.update_action_label(name, target):
                    self._patched_acts.add(name)

                zh_tip = self.act_tooltips.get(name)
                if zh_tip:
                    ida_kernwin.update_action_tooltip(name, zh_tip)
            except Exception:
                continue

    @_guard
    def _patch_toolbars(self):
        if not self.enabled or not _init_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        for w in list(app.allWidgets()):
            if not _alive(w):
                continue
            if isinstance(w, (QtWidgets.QToolBar, QtWidgets.QDockWidget)):
                title = w.windowTitle() or ""
                clean = _strip_accel(title)
                zh = TOOLBAR_MAP.get(clean) or self.tab_titles.get(clean)
                if zh and not _has_cjk(title):
                    w.setProperty("_ida_zh_orig_title", title)
                    w.setWindowTitle(zh)
                ta = w.toggleViewAction()
                if _alive(ta):
                    atxt = ta.text() or ""
                    aclean = _strip_accel(atxt)
                    zh_a = zh or TOOLBAR_MAP.get(aclean) or self.tab_titles.get(aclean)
                    if zh_a and atxt and not _has_cjk(atxt):
                        ta.setProperty("_ida_zh_orig_text", atxt)
                        ta.setText(zh_a)
            elif isinstance(w, QtWidgets.QComboBox):
                if (w.objectName() or "") in SAFE_COMBOS:
                    self._patch_combo(w)

    @_guard
    def _patch_combo(self, cb):
        if not _alive(cb):
            return
        for i in range(cb.count()):
            txt = cb.itemText(i) or ""
            if txt and not _has_cjk(txt):
                zh = self._tr(txt)
                if zh and zh != txt:
                    cb.setProperty(f"_ida_zh_orig_item_{i}", txt)
                    cb.setItemText(i, zh)

    @_guard
    def _restore_combo(self, cb):
        if not _alive(cb):
            return
        for i in range(cb.count()):
            orig = cb.property(f"_ida_zh_orig_item_{i}")
            if orig:
                cb.setItemText(i, str(orig))

    @_guard
    def _patch_menus(self):
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        widgets = list(app.allWidgets())
        for w in widgets:
            if _alive(w) and isinstance(w, QtWidgets.QMenuBar):
                for act in w.actions():
                    if _alive(act) and _alive(act.menu()):
                        self._patch_menu(act.menu(), top=True)
        for w in widgets:
            if _alive(w) and isinstance(w, QtWidgets.QMenu):
                self._patch_menu(w, top=bool(w.property("_ida_zh_is_top")))

    @_guard
    def _patch_menu(self, menu, top=False):
        if not _alive(menu):
            return
        if top:
            menu.setProperty("_ida_zh_is_top", True)
        else:
            top = bool(menu.property("_ida_zh_is_top"))

        name = menu.objectName() or ""
        cur = menu.title() or ""
        if cur and not _has_cjk(cur):
            menu.setProperty("_ida_zh_orig_title", cur)

        orig = str(menu.property("_ida_zh_orig_title") or cur)
        clean = _strip_accel(_strip_zh_tail(orig)).lower()

        if self.enabled:
            role_top = name.endswith((":Edit", ":Jump", ":Search", ":File", ":Windows", ":Help"))
            if top or role_top or name in self.top_menus:
                if name in DBG_MENU_NAMES:
                    ma = menu.menuAction()
                    vis = bool(_alive(ma) and ma.isVisible())
                    target = "Deb&ugger 调试器" if vis else name
                    if menu.title() != target:
                        menu.setTitle(target)
                elif orig not in DBG_MENU_NAMES:
                    zh_top = (
                        self.top_menus.get(name)
                        or self.top_menus_lower.get(name.lower())
                        or self.top_menus_lower.get(clean)
                    )
                    if zh_top and menu.title() != zh_top:
                        menu.setTitle(zh_top)
            else:
                closed = self.submenus_closed.get(clean)
                if closed:
                    if menu.title() != closed:
                        menu.setTitle(closed)
                else:
                    zh_sub = self.act_text_zh.get(orig) or self.act_text_zh_lower.get(clean)
                    if zh_sub and menu.title() != zh_sub:
                        menu.setTitle(zh_sub)

        is_tb = clean in ("toolbars", "toolbar")
        for act in menu.actions():
            if not _alive(act) or act.isSeparator():
                continue
            sub = act.menu()
            if _alive(sub) and sub is not menu:
                self._patch_menu(sub, top=False)
            elif is_tb and self.enabled:
                txt = act.text() or ""
                if txt and not _has_cjk(txt):
                    zh_a = TOOLBAR_MAP.get(_strip_accel(txt))
                    if zh_a:
                        act.setProperty("_ida_zh_orig_text", txt)
                        act.setText(zh_a)

    @_guard
    def on_popup_ready(self):
        if not self.initialized or not self.enabled or not _init_qt():
            return
        self._patch_toolbars()
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        for w in list(app.allWidgets()):
            if _alive(w) and isinstance(w, QtWidgets.QMenu) and not w.property("_ida_zh_is_top"):
                self._patch_popup(w)

    @_guard
    def _patch_popup(self, menu):
        if not _alive(menu) or bool(menu.property("_ida_zh_is_top")):
            return
        for act in menu.actions():
            if not _alive(act) or act.isSeparator():
                continue
            sub = act.menu()
            if _alive(sub) and sub is not menu:
                self._patch_menu(sub, top=False)
                self._patch_popup(sub)
                continue

            txt = act.text() or ""
            if not txt or _has_cjk(txt):
                continue

            parts = txt.split("\t", 1)
            head = parts[0]
            tail = ("\t" + parts[1]) if len(parts) > 1 else ""
            clean = _strip_accel(head)
            zh = (
                TOOLBAR_MAP.get(clean)
                or self.act_text_zh.get(head)
                or self.act_text_zh.get(clean)
                or self.act_text_zh_lower.get(clean.lower())
            )
            if zh:
                if not act.property("_ida_zh_orig_text"):
                    act.setProperty("_ida_zh_orig_text", txt)
                act.setText(_strip_accel(zh) + tail)

    @_guard
    def _patch_tabbars(self):
        if not self.enabled or not _init_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        for w in list(app.allWidgets()):
            if _alive(w) and isinstance(w, QtWidgets.QTabBar):
                self._patch_tabbar(w)

    @_guard
    def _patch_tabbar(self, tb):
        if not _alive(tb):
            return
        if self._proxy is not None and not tb.property("_ida_zh_tb_hooked"):
            tb.setProperty("_ida_zh_tb_hooked", True)
            try:
                tb.currentChanged.connect(self._proxy.on_tab_change)
            except Exception:
                pass
        for i in range(tb.count()):
            txt = tb.tabText(i)
            if not txt:
                continue
            clean = _strip_accel(txt)
            zh = (
                self.tab_titles.get(txt)
                or self.tab_titles.get(clean)
                or self.tab_titles_lower.get(clean.lower())
            )
            if zh:
                if txt != zh:
                    tb.setTabText(i, zh)
                continue
            for en_p, zh_p in self.tab_prefixes:
                if clean.startswith(en_p):
                    new_t = zh_p + clean[len(en_p):]
                    if txt != new_t:
                        tb.setTabText(i, new_t)
                    break

    @_guard
    def _restore_tabbar(self, tb):
        if not _alive(tb):
            return
        for i in range(tb.count()):
            txt = tb.tabText(i)
            if not txt:
                continue
            if txt in self._zh_to_en_tabs:
                tb.setTabText(i, self._zh_to_en_tabs[txt])
                continue
            for en_p, zh_p in self.tab_prefixes:
                if txt.startswith(zh_p):
                    tb.setTabText(i, en_p + txt[len(zh_p):])
                    break

    @_guard
    def on_action_event(self):
        if self.initialized and self.enabled and self._proxy is not None:
            self._proxy.defer_refresh(25)

    @_guard
    def on_widget_event(self):
        if not self.initialized or not self.enabled or not _init_qt():
            return
        self._patch_toolbars()
        self._patch_tabbars()
        self._patch_dialogs()
        if self._proxy is not None:
            self._proxy.defer_refresh(30)

    @_guard
    def _patch_dialogs(self):
        if not self.enabled or not _init_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        popup = app.activePopupWidget()
        if _alive(popup) and isinstance(popup, QtWidgets.QMenu) and not popup.property("_ida_zh_is_top"):
            self._patch_popup(popup)
        for top in list(app.topLevelWidgets()):
            if not _alive(top) or not top.isVisible():
                continue
            if isinstance(top, QtWidgets.QDialog):
                self._patch_form(top)
            elif isinstance(top, QtWidgets.QMainWindow):
                self._patch_form(top, is_main=True)
            elif isinstance(top, QtWidgets.QWidget) and not isinstance(top, QtWidgets.QMenu):
                self._patch_form(top)

    @_guard
    def _on_focus_changed(self, _old, _new):
        if not self.initialized or not self.enabled:
            return
        self._patch_dialogs()
        self._patch_toolbars()
        self._patch_tabbars()
        if self._proxy is not None:
            self._proxy.defer_refresh(25)

    @_guard
    def _patch_form(self, container, is_main=False):
        if not self.enabled or not _alive(container):
            return

        if not is_main:
            title = container.windowTitle() or ""
            if title and not _has_cjk(title):
                zh_t = self._tr(title)
                if zh_t and zh_t != title:
                    container.setProperty("_ida_zh_orig_title", title)
                    container.setWindowTitle(zh_t)

        btn_types = (
            QtWidgets.QPushButton,
            QtWidgets.QCheckBox,
            QtWidgets.QRadioButton,
            QtWidgets.QToolButton,
        )

        for w in container.findChildren(QtWidgets.QWidget):
            if not _alive(w):
                continue

            if isinstance(w, btn_types):
                if is_main and isinstance(w, QtWidgets.QToolButton):
                    continue
                txt = w.text() or ""
                if txt and not _has_cjk(txt):
                    zh = self._tr(txt)
                    if zh and zh != txt:
                        w.setProperty("_ida_zh_orig_text", txt)
                        w.setText(zh)
                if self._proxy is not None and not w.property("_ida_zh_btn_hooked"):
                    w.setProperty("_ida_zh_btn_hooked", True)
                    try:
                        if isinstance(w, (QtWidgets.QCheckBox, QtWidgets.QRadioButton)):
                            w.toggled.connect(self._proxy.on_tab_change)
                        else:
                            w.clicked.connect(self._proxy.on_btn_click)
                    except Exception:
                        pass

            elif isinstance(w, QtWidgets.QGroupBox):
                gtxt = w.title() or ""
                if gtxt and not _has_cjk(gtxt):
                    zh = self._tr(gtxt)
                    if zh and zh != gtxt:
                        w.setProperty("_ida_zh_orig_title", gtxt)
                        w.setTitle(zh)

            elif isinstance(w, QtWidgets.QLabel):
                ltxt = w.text() or ""
                if ltxt and not _has_cjk(ltxt) and len(ltxt) < 400:
                    if ltxt in self.qt_tr:
                        w.setProperty("_ida_zh_orig_text", ltxt)
                        w.setText(self.qt_tr[ltxt])
                    elif not ltxt.lstrip().startswith("<"):
                        zh = self._tr(ltxt)
                        if zh and zh != ltxt:
                            w.setProperty("_ida_zh_orig_text", ltxt)
                            w.setText(zh)

            elif isinstance(w, QtWidgets.QComboBox):
                if (w.objectName() or "") in SAFE_COMBOS:
                    self._patch_combo(w)

            elif isinstance(w, QtWidgets.QListWidget):
                if (w.objectName() or "") == "nats":
                    for i in range(w.count()):
                        it = w.item(i)
                        if it is not None:
                            itxt = it.text() or ""
                            if itxt and not _has_cjk(itxt):
                                zh = self._tr(itxt)
                                if zh and zh != itxt:
                                    it.setData(ROLE_ORIG, itxt)
                                    it.setText(zh)

            elif isinstance(w, QtWidgets.QAbstractItemView):
                if not is_main and self._proxy is not None and not w.property("_ida_zh_sel_hooked"):
                    sm = w.selectionModel()
                    if _alive(sm):
                        w.setProperty("_ida_zh_sel_hooked", True)
                        try:
                            sm.selectionChanged.connect(self._proxy.on_btn_click)
                        except Exception:
                            pass
                if not is_main and isinstance(w, QtWidgets.QTableWidget):
                    for col in range(w.columnCount()):
                        hi = w.horizontalHeaderItem(col)
                        if hi is not None:
                            ht = hi.text() or ""
                            if ht and not _has_cjk(ht):
                                zh = self._tr(ht)
                                if zh and zh != ht:
                                    hi.setData(ROLE_ORIG, ht)
                                    hi.setText(zh)
                elif not is_main and isinstance(w, QtWidgets.QTreeWidget):
                    hi = w.headerItem()
                    if hi is not None:
                        for col in range(w.columnCount()):
                            ht = hi.text(col) or ""
                            if ht and not _has_cjk(ht):
                                zh = self._tr(ht)
                                if zh and zh != ht:
                                    hi.setData(col, ROLE_ORIG, ht)
                                    hi.setText(col, zh)

            elif isinstance(w, QtWidgets.QTabBar):
                if not is_main:
                    for i in range(w.count()):
                        tt = w.tabText(i) or ""
                        if tt and not _has_cjk(tt):
                            zh = self._tr(tt)
                            if zh and zh != tt:
                                w.setProperty(f"_ida_zh_orig_tab_{i}", tt)
                                w.setTabText(i, zh)

            elif isinstance(w, QtWidgets.QTabWidget):
                if self._proxy is not None and not w.property("_ida_zh_tab_hooked"):
                    w.setProperty("_ida_zh_tab_hooked", True)
                    try:
                        w.currentChanged.connect(self._proxy.on_tab_change)
                    except Exception:
                        pass

            elif isinstance(w, QtWidgets.QStatusBar):
                self._patch_statusbar(w)
                if self._proxy is not None and not w.property("_ida_zh_sb_hooked"):
                    w.setProperty("_ida_zh_sb_hooked", True)
                    try:
                        w.messageChanged.connect(self._proxy.on_status_msg)
                    except Exception:
                        pass

    @_guard
    def _patch_statusbar(self, sb, msg=None):
        if not self.enabled or not _alive(sb):
            return
        cur = msg if msg is not None else (sb.currentMessage() or "")
        if not cur or _has_cjk(cur):
            return
        zh = self._tr(cur)
        if zh and zh != cur:
            sb.setProperty("_ida_zh_orig_msg", cur)
            sb.showMessage(zh)

    @_guard
    def _restore_form(self, container):
        if not _alive(container):
            return
        if not isinstance(container, QtWidgets.QMainWindow):
            orig_t = container.property("_ida_zh_orig_title")
            if orig_t:
                container.setWindowTitle(str(orig_t))

        txt_widgets = (
            QtWidgets.QPushButton,
            QtWidgets.QCheckBox,
            QtWidgets.QRadioButton,
            QtWidgets.QToolButton,
            QtWidgets.QLabel,
        )
        for w in container.findChildren(QtWidgets.QWidget):
            if not _alive(w):
                continue
            if isinstance(w, txt_widgets):
                orig = w.property("_ida_zh_orig_text")
                if orig:
                    w.setText(str(orig))
            elif isinstance(w, QtWidgets.QGroupBox):
                orig = w.property("_ida_zh_orig_title")
                if orig:
                    w.setTitle(str(orig))
            elif isinstance(w, QtWidgets.QComboBox):
                if (w.objectName() or "") in SAFE_COMBOS:
                    self._restore_combo(w)
            elif isinstance(w, QtWidgets.QListWidget):
                if (w.objectName() or "") == "nats":
                    for i in range(w.count()):
                        it = w.item(i)
                        if it is not None:
                            orig = it.data(ROLE_ORIG)
                            if orig:
                                it.setText(str(orig))
            elif isinstance(w, QtWidgets.QTabBar):
                for i in range(w.count()):
                    orig = w.property(f"_ida_zh_orig_tab_{i}")
                    if orig:
                        w.setTabText(i, str(orig))
            elif isinstance(w, QtWidgets.QStatusBar):
                orig = w.property("_ida_zh_orig_msg")
                if orig:
                    w.showMessage(str(orig))

    def _tr(self, text):
        if not text:
            return ""
        raw = text.strip()
        if raw in self.dlg_text:
            return self.dlg_text[raw]
        if raw in self.qt_tr:
            return self.qt_tr[raw]

        clean = _strip_accel(raw)
        if clean in self.dlg_text:
            return self.dlg_text[clean]
        if clean in self.tab_titles:
            return self.tab_titles[clean]

        low = clean.lower()
        if low in self.dlg_text_lower:
            return self.dlg_text_lower[low]
        if low in self.qt_tr_clean:
            return self.qt_tr_clean[low]
        if low in self.tab_titles_lower:
            return self.tab_titles_lower[low]

        for en_p, zh_p in self.tab_prefixes:
            if clean.startswith(en_p):
                return zh_p + clean[len(en_p):]

        if "\n" in raw:
            out_lines = []
            changed = False
            for ln in raw.splitlines():
                s = ln.strip()
                if not s:
                    out_lines.append(ln)
                    continue
                zh_ln = self._tr(s)
                if zh_ln and zh_ln != s:
                    out_lines.append(zh_ln)
                    changed = True
                else:
                    out_lines.append(ln)
            if changed:
                return "\n".join(out_lines)

        m = RE_LOAD_AS.match(clean)
        if m:
            return f"加载文件 {m.group(1)} 为"

        m = RE_LINE_OF.match(clean)
        if m:
            suf = m.group(3) or ""
            if suf == ", (outdated)":
                suf = " (已过期)"
            elif suf.endswith(" (outdated)"):
                suf = suf[:-11] + " (已过期)"
            return f"第 {m.group(1)} / {m.group(2)} 行{suf}"

        m = RE_DISK.match(clean)
        if m:
            return f"磁盘可用: {m.group(1)}"

        m = RE_AU.match(clean)
        if m:
            st = m.group(1).strip()
            return "自动分析: 空闲" if st.lower() == "idle" else f"自动分析: {st}"

        m = RE_NAV_SCALE.match(clean)
        if m:
            return f"导航栏比例: {m.group(1)} 像素 = {m.group(2)} 字节; 范围: {m.group(3)}"

        m = RE_SYNC.match(clean)
        if m:
            t = m.group(1).strip()
            return f"(已与 {self._tr(t) or t} 同步)"

        m = RE_FONT.match(clean)
        if m:
            t = m.group(1).strip()
            return f"选择字体: {self._tr(t) or t}"

        m = RE_SEG_VIS.match(clean)
        if m:
            return f"从 {m.group(1)} 可见的段"

        m = RE_NEW_VAL.match(clean)
        if m:
            return f"{m.group(1)} 的新值"

        m = RE_EXT_ASSOC.match(clean)
        if m:
            return f"编辑文件扩展名 '{m.group(1)}' 关联"

        m = RE_CONV_MASSE.match(clean)
        if m:
            return f'批量转换为 "{m.group(1)}"'

        m = RE_CHUNK.match(clean)
        if m:
            return f"分块 {m.group(1)} 起始地址"

        for en_s, zh_s in (
            (" (non-graph)", " (非图形)"),
            (" (graph)", " (图形)"),
            (" (default)", " (默认)"),
            (" (highlighted)", " (高亮)"),
        ):
            if low.endswith(en_s):
                base = low[:-len(en_s)].strip()
                zh_b = self.dlg_text_lower.get(base) or self.qt_tr_clean.get(base)
                if zh_b:
                    return _strip_accel(zh_b) + zh_s

        for en_p, zh_p in (
            ("Line prefix example: ", "行前缀示例: "),
            ("Example: ", "示例: "),
            ("Supported languages: ", "支持的语言: "),
            ("Current processor: ", "当前处理器: "),
            ("Debug application setup: ", "调试应用程序设置: "),
            ("Xref Graph: ", "交叉引用图: "),
        ):
            if clean.startswith(en_p):
                return zh_p + clean[len(en_p):]

        if low.endswith(":"):
            base = low[:-1].strip()
            zh_b = self.dlg_text_lower.get(base) or self.qt_tr_clean.get(base)
            if zh_b:
                return _strip_accel(zh_b).rstrip(":：") + ":"
        if low.endswith("..."):
            base = low[:-3].strip()
            zh_b = self.dlg_text_lower.get(base) or self.qt_tr_clean.get(base)
            if zh_b:
                return _strip_accel(zh_b).rstrip(".") + "..."
        return ""

    _lookup_dialog_string = _tr
    _translate_dialog = _patch_form
    _translate_popup_menu_once = _patch_popup
    load_config_and_dict = load_dict


IdaZhLocalizationManager = ZhLocalizer
_g_manager = None


class IdaZhCnPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_KEEP
    comment = "IDA 简体中文插件 | Author: CHENDIYAO (转发请注明出处)"
    help = "作者: CHENDIYAO (转发请注明出处) | 快捷键 Ctrl+Alt+L 切换中英文"
    wanted_name = "IDA 简体中文汉化 [By CHENDIYAO]"
    wanted_hotkey = "Ctrl-Alt-L"

    @_guard
    def init(self):
        global _g_manager
        if not ida_kernwin.is_idaq():
            return ida_idaapi.PLUGIN_SKIP
        if _g_manager is None:
            _g_manager = ZhLocalizer()
        _g_manager.start()
        return ida_idaapi.PLUGIN_KEEP

    @_guard
    def run(self, arg):
        global _g_manager
        if _g_manager is not None:
            if not _g_manager.initialized:
                _g_manager.start()
            else:
                _g_manager.toggle_language()

    @_guard
    def term(self):
        global _g_manager
        if _g_manager is not None:
            _g_manager.stop()
            _g_manager = None


def PLUGIN_ENTRY():
    return IdaZhCnPlugin()
