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
    _PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
except Exception:
    _PLUGIN_DIR = ""

QtCore = None
QtGui = None
QtWidgets = None
Shiboken = None

_RE_LOAD_FILE_AS = re.compile(r"^Load file\s+(.+?)\s+as:?$", re.IGNORECASE)
_RE_LINE_OF = re.compile(r"^Line\s+(\d+)\s+of\s+(\d+)(.*)$", re.IGNORECASE)
_RE_DISK_SPACE = re.compile(r"^Disk:\s*(.+)$", re.IGNORECASE)
_RE_AU_STATE = re.compile(r"^AU:\s*(.+)$", re.IGNORECASE)
_RE_NAV_SCALE = re.compile(
    r"^Navigator Scale:\s*(\d+)\s*pixel\s*=\s*(\d+)\s*bytes?;\s*Range:\s*(.+)$",
    re.IGNORECASE,
)
_RE_SYNC_WITH = re.compile(r"^\(Synchronized with\s+(.+)\)$", re.IGNORECASE)
_RE_SELECT_FONT = re.compile(r"^Select font for:\s*(.+)$", re.IGNORECASE)
_RE_SEGMENTS_VISIBLE = re.compile(r"^Segments visible from\s+(.+)$", re.IGNORECASE)
_RE_NEW_VALUE_OF = re.compile(r"^New value of\s+(.+)$", re.IGNORECASE)
_RE_EDIT_EXT_ASSOC = re.compile(r"^Edit file extension\s+'(.+?)'\s+association$", re.IGNORECASE)
_RE_CONVERT_EN_MASSE = re.compile(r'^Convert to\s+"(.+?)"\s+en masse$', re.IGNORECASE)
_RE_CHUNK_START = re.compile(r"^Chunk\s+(\d+)\s+Start$", re.IGNORECASE)


def _safe_call(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            return None
    return _wrapper


def _has_cjk(text):
    if not text:
        return False
    for ch in text:
        if "\u4e00" <= ch <= "\u9fff":
            return True
    return False


def _strip_accel(text):
    if not text:
        return ""
    s = text.replace("&&", "\x00")
    s = re.sub(r"~([A-Za-z0-9])~", r"\1", s)
    s = re.sub(r"\(&+[A-Za-z0-9]\)", "", s)
    s = re.sub(r"&(?=\S)", "", s)
    return s.replace("\x00", "&").strip()


def _strip_bilingual_suffix(text):
    if not text:
        return ""
    m = re.match(r"^(.*?)\s*\([^()]*[\u4e00-\u9fff][^()]*\)\s*$", text)
    if m and m.group(1).strip():
        return m.group(1).strip()
    m2 = re.match(r"^([A-Za-z0-9_&\-\./\s\?\+:]+?)\s+[\u4e00-\u9fff].*$", text)
    if m2 and m2.group(1).strip():
        return m2.group(1).strip()
    return text


def _resolve_dict_path():
    candidates = []
    if _PLUGIN_DIR:
        candidates.append(os.path.join(_PLUGIN_DIR, "ida_zh_cn_dict.json"))
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(here, "ida_zh_cn_dict.json"))
    except Exception:
        pass
    try:
        sys_dict = ida_diskio.getsysfile("ida_zh_cn_dict.json", ida_diskio.PLG_SUBDIR)
        if sys_dict:
            candidates.append(sys_dict)
    except Exception:
        pass
    try:
        user_dir = ida_diskio.get_user_idadir()
        if user_dir:
            candidates.append(os.path.join(user_dir, "plugins", "ida_zh_cn_dict.json"))
            candidates.append(os.path.join(user_dir, "ida_zh_cn_dict.json"))
    except Exception:
        pass
    try:
        plg_dir = ida_diskio.idadir(ida_diskio.PLG_SUBDIR)
        if plg_dir:
            candidates.append(os.path.join(plg_dir, "ida_zh_cn_dict.json"))
    except Exception:
        pass
    candidates.append(os.path.expanduser("~/.idapro/plugins/ida_zh_cn_dict.json"))
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return candidates[0] if candidates else os.path.expanduser("~/.idapro/plugins/ida_zh_cn_dict.json")


def _resolve_state_path():
    try:
        user_dir = ida_diskio.get_user_idadir()
        if user_dir:
            return os.path.join(user_dir, "ida_zh_cn_state.json")
    except Exception:
        pass
    return os.path.expanduser("~/.idapro/ida_zh_cn_state.json")


def _ensure_qt():
    global QtCore, QtGui, QtWidgets, Shiboken
    if QtWidgets is not None:
        return True
    try:
        from PySide6 import QtCore as _QtCore
        from PySide6 import QtGui as _QtGui
        from PySide6 import QtWidgets as _QtWidgets
        from shiboken6 import Shiboken as _Shiboken
        QtCore = _QtCore
        QtGui = _QtGui
        QtWidgets = _QtWidgets
        Shiboken = _Shiboken
        return True
    except Exception:
        return False


def _is_valid_qobj(obj):
    if obj is None:
        return False
    if Shiboken is not None:
        try:
            return bool(Shiboken.isValid(obj))
        except Exception:
            return False
    return True


def _create_signal_receiver(manager):
    if not _ensure_qt():
        return None

    class _QtSignalReceiver(QtCore.QObject):
        def __init__(self, mgr):
            super().__init__()
            self._mgr = mgr
            self._timer = QtCore.QTimer(self)
            self._timer.setSingleShot(True)
            self._timer.timeout.connect(self.on_deferred_ui_refresh)
            self._timer_followup = QtCore.QTimer(self)
            self._timer_followup.setSingleShot(True)
            self._timer_followup.timeout.connect(self.on_deferred_ui_refresh)

        @_safe_call
        def schedule_ui_refresh(self, delay_ms=30):
            if not self._mgr or not self._mgr.initialized:
                return
            if self._timer is not None and _is_valid_qobj(self._timer):
                self._timer.start(delay_ms)
            if self._timer_followup is not None and _is_valid_qobj(self._timer_followup):
                self._timer_followup.start(max(delay_ms + 100, 140))

        @_safe_call
        def stop_timer(self):
            if self._timer is not None and _is_valid_qobj(self._timer):
                self._timer.stop()
            if self._timer_followup is not None and _is_valid_qobj(self._timer_followup):
                self._timer_followup.stop()

        @_safe_call
        def on_deferred_ui_refresh(self):
            if not self._mgr or not self._mgr.initialized or not self._mgr.enabled:
                return
            self._mgr._translate_toolbars_and_docks()
            self._mgr._translate_all_tabbars()
            self._mgr._translate_active_dialogs()

        @_safe_call
        def on_focus_changed(self, old_widget, new_widget):
            if not self._mgr or not self._mgr.initialized:
                return
            self._mgr._on_focus_changed(old_widget, new_widget)

        @_safe_call
        def on_focus_window_changed(self, _focus_window=None):
            if not self._mgr or not self._mgr.initialized or not self._mgr.enabled:
                return
            self._mgr._translate_active_dialogs()
            self.schedule_ui_refresh(25)

        @_safe_call
        def on_dialog_interaction(self, *_args):
            if not self._mgr or not self._mgr.initialized or not self._mgr.enabled:
                return
            self.schedule_ui_refresh(20)

        @_safe_call
        def on_statusbar_message_changed(self, msg=""):
            if not self._mgr or not self._mgr.initialized or not self._mgr.enabled:
                return
            sb = self.sender()
            if _is_valid_qobj(sb) and isinstance(sb, QtWidgets.QStatusBar):
                self._mgr._translate_statusbar(sb, msg)

        @_safe_call
        def on_tab_current_changed(self, _idx=0):
            if not self._mgr or not self._mgr.initialized:
                return
            tabw = self.sender()
            if _is_valid_qobj(tabw) and isinstance(tabw, QtWidgets.QTabBar):
                self._mgr._translate_single_tabbar(tabw)
            self._mgr._translate_active_dialogs()
            self.schedule_ui_refresh(20)

    return _QtSignalReceiver(manager)


class IdaZhUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, manager):
        super().__init__()
        self._mgr = manager

    @_safe_call
    def ready_to_run(self):
        if self._mgr:
            self._mgr.apply_all()

    @_safe_call
    def database_inited(self, is_new_database, idc_script):
        if self._mgr:
            self._mgr.apply_all()

    @_safe_call
    def debugger_menu_change(self, enable):
        if self._mgr:
            self._mgr.apply_all()

    @_safe_call
    def plugin_loaded(self, plugin_info):
        if self._mgr:
            self._mgr.apply_all()

    @_safe_call
    def desktop_applied(self, name, from_idb, type):
        if self._mgr:
            self._mgr.on_widget_event()

    @_safe_call
    def widget_visible(self, widget):
        if self._mgr:
            self._mgr.on_widget_event()

    @_safe_call
    def current_widget_changed(self, widget, prev_widget):
        if self._mgr:
            self._mgr.on_widget_event()

    @_safe_call
    def preprocess_action(self, name):
        if self._mgr:
            self._mgr.on_action_event()
        return 0

    @_safe_call
    def postprocess_action(self):
        if self._mgr:
            self._mgr.on_action_event()

    @_safe_call
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if self._mgr:
            self._mgr.on_popup_ready()

    @_safe_call
    def about_to_exit(self):
        if self._mgr:
            self._mgr.stop()


class IdaZhLocalizationManager:
    TOGGLE_ACTION_NAME = "ida_zh_cn:toggle_language"

    _STATIC_ANCHOR_ACTIONS = {
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

    _TOOLBAR_TITLES = {
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

    _SAFE_COMBOBOX_NAMES = ("DebuggerList", "comboBkgColor", "comboColor")

    def __init__(self):
        self.dict_path = _resolve_dict_path()
        self.state_path = _resolve_state_path()
        self.enabled = True
        self.initialized = False
        self._receiver = None
        self._ui_hooks = None
        self._action_registered = False

        self.top_level_menus = {}
        self.top_level_menus_lower = {}
        self.submenu_clean_to_closed = {}
        self.actions_label = {}
        self.actions_tooltip = {}
        self.action_text_to_zh = {}
        self.action_text_to_zh_lower = {}
        self.qt_translate = {}
        self.qt_translate_clean = {}
        self.dialog_text = {}
        self.dialog_text_lower = {}
        self.tab_titles = {}
        self.tab_titles_lower = {}
        self.tab_prefixes = []

        self._orig_action_labels = {}
        self._orig_action_tooltips = {}
        self._translated_actions = set()
        self._zh_tab_to_en = {}

    @_safe_call
    def load_config_and_dict(self):
        self.dict_path = _resolve_dict_path()
        self.state_path = _resolve_state_path()

        if os.path.isfile(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    st = json.load(f)
                    self.enabled = bool(st.get("enabled", True))
            except Exception:
                self.enabled = True

        if not os.path.isfile(self.dict_path):
            ida_kernwin.msg(f"[IDA-ZH] 未找到词典文件: {self.dict_path}\n")
            return False

        with open(self.dict_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.top_level_menus = data.get("top_level_menus", {})
        self.top_level_menus_lower = {k.lower(): v for k, v in self.top_level_menus.items()}
        self.submenu_clean_to_closed = data.get("submenu_clean_to_closed", {})
        self.actions_label = data.get("actions_label", {})
        self.actions_tooltip = data.get("actions_tooltip", {})
        self.action_text_to_zh = data.get("action_text_to_zh", {})
        self.action_text_to_zh_lower = {
            _strip_accel(k).lower(): v for k, v in self.action_text_to_zh.items() if k
        }
        self.qt_translate = data.get("qt_translate", {})
        self.qt_translate_clean = {}
        for k, v in self.qt_translate.items():
            if not k:
                continue
            ck = _strip_accel(k).strip().lower()
            self.qt_translate_clean[ck] = v
            if ck.endswith(":"):
                ck_no_colon = ck[:-1].strip()
                if ck_no_colon and ck_no_colon not in self.qt_translate_clean:
                    self.qt_translate_clean[ck_no_colon] = _strip_accel(v).rstrip(":：").strip()

        self.dialog_text = data.get("dialog_text", {})
        self.dialog_text_lower = {}
        for k, v in self.dialog_text.items():
            if not k:
                continue
            ck = _strip_accel(k).strip().lower()
            self.dialog_text_lower[ck] = v
            if ck.endswith(":"):
                ck_no_colon = ck[:-1].strip()
                if ck_no_colon and ck_no_colon not in self.dialog_text_lower:
                    self.dialog_text_lower[ck_no_colon] = _strip_accel(v).rstrip(":：").strip()

        self.tab_titles = data.get("tab_titles", {})
        self.tab_titles_lower = {k.lower(): v for k, v in self.tab_titles.items()}
        self.tab_prefixes = data.get("tab_prefixes", [])
        self._zh_tab_to_en = {v: k for k, v in self.tab_titles.items()}
        return True

    @_safe_call
    def save_state(self):
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({"enabled": self.enabled}, f, indent=2)
        except Exception:
            pass

    @_safe_call
    def start(self):
        if self.initialized:
            return True
        if not ida_kernwin.is_idaq():
            return False
        if not _ensure_qt():
            return False
        if not self.load_config_and_dict():
            return False

        app = QtWidgets.QApplication.instance()
        if app is None:
            return False

        if self._receiver is None:
            self._receiver = _create_signal_receiver(self)
            if self._receiver is not None:
                try:
                    app.focusChanged.connect(self._receiver.on_focus_changed)
                except Exception:
                    pass
                try:
                    app.focusWindowChanged.connect(self._receiver.on_focus_window_changed)
                except Exception:
                    pass

        if self._ui_hooks is None:
            self._ui_hooks = IdaZhUIHooks(self)
            self._ui_hooks.hook()

        self._register_toggle_action()

        self.initialized = True
        self.apply_all()
        ida_kernwin.msg(
            "[IDA-ZH] IDA 简体中文插件已加载 | Author: CHENDIYAO (转发请注明出处) | Ctrl+Alt+L 切换中英文\n"
        )
        return True

    @_safe_call
    def stop(self):
        if not self.initialized and self._ui_hooks is None and self._receiver is None:
            return
        self.initialized = False

        if self._ui_hooks is not None:
            try:
                self._ui_hooks.unhook()
            except Exception:
                pass
            self._ui_hooks = None

        if self._receiver is not None:
            try:
                self._receiver.stop_timer()
                if QtWidgets is not None:
                    app = QtWidgets.QApplication.instance()
                    if app is not None:
                        try:
                            app.focusChanged.disconnect(self._receiver.on_focus_changed)
                        except Exception:
                            pass
                        try:
                            app.focusWindowChanged.disconnect(self._receiver.on_focus_window_changed)
                        except Exception:
                            pass
                if Shiboken is not None and Shiboken.isValid(self._receiver):
                    Shiboken.delete(self._receiver)
            except Exception:
                pass
            self._receiver = None

        if self._action_registered:
            try:
                ida_kernwin.unregister_action(self.TOGGLE_ACTION_NAME)
            except Exception:
                pass
            self._action_registered = False

    @_safe_call
    def _register_toggle_action(self):
        if self._action_registered:
            return
        mgr = self

        class ToggleHandler(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                mgr.toggle_language()
                return 1

            def update(self, ctx):
                return ida_kernwin.AST_ENABLE_ALWAYS

        desc = ida_kernwin.action_desc_t(
            self.TOGGLE_ACTION_NAME,
            "切换中英文界面 (Toggle Chinese/English UI)",
            ToggleHandler(),
            "Ctrl+Alt+L",
            "在中文与英文界面之间切换",
            -1,
        )
        if ida_kernwin.register_action(desc):
            self._action_registered = True
            ida_kernwin.attach_action_to_menu(
                "Options/",
                self.TOGGLE_ACTION_NAME,
                ida_kernwin.SETMENU_APP,
            )

    @_safe_call
    def toggle_language(self):
        self.enabled = not self.enabled
        self.save_state()
        if self.enabled:
            self._translated_actions.clear()
            self.apply_all()
            ida_kernwin.msg("[IDA-ZH] 已切换为中文界面 (Ctrl+Alt+L)\n")
        else:
            self.restore_english()
            ida_kernwin.msg("[IDA-ZH] Switched to English UI (Ctrl+Alt+L)\n")

    @_safe_call
    def apply_all(self):
        if not self.initialized or not self.enabled or not _ensure_qt():
            return
        self._translate_registered_actions()
        self._translate_toolbars_and_docks()
        self._translate_all_menus()
        self._translate_all_tabbars()
        self._translate_active_dialogs()
        if self._receiver is not None:
            self._receiver.schedule_ui_refresh(30)

    @_safe_call
    def restore_english(self):
        if not _ensure_qt():
            return
        self._translated_actions.clear()
        for act_name, orig_lbl in list(self._orig_action_labels.items()):
            try:
                ida_kernwin.update_action_label(act_name, orig_lbl)
            except Exception:
                pass
        for act_name, orig_tip in list(self._orig_action_tooltips.items()):
            try:
                ida_kernwin.update_action_tooltip(act_name, orig_tip)
            except Exception:
                pass

        app = QtWidgets.QApplication.instance()
        if app is not None:
            for w in list(app.allWidgets()):
                if not _is_valid_qobj(w):
                    continue
                if isinstance(w, QtWidgets.QMenu):
                    obj_name = w.objectName() or ""
                    if obj_name in ("DebuggerSelected", "DebuggerUnselected", "DebuggerRunToAndAttach"):
                        menu_act = w.menuAction()
                        is_vis = bool(_is_valid_qobj(menu_act) and menu_act.isVisible())
                        w.setTitle("Deb&ugger" if is_vis else obj_name)
                    else:
                        orig_title = w.property("_ida_zh_orig_title")
                        if orig_title:
                            w.setTitle(str(orig_title))
                    for act in w.actions():
                        if _is_valid_qobj(act):
                            orig_txt = act.property("_ida_zh_orig_text")
                            if orig_txt:
                                act.setText(str(orig_txt))
                elif isinstance(w, (QtWidgets.QToolBar, QtWidgets.QDockWidget)):
                    orig_title = w.property("_ida_zh_orig_title")
                    if orig_title:
                        w.setWindowTitle(str(orig_title))
                    toggle_act = w.toggleViewAction()
                    if _is_valid_qobj(toggle_act):
                        orig_act_txt = toggle_act.property("_ida_zh_orig_text")
                        if orig_act_txt:
                            toggle_act.setText(str(orig_act_txt))
                elif isinstance(w, QtWidgets.QComboBox):
                    if (w.objectName() or "") in self._SAFE_COMBOBOX_NAMES:
                        self._restore_combobox_items(w)
                elif isinstance(w, QtWidgets.QTabBar):
                    self._restore_tabbar(w)
                elif isinstance(w, (QtWidgets.QDialog, QtWidgets.QMainWindow)):
                    self._restore_dialog(w)

    @_safe_call
    def _translate_registered_actions(self):
        for act_name, zh_label in self.actions_label.items():
            if not zh_label or act_name in self._translated_actions:
                continue
            try:
                if act_name not in self._orig_action_labels:
                    cur_lbl = ida_kernwin.get_action_label(act_name)
                    if not cur_lbl:
                        continue
                    self._orig_action_labels[act_name] = cur_lbl
                    cur_tip = ida_kernwin.get_action_tooltip(act_name)
                    if cur_tip is not None:
                        self._orig_action_tooltips[act_name] = cur_tip

                target_lbl = self._STATIC_ANCHOR_ACTIONS.get(act_name, _strip_accel(zh_label))
                if ida_kernwin.update_action_label(act_name, target_lbl):
                    self._translated_actions.add(act_name)

                zh_tip = self.actions_tooltip.get(act_name)
                if zh_tip:
                    ida_kernwin.update_action_tooltip(act_name, zh_tip)
            except Exception:
                continue

    @_safe_call
    def _translate_toolbars_and_docks(self):
        if not self.enabled or not _ensure_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        for w in list(app.allWidgets()):
            if not _is_valid_qobj(w):
                continue
            if isinstance(w, (QtWidgets.QToolBar, QtWidgets.QDockWidget)):
                title = w.windowTitle() or ""
                clean_title = _strip_accel(title)
                zh = self._TOOLBAR_TITLES.get(clean_title) or self.tab_titles.get(clean_title)
                if zh and not _has_cjk(title):
                    w.setProperty("_ida_zh_orig_title", title)
                    w.setWindowTitle(zh)
                toggle_act = w.toggleViewAction()
                if _is_valid_qobj(toggle_act):
                    act_txt = toggle_act.text() or ""
                    clean_act = _strip_accel(act_txt)
                    zh_act = zh or self._TOOLBAR_TITLES.get(clean_act) or self.tab_titles.get(clean_act)
                    if zh_act and act_txt and not _has_cjk(act_txt):
                        toggle_act.setProperty("_ida_zh_orig_text", act_txt)
                        toggle_act.setText(zh_act)
            elif isinstance(w, QtWidgets.QComboBox):
                if (w.objectName() or "") in self._SAFE_COMBOBOX_NAMES:
                    self._translate_combobox_items(w)

    @_safe_call
    def _translate_combobox_items(self, cb):
        if not _is_valid_qobj(cb):
            return
        count = cb.count()
        for i in range(count):
            it_txt = cb.itemText(i) or ""
            if it_txt and not _has_cjk(it_txt):
                zh_it = self._lookup_dialog_string(it_txt)
                if zh_it and zh_it != it_txt:
                    cb.setProperty(f"_ida_zh_orig_item_{i}", it_txt)
                    cb.setItemText(i, zh_it)

    @_safe_call
    def _restore_combobox_items(self, cb):
        if not _is_valid_qobj(cb):
            return
        count = cb.count()
        for i in range(count):
            orig_it = cb.property(f"_ida_zh_orig_item_{i}")
            if orig_it:
                cb.setItemText(i, str(orig_it))

    @_safe_call
    def _translate_all_menus(self):
        app = QtWidgets.QApplication.instance()
        if app is None:
            return

        widgets = list(app.allWidgets())

        for w in widgets:
            if not _is_valid_qobj(w):
                continue
            if isinstance(w, QtWidgets.QMenuBar):
                for act in w.actions():
                    if not _is_valid_qobj(act):
                        continue
                    sub = act.menu()
                    if _is_valid_qobj(sub):
                        self._setup_static_menu(sub, is_top_level=True)

        for w in widgets:
            if not _is_valid_qobj(w):
                continue
            if isinstance(w, QtWidgets.QMenu):
                is_top = bool(w.property("_ida_zh_is_top"))
                self._setup_static_menu(w, is_top_level=is_top)

    @_safe_call
    def _setup_static_menu(self, qmenu, is_top_level=False):
        if not _is_valid_qobj(qmenu):
            return

        if is_top_level:
            qmenu.setProperty("_ida_zh_is_top", True)
        else:
            is_top_level = bool(qmenu.property("_ida_zh_is_top"))

        obj_name = qmenu.objectName() or ""
        cur_title = qmenu.title() or ""

        if cur_title and not _has_cjk(cur_title):
            qmenu.setProperty("_ida_zh_orig_title", cur_title)

        orig_title = str(qmenu.property("_ida_zh_orig_title") or cur_title)
        clean_orig = _strip_accel(_strip_bilingual_suffix(orig_title)).lower()

        if self.enabled:
            is_role_top = obj_name.endswith((":Edit", ":Jump", ":Search", ":File", ":Windows", ":Help"))
            if is_top_level or is_role_top or obj_name in self.top_level_menus:
                if obj_name in ("DebuggerSelected", "DebuggerUnselected", "DebuggerRunToAndAttach"):
                    menu_act = qmenu.menuAction()
                    is_vis = bool(_is_valid_qobj(menu_act) and menu_act.isVisible())
                    target_dbg_title = "Deb&ugger 调试器" if is_vis else obj_name
                    if qmenu.title() != target_dbg_title:
                        qmenu.setTitle(target_dbg_title)
                elif orig_title not in ("DebuggerSelected", "DebuggerUnselected", "DebuggerRunToAndAttach"):
                    zh_top = (
                        self.top_level_menus.get(obj_name)
                        or self.top_level_menus_lower.get(obj_name.lower())
                        or self.top_level_menus_lower.get(clean_orig)
                    )
                    if zh_top and qmenu.title() != zh_top:
                        qmenu.setTitle(zh_top)
            else:
                closed_title = self.submenu_clean_to_closed.get(clean_orig)
                if closed_title:
                    if qmenu.title() != closed_title:
                        qmenu.setTitle(closed_title)
                else:
                    zh_sub = (
                        self.action_text_to_zh.get(orig_title)
                        or self.action_text_to_zh_lower.get(clean_orig)
                    )
                    if zh_sub and qmenu.title() != zh_sub:
                        qmenu.setTitle(zh_sub)

        is_toolbar_menu = clean_orig in ("toolbars", "toolbar")
        for act in qmenu.actions():
            if not _is_valid_qobj(act) or act.isSeparator():
                continue
            sub = act.menu()
            if _is_valid_qobj(sub) and sub is not qmenu:
                self._setup_static_menu(sub, is_top_level=False)
            elif is_toolbar_menu and self.enabled:
                txt = act.text() or ""
                if txt and not _has_cjk(txt):
                    clean_act = _strip_accel(txt)
                    zh_act = self._TOOLBAR_TITLES.get(clean_act)
                    if zh_act:
                        act.setProperty("_ida_zh_orig_text", txt)
                        act.setText(zh_act)

    @_safe_call
    def on_popup_ready(self):
        if not self.initialized or not self.enabled or not _ensure_qt():
            return
        self._translate_toolbars_and_docks()
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        for w in list(app.allWidgets()):
            if _is_valid_qobj(w) and isinstance(w, QtWidgets.QMenu):
                if not w.property("_ida_zh_is_top"):
                    self._translate_popup_menu_once(w)

    @_safe_call
    def _translate_popup_menu_once(self, qmenu):
        if not _is_valid_qobj(qmenu) or bool(qmenu.property("_ida_zh_is_top")):
            return
        for act in qmenu.actions():
            if not _is_valid_qobj(act) or act.isSeparator():
                continue
            sub = act.menu()
            is_sub = _is_valid_qobj(sub) and (sub is not qmenu)
            if is_sub:
                self._setup_static_menu(sub, is_top_level=False)
                self._translate_popup_menu_once(sub)
                continue

            txt = act.text() or ""
            if not txt or _has_cjk(txt):
                continue

            parts = txt.split("\t", 1)
            main_txt = parts[0]
            shortcut_suffix = ("\t" + parts[1]) if len(parts) > 1 else ""
            clean_main = _strip_accel(main_txt)
            clean_lower = clean_main.lower()

            zh_txt = (
                self._TOOLBAR_TITLES.get(clean_main)
                or self.action_text_to_zh.get(main_txt)
                or self.action_text_to_zh.get(clean_main)
                or self.action_text_to_zh_lower.get(clean_lower)
            )
            if zh_txt:
                if not act.property("_ida_zh_orig_text"):
                    act.setProperty("_ida_zh_orig_text", txt)
                act.setText(_strip_accel(zh_txt) + shortcut_suffix)

    @_safe_call
    def _translate_all_tabbars(self):
        if not self.enabled or not _ensure_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        for w in list(app.allWidgets()):
            if _is_valid_qobj(w) and isinstance(w, QtWidgets.QTabBar):
                self._translate_single_tabbar(w)

    @_safe_call
    def _translate_single_tabbar(self, tabbar):
        if not _is_valid_qobj(tabbar):
            return
        if self._receiver is not None and not tabbar.property("_ida_zh_tabbar_hooked"):
            tabbar.setProperty("_ida_zh_tabbar_hooked", True)
            try:
                tabbar.currentChanged.connect(self._receiver.on_tab_current_changed)
            except Exception:
                pass
        count = tabbar.count()
        for i in range(count):
            txt = tabbar.tabText(i)
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
                    tabbar.setTabText(i, zh)
                continue
            for en_prefix, zh_prefix in self.tab_prefixes:
                if clean.startswith(en_prefix):
                    suffix = clean[len(en_prefix):]
                    new_txt = zh_prefix + suffix
                    if txt != new_txt:
                        tabbar.setTabText(i, new_txt)
                    break

    @_safe_call
    def _restore_tabbar(self, tabbar):
        if not _is_valid_qobj(tabbar):
            return
        count = tabbar.count()
        for i in range(count):
            txt = tabbar.tabText(i)
            if not txt:
                continue
            if txt in self._zh_tab_to_en:
                tabbar.setTabText(i, self._zh_tab_to_en[txt])
                continue
            for en_prefix, zh_prefix in self.tab_prefixes:
                if txt.startswith(zh_prefix):
                    suffix = txt[len(zh_prefix):]
                    tabbar.setTabText(i, en_prefix + suffix)
                    break

    @_safe_call
    def on_action_event(self):
        if not self.initialized or not self.enabled or not _ensure_qt():
            return
        if self._receiver is not None:
            self._receiver.schedule_ui_refresh(25)

    @_safe_call
    def on_widget_event(self):
        if not self.initialized or not self.enabled or not _ensure_qt():
            return
        self._translate_toolbars_and_docks()
        self._translate_all_tabbars()
        self._translate_active_dialogs()
        if self._receiver is not None:
            self._receiver.schedule_ui_refresh(30)

    @_safe_call
    def _translate_active_dialogs(self):
        if not self.enabled or not _ensure_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        popup = app.activePopupWidget()
        if _is_valid_qobj(popup) and isinstance(popup, QtWidgets.QMenu):
            if not popup.property("_ida_zh_is_top"):
                self._translate_popup_menu_once(popup)
        for top in list(app.topLevelWidgets()):
            if not _is_valid_qobj(top) or not top.isVisible():
                continue
            if isinstance(top, QtWidgets.QDialog):
                self._translate_dialog(top)
            elif isinstance(top, QtWidgets.QMainWindow):
                self._translate_dialog(top, is_mainwindow=True)
            elif isinstance(top, QtWidgets.QWidget) and not isinstance(top, QtWidgets.QMenu):
                self._translate_dialog(top)

    @_safe_call
    def _on_focus_changed(self, old_widget, new_widget):
        if not self.initialized or not self.enabled:
            return
        self._translate_active_dialogs()
        self._translate_toolbars_and_docks()
        self._translate_all_tabbars()
        if self._receiver is not None:
            self._receiver.schedule_ui_refresh(25)

    @_safe_call
    def _translate_dialog(self, dlg, is_mainwindow=False):
        if not self.enabled or not _is_valid_qobj(dlg):
            return

        if not is_mainwindow:
            title = dlg.windowTitle() or ""
            if title and not _has_cjk(title):
                zh_title = self._lookup_dialog_string(title)
                if zh_title and zh_title != title:
                    dlg.setProperty("_ida_zh_orig_title", title)
                    dlg.setWindowTitle(zh_title)

        for child in dlg.findChildren(QtWidgets.QWidget):
            if not _is_valid_qobj(child):
                continue

            if isinstance(
                child,
                (
                    QtWidgets.QPushButton,
                    QtWidgets.QCheckBox,
                    QtWidgets.QRadioButton,
                    QtWidgets.QToolButton,
                ),
            ):
                if is_mainwindow and isinstance(child, QtWidgets.QToolButton):
                    continue
                txt = child.text() or ""
                if txt and not _has_cjk(txt):
                    zh = self._lookup_dialog_string(txt)
                    if zh and zh != txt:
                        child.setProperty("_ida_zh_orig_text", txt)
                        child.setText(zh)
                if self._receiver is not None and not child.property("_ida_zh_btn_hooked"):
                    child.setProperty("_ida_zh_btn_hooked", True)
                    try:
                        if isinstance(child, (QtWidgets.QCheckBox, QtWidgets.QRadioButton)):
                            child.toggled.connect(self._receiver.on_tab_current_changed)
                        else:
                            child.clicked.connect(self._receiver.on_dialog_interaction)
                    except Exception:
                        pass

            elif isinstance(child, QtWidgets.QGroupBox):
                gb_title = child.title() or ""
                if gb_title and not _has_cjk(gb_title):
                    zh = self._lookup_dialog_string(gb_title)
                    if zh and zh != gb_title:
                        child.setProperty("_ida_zh_orig_title", gb_title)
                        child.setTitle(zh)

            elif isinstance(child, QtWidgets.QLabel):
                lbl_txt = child.text() or ""
                if lbl_txt and not _has_cjk(lbl_txt) and len(lbl_txt) < 400:
                    if lbl_txt in self.qt_translate:
                        child.setProperty("_ida_zh_orig_text", lbl_txt)
                        child.setText(self.qt_translate[lbl_txt])
                    elif not lbl_txt.lstrip().startswith("<"):
                        zh = self._lookup_dialog_string(lbl_txt)
                        if zh and zh != lbl_txt:
                            child.setProperty("_ida_zh_orig_text", lbl_txt)
                            child.setText(zh)

            elif isinstance(child, QtWidgets.QComboBox):
                if (child.objectName() or "") in self._SAFE_COMBOBOX_NAMES:
                    self._translate_combobox_items(child)

            elif isinstance(child, QtWidgets.QListWidget):
                if (child.objectName() or "") == "nats":
                    for i in range(child.count()):
                        item = child.item(i)
                        if item is not None:
                            it_txt = item.text() or ""
                            if it_txt and not _has_cjk(it_txt):
                                zh_it = self._lookup_dialog_string(it_txt)
                                if zh_it and zh_it != it_txt:
                                    item.setData(QtCore.Qt.UserRole + 999, it_txt)
                                    item.setText(zh_it)

            elif isinstance(child, QtWidgets.QAbstractItemView):
                if not is_mainwindow and self._receiver is not None and not child.property("_ida_zh_sel_hooked"):
                    sel_model = child.selectionModel()
                    if _is_valid_qobj(sel_model):
                        child.setProperty("_ida_zh_sel_hooked", True)
                        try:
                            sel_model.selectionChanged.connect(self._receiver.on_dialog_interaction)
                        except Exception:
                            pass
                if not is_mainwindow and isinstance(child, QtWidgets.QTableWidget):
                    for col in range(child.columnCount()):
                        hdr_item = child.horizontalHeaderItem(col)
                        if hdr_item is not None:
                            h_txt = hdr_item.text() or ""
                            if h_txt and not _has_cjk(h_txt):
                                zh_h = self._lookup_dialog_string(h_txt)
                                if zh_h and zh_h != h_txt:
                                    hdr_item.setData(QtCore.Qt.UserRole + 999, h_txt)
                                    hdr_item.setText(zh_h)
                elif not is_mainwindow and isinstance(child, QtWidgets.QTreeWidget):
                    hdr_item = child.headerItem()
                    if hdr_item is not None:
                        for col in range(child.columnCount()):
                            h_txt = hdr_item.text(col) or ""
                            if h_txt and not _has_cjk(h_txt):
                                zh_h = self._lookup_dialog_string(h_txt)
                                if zh_h and zh_h != h_txt:
                                    hdr_item.setData(col, QtCore.Qt.UserRole + 999, h_txt)
                                    hdr_item.setText(col, zh_h)

            elif isinstance(child, QtWidgets.QTabBar):
                if not is_mainwindow:
                    for i in range(child.count()):
                        t_txt = child.tabText(i) or ""
                        if t_txt and not _has_cjk(t_txt):
                            zh = self._lookup_dialog_string(t_txt)
                            if zh and zh != t_txt:
                                child.setProperty(f"_ida_zh_orig_tab_{i}", t_txt)
                                child.setTabText(i, zh)

            elif isinstance(child, QtWidgets.QTabWidget):
                if self._receiver is not None and not child.property("_ida_zh_tab_hooked"):
                    child.setProperty("_ida_zh_tab_hooked", True)
                    try:
                        child.currentChanged.connect(self._receiver.on_tab_current_changed)
                    except Exception:
                        pass

            elif isinstance(child, QtWidgets.QStatusBar):
                self._translate_statusbar(child)
                if self._receiver is not None and not child.property("_ida_zh_sb_hooked"):
                    child.setProperty("_ida_zh_sb_hooked", True)
                    try:
                        child.messageChanged.connect(self._receiver.on_statusbar_message_changed)
                    except Exception:
                        pass

    @_safe_call
    def _translate_statusbar(self, sb, msg=None):
        if not self.enabled or not _is_valid_qobj(sb):
            return
        cur = msg if msg is not None else (sb.currentMessage() or "")
        if not cur or _has_cjk(cur):
            return
        zh = self._lookup_dialog_string(cur)
        if zh and zh != cur:
            sb.setProperty("_ida_zh_orig_msg", cur)
            sb.showMessage(zh)

    @_safe_call
    def _restore_dialog(self, dlg):
        if not _is_valid_qobj(dlg):
            return
        if not isinstance(dlg, QtWidgets.QMainWindow):
            orig_title = dlg.property("_ida_zh_orig_title")
            if orig_title:
                dlg.setWindowTitle(str(orig_title))
        for child in dlg.findChildren(QtWidgets.QWidget):
            if not _is_valid_qobj(child):
                continue
            if isinstance(
                child,
                (
                    QtWidgets.QPushButton,
                    QtWidgets.QCheckBox,
                    QtWidgets.QRadioButton,
                    QtWidgets.QToolButton,
                    QtWidgets.QLabel,
                ),
            ):
                orig_txt = child.property("_ida_zh_orig_text")
                if orig_txt:
                    child.setText(str(orig_txt))
            elif isinstance(child, QtWidgets.QGroupBox):
                orig_gb = child.property("_ida_zh_orig_title")
                if orig_gb:
                    child.setTitle(str(orig_gb))
            elif isinstance(child, QtWidgets.QComboBox):
                if (child.objectName() or "") in self._SAFE_COMBOBOX_NAMES:
                    self._restore_combobox_items(child)
            elif isinstance(child, QtWidgets.QListWidget):
                if (child.objectName() or "") == "nats":
                    for i in range(child.count()):
                        item = child.item(i)
                        if item is not None:
                            orig_it = item.data(QtCore.Qt.UserRole + 999)
                            if orig_it:
                                item.setText(str(orig_it))
            elif isinstance(child, QtWidgets.QTabBar):
                for i in range(child.count()):
                    orig_tab = child.property(f"_ida_zh_orig_tab_{i}")
                    if orig_tab:
                        child.setTabText(i, str(orig_tab))
            elif isinstance(child, QtWidgets.QStatusBar):
                orig_msg = child.property("_ida_zh_orig_msg")
                if orig_msg:
                    child.showMessage(str(orig_msg))

    def _lookup_dialog_string(self, text):
        if not text:
            return ""
        raw = text.strip()
        if raw in self.dialog_text:
            return self.dialog_text[raw]
        if raw in self.qt_translate:
            return self.qt_translate[raw]

        clean = _strip_accel(raw)
        if clean in self.dialog_text:
            return self.dialog_text[clean]
        if clean in self.tab_titles:
            return self.tab_titles[clean]

        clean_lower = clean.lower()
        if clean_lower in self.dialog_text_lower:
            return self.dialog_text_lower[clean_lower]
        if clean_lower in self.qt_translate_clean:
            return self.qt_translate_clean[clean_lower]
        if clean_lower in self.tab_titles_lower:
            return self.tab_titles_lower[clean_lower]

        for en_prefix, zh_prefix in self.tab_prefixes:
            if clean.startswith(en_prefix):
                return zh_prefix + clean[len(en_prefix):]

        if "\n" in raw:
            lines = raw.splitlines()
            translated_lines = []
            any_changed = False
            for ln in lines:
                s_ln = ln.strip()
                if not s_ln:
                    translated_lines.append(ln)
                    continue
                zh_ln = self._lookup_dialog_string(s_ln)
                if zh_ln and zh_ln != s_ln:
                    translated_lines.append(zh_ln)
                    any_changed = True
                else:
                    translated_lines.append(ln)
            if any_changed:
                return "\n".join(translated_lines)

        m_load = _RE_LOAD_FILE_AS.match(clean)
        if m_load:
            return f"加载文件 {m_load.group(1)} 为"

        m_line = _RE_LINE_OF.match(clean)
        if m_line:
            suffix = m_line.group(3) or ""
            if suffix == ", (outdated)":
                suffix = " (已过期)"
            elif suffix.endswith(" (outdated)"):
                suffix = suffix[:-11] + " (已过期)"
            return f"第 {m_line.group(1)} / {m_line.group(2)} 行{suffix}"

        m_disk = _RE_DISK_SPACE.match(clean)
        if m_disk:
            return f"磁盘可用: {m_disk.group(1)}"

        m_au = _RE_AU_STATE.match(clean)
        if m_au:
            st = m_au.group(1).strip()
            if st.lower() == "idle":
                return "自动分析: 空闲"
            return f"自动分析: {st}"

        m_nav = _RE_NAV_SCALE.match(clean)
        if m_nav:
            return f"导航栏比例: {m_nav.group(1)} 像素 = {m_nav.group(2)} 字节; 范围: {m_nav.group(3)}"

        m_sync = _RE_SYNC_WITH.match(clean)
        if m_sync:
            target = m_sync.group(1).strip()
            zh_target = self._lookup_dialog_string(target) or target
            return f"(已与 {zh_target} 同步)"

        m_font = _RE_SELECT_FONT.match(clean)
        if m_font:
            target = m_font.group(1).strip()
            zh_target = self._lookup_dialog_string(target) or target
            return f"选择字体: {zh_target}"

        m_seg = _RE_SEGMENTS_VISIBLE.match(clean)
        if m_seg:
            return f"从 {m_seg.group(1)} 可见的段"

        m_val = _RE_NEW_VALUE_OF.match(clean)
        if m_val:
            return f"{m_val.group(1)} 的新值"

        m_ext = _RE_EDIT_EXT_ASSOC.match(clean)
        if m_ext:
            return f"编辑文件扩展名 '{m_ext.group(1)}' 关联"

        m_conv = _RE_CONVERT_EN_MASSE.match(clean)
        if m_conv:
            return f'批量转换为 "{m_conv.group(1)}"'

        m_chunk = _RE_CHUNK_START.match(clean)
        if m_chunk:
            return f"分块 {m_chunk.group(1)} 起始地址"

        for en_suf, zh_suf in (
            (" (non-graph)", " (非图形)"),
            (" (graph)", " (图形)"),
            (" (default)", " (默认)"),
            (" (highlighted)", " (高亮)"),
        ):
            if clean_lower.endswith(en_suf):
                base = clean_lower[: -len(en_suf)].strip()
                zh_base = self.dialog_text_lower.get(base) or self.qt_translate_clean.get(base)
                if zh_base:
                    return _strip_accel(zh_base) + zh_suf

        for en_pref, zh_pref in (
            ("Line prefix example: ", "行前缀示例: "),
            ("Example: ", "示例: "),
            ("Supported languages: ", "支持的语言: "),
            ("Current processor: ", "当前处理器: "),
            ("Debug application setup: ", "调试应用程序设置: "),
            ("Xref Graph: ", "交叉引用图: "),
        ):
            if clean.startswith(en_pref):
                return zh_pref + clean[len(en_pref) :]

        if clean_lower.endswith(":"):
            base = clean_lower[:-1].strip()
            zh_base = self.dialog_text_lower.get(base) or self.qt_translate_clean.get(base)
            if zh_base:
                return _strip_accel(zh_base).rstrip(":：") + ":"
        if clean_lower.endswith("..."):
            base = clean_lower[:-3].strip()
            zh_base = self.dialog_text_lower.get(base) or self.qt_translate_clean.get(base)
            if zh_base:
                return _strip_accel(zh_base).rstrip(".") + "..."
        return ""


_g_manager = None


class IdaZhCnPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_KEEP
    comment = "IDA 简体中文插件 | Author: CHENDIYAO (转发请注明出处)"
    help = "作者: CHENDIYAO (转发请注明出处) | 快捷键 Ctrl+Alt+L 切换中英文"
    wanted_name = "IDA 简体中文汉化 [By CHENDIYAO]"
    wanted_hotkey = "Ctrl-Alt-L"

    @_safe_call
    def init(self):
        global _g_manager
        if not ida_kernwin.is_idaq():
            return ida_idaapi.PLUGIN_SKIP
        if _g_manager is None:
            _g_manager = IdaZhLocalizationManager()
        _g_manager.start()
        return ida_idaapi.PLUGIN_KEEP

    @_safe_call
    def run(self, arg):
        global _g_manager
        if _g_manager is not None:
            if not _g_manager.initialized:
                _g_manager.start()
            else:
                _g_manager.toggle_language()

    @_safe_call
    def term(self):
        global _g_manager
        if _g_manager is not None:
            _g_manager.stop()
            _g_manager = None


def PLUGIN_ENTRY():
    return IdaZhCnPlugin()
