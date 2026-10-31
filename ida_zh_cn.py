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
    s = re.sub(r"~([A-Za-z0-9])~", r"\1", text)
    s = re.sub(r"\(&+[A-Za-z0-9]\)", "", s)
    return s.replace("&", "").strip()


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

        @_safe_call
        def schedule_ui_refresh(self, delay_ms=50):
            if not self._mgr or not self._mgr.initialized:
                return
            if self._timer is not None and _is_valid_qobj(self._timer):
                self._timer.start(delay_ms)

        @_safe_call
        def stop_timer(self):
            if self._timer is not None and _is_valid_qobj(self._timer):
                self._timer.stop()

        @_safe_call
        def on_deferred_ui_refresh(self):
            if not self._mgr or not self._mgr.initialized or not self._mgr.enabled:
                return
            self._mgr._translate_all_tabbars()
            self._mgr._translate_active_dialogs()

        @_safe_call
        def on_focus_changed(self, old_widget, new_widget):
            if not self._mgr or not self._mgr.initialized:
                return
            self._mgr._on_focus_changed(old_widget, new_widget)

        @_safe_call
        def on_tab_current_changed(self, _idx=0):
            if not self._mgr or not self._mgr.initialized:
                return
            tabw = self.sender()
            if _is_valid_qobj(tabw):
                if isinstance(tabw, QtWidgets.QTabBar):
                    self._mgr._translate_single_tabbar(tabw)
                elif isinstance(tabw, QtWidgets.QWidget):
                    win = tabw.window()
                    if _is_valid_qobj(win) and isinstance(win, QtWidgets.QDialog):
                        self._mgr._translate_dialog(win)
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
        self._translate_all_menus()
        self._translate_all_tabbars()
        self._translate_active_dialogs()
        if self._receiver is not None:
            self._receiver.schedule_ui_refresh(50)

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
                elif isinstance(w, QtWidgets.QTabBar):
                    self._restore_tabbar(w)
                elif isinstance(w, QtWidgets.QDialog):
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

        for act in qmenu.actions():
            if not _is_valid_qobj(act) or act.isSeparator():
                continue
            sub = act.menu()
            if _is_valid_qobj(sub) and sub is not qmenu:
                self._setup_static_menu(sub, is_top_level=False)

    @_safe_call
    def on_popup_ready(self):
        if not self.initialized or not self.enabled or not _ensure_qt():
            return
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
                self.action_text_to_zh.get(main_txt)
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
    def on_widget_event(self):
        if not self.initialized or not self.enabled or not _ensure_qt():
            return
        self._translate_all_tabbars()
        self._translate_active_dialogs()
        if self._receiver is not None:
            self._receiver.schedule_ui_refresh(50)

    @_safe_call
    def _translate_active_dialogs(self):
        if not self.enabled or not _ensure_qt():
            return
        app = QtWidgets.QApplication.instance()
        if app is None:
            return
        modal = app.activeModalWidget()
        if _is_valid_qobj(modal) and isinstance(modal, QtWidgets.QDialog):
            self._translate_dialog(modal)
        for top in list(app.topLevelWidgets()):
            if _is_valid_qobj(top) and isinstance(top, QtWidgets.QDialog) and top.isVisible():
                self._translate_dialog(top)

    @_safe_call
    def _on_focus_changed(self, old_widget, new_widget):
        if not self.initialized or not self.enabled:
            return
        if _is_valid_qobj(new_widget):
            win = new_widget.window()
            if _is_valid_qobj(win) and isinstance(win, QtWidgets.QDialog):
                self._translate_dialog(win)
        self._translate_all_tabbars()

    @_safe_call
    def _translate_dialog(self, dlg):
        if not self.enabled or not _is_valid_qobj(dlg):
            return

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
                txt = child.text() or ""
                if txt and not _has_cjk(txt):
                    zh = self._lookup_dialog_string(txt)
                    if zh and zh != txt:
                        child.setProperty("_ida_zh_orig_text", txt)
                        child.setText(zh)
                if (
                    isinstance(child, (QtWidgets.QCheckBox, QtWidgets.QRadioButton))
                    and self._receiver is not None
                    and not child.property("_ida_zh_btn_hooked")
                ):
                    child.setProperty("_ida_zh_btn_hooked", True)
                    try:
                        child.toggled.connect(self._receiver.on_tab_current_changed)
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
                if lbl_txt and not _has_cjk(lbl_txt) and len(lbl_txt) < 300:
                    if lbl_txt in self.qt_translate:
                        child.setProperty("_ida_zh_orig_text", lbl_txt)
                        child.setText(self.qt_translate[lbl_txt])
                    elif not lbl_txt.lstrip().startswith("<"):
                        zh = self._lookup_dialog_string(lbl_txt)
                        if zh and zh != lbl_txt:
                            child.setProperty("_ida_zh_orig_text", lbl_txt)
                            child.setText(zh)

            elif isinstance(child, QtWidgets.QTabBar):
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

    @_safe_call
    def _restore_dialog(self, dlg):
        if not _is_valid_qobj(dlg):
            return
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
            elif isinstance(child, QtWidgets.QTabBar):
                for i in range(child.count()):
                    orig_tab = child.property(f"_ida_zh_orig_tab_{i}")
                    if orig_tab:
                        child.setTabText(i, str(orig_tab))

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

        clean_lower = clean.lower()
        if clean_lower in self.dialog_text_lower:
            return self.dialog_text_lower[clean_lower]
        if clean_lower in self.qt_translate_clean:
            return self.qt_translate_clean[clean_lower]

        for en_suf, zh_suf in (
            (" (non-graph)", " (非图形)"),
            (" (graph)", " (图形)"),
            (" (default)", " (默认)"),
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
        ):
            if clean.startswith(en_pref):
                return zh_pref + clean[len(en_pref) :]

        if clean_lower.endswith(":"):
            base = clean_lower[:-1].strip()
            zh_base = self.dialog_text_lower.get(base) or self.qt_translate_clean.get(base)
            if zh_base:
                return _strip_accel(zh_base).rstrip(":") + ":"
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
