"""
RSA Digital Signature Studio
Windows 11 Native GUI Application for Academic Practical Demonstrations.
Built with Python 3, PySide6, and the official cryptography library.
Identical in design, layout, color palette, and interactive workflow to the web preview.
"""

import sys
import os
import time
import hashlib
from typing import Optional, Dict, Any, List

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFileDialog, QMessageBox,
    QLineEdit, QTextEdit, QComboBox, QGroupBox, QSplitter,
    QProgressBar, QScrollArea, QFrame
)
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QFont, QIcon, QColor, QPalette, QKeySequence, QShortcut

from modules.key_manager import KeyManager
from modules.signer import Signer
from modules.verifier import Verifier
from modules.file_handler import FileHandler


class MainWindow(QMainWindow):
    """Windows 11 Fluent Design Main Application Window."""

    def __init__(self, is_dark: bool = False):
        super().__init__()
        self.setWindowTitle("RSA Digital Signature Studio — Standalone Desktop Application")
        self.resize(1280, 840)
        self.setMinimumSize(1020, 680)

        # Theme state: False = Light Mode (Default matching web preview), True = Dark Mode
        self.is_dark_mode = is_dark

        # Cryptographic session state
        self.active_private_key = None
        self.active_public_key = None
        self.active_key_size: int = 2048
        self.active_priv_pem: str = ""
        self.active_pub_pem: str = ""

        # Presets and Document state
        self.presets = FileHandler.get_preset_documents()
        self.active_preset_idx: int = 0
        self.active_doc_name: str = self.presets[0]["name"]
        self.original_content_snapshot: str = self.presets[0]["content"]

        # Signature state
        self.active_signature_bytes: Optional[bytes] = None
        self.active_signature_hex: str = ""
        self.active_signature_size: int = 0
        self.active_signature_timestamp: str = ""

        # Tampering state
        self.is_tampered: bool = False

        # Dedicated Verification Page State
        self.ver_doc_name: str = "Academic_Practical_Report.txt"
        self.ver_original_snapshot: str = self.presets[0]["content"]
        self.ver_pubkey_name: str = "public_key.pem"
        self.ver_pubkey_bytes: Optional[bytes] = None
        self.ver_pubkey_obj = None
        self.ver_sig_name: str = "document.sig"
        self.ver_sig_bytes: Optional[bytes] = None

        # 1-Click Classroom execution state
        self.is_running_auto_demo: bool = False
        self.demo_step: int = 0

        self._setup_ui()
        self._apply_theme(self.is_dark_mode)

        # Initial calculation of hash for default document
        self._on_studio_text_changed()
        self._ver_on_text_changed()

    def _setup_ui(self):
        root_widget = QWidget()
        self.setCentralWidget(root_widget)
        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Windows 11 TitleBar Header
        header_bar = self._create_title_bar()
        root_layout.addWidget(header_bar)

        # 2. Main Body Split: Left Sidebar + Right Stacked Pages
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        sidebar = self._create_sidebar()
        body_layout.addWidget(sidebar)

        # Pages Container
        self.pages = QStackedWidget()
        self.pages.addWidget(self._create_studio_page())        # Index 0: Interactive Studio (Default!)
        self.pages.addWidget(self._create_dashboard_page())     # Index 1: Protocol Architecture
        self.pages.addWidget(self._create_key_gen_page())       # Index 2: RSA Key Generation
        self.pages.addWidget(self._create_signing_page())       # Index 3: Sign a Text File
        self.pages.addWidget(self._create_verification_page())  # Index 4: Verify a Signature
        self.pages.addWidget(self._create_about_page())         # Index 5: About & Lab Manual

        body_layout.addWidget(self.pages)
        root_layout.addWidget(body_widget)

        # Default to Interactive Studio (Index 0)
        self._navigate_to(0)

    # =========================================================================
    # HEADER BAR (Matching TitleBar.tsx)
    # =========================================================================
    def _create_title_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("headerBar")
        bar.setFixedHeight(44)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(12)

        # Left App Identity
        left_layout = QHBoxLayout()
        left_layout.setSpacing(8)

        shield_icon = QLabel("🛡️")
        shield_icon.setStyleSheet("font-size: 16px;")
        left_layout.addWidget(shield_icon)

        title_lbl = QLabel("RSA Digital Signature Studio")
        title_lbl.setObjectName("headerTitle")
        left_layout.addWidget(title_lbl)

        badge_lbl = QLabel("Standalone Desktop App")
        badge_lbl.setObjectName("headerBadge")
        left_layout.addWidget(badge_lbl)

        layout.addLayout(left_layout)

        # Center Status info
        center_lbl = QLabel("RSA-PSS 2048/3072/4096-bit  ·  SHA-256 Digest  ·  Native Cryptography")
        center_lbl.setObjectName("headerCenterInfo")
        center_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(center_lbl)

        layout.addStretch()

        # Right Actions
        right_layout = QHBoxLayout()
        right_layout.setSpacing(8)

        self.theme_btn = QPushButton("🌙 Switch to Dark Mode" if not self.is_dark_mode else "☀️ Switch to Light Mode")
        self.theme_btn.setObjectName("headerActionBtn")
        self.theme_btn.setCursor(Qt.PointingHandCursor)
        self.theme_btn.clicked.connect(self._toggle_theme)
        right_layout.addWidget(self.theme_btn)

        self.fullscreen_btn = QPushButton("⛶ Fullscreen")
        self.fullscreen_btn.setObjectName("headerActionBtn")
        self.fullscreen_btn.setCursor(Qt.PointingHandCursor)
        self.fullscreen_btn.clicked.connect(self._toggle_fullscreen)
        right_layout.addWidget(self.fullscreen_btn)

        layout.addLayout(right_layout)
        return bar

    # =========================================================================
    # SIDEBAR (Matching Sidebar.tsx)
    # =========================================================================
    def _create_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(6)

        # Sidebar Header Branding
        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(2)
        sb_title = QLabel("RSA Signature Studio")
        sb_title.setObjectName("sbTitle")
        sb_sub = QLabel("Windows 11 Academic Suite")
        sb_sub.setObjectName("sbSubtitle")
        brand_layout.addWidget(sb_title)
        brand_layout.addWidget(sb_sub)
        layout.addLayout(brand_layout)
        layout.addSpacing(10)

        # Nav items
        self.nav_buttons: List[QPushButton] = []
        nav_items = [
            ("⚡ Interactive Studio", "Live", 0),
            ("📊 Protocol Architecture", "", 1),
            ("🔑 RSA Key Generation", "", 2),
            ("✍️ Sign a Text File", "", 3),
            ("🛡️ Verify a Signature", "", 4),
            ("ℹ️ About & Lab Manual", "", 5),
        ]

        for text, badge, idx in nav_items:
            btn = QPushButton(f"  {text}")
            btn.setObjectName("navButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, target=idx: self._navigate_to(target))
            self.nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # Session State Box in Sidebar Bottom
        state_box = QGroupBox("Cryptographic Session State")
        state_box.setObjectName("sessionStateBox")
        state_layout = QVBoxLayout(state_box)
        state_layout.setContentsMargins(10, 12, 10, 10)
        state_layout.setSpacing(6)

        # Key state
        row_key = QHBoxLayout()
        row_key.addWidget(QLabel("RSA Key Pair:"))
        self.session_key_val = QLabel("None")
        self.session_key_val.setObjectName("sessionValMuted")
        row_key.addWidget(self.session_key_val)
        state_layout.addLayout(row_key)

        # Doc state
        row_doc = QHBoxLayout()
        row_doc.addWidget(QLabel("Document:"))
        self.session_doc_val = QLabel("Report.txt (389 B)")
        self.session_doc_val.setObjectName("sessionValText")
        row_doc.addWidget(self.session_doc_val)
        state_layout.addLayout(row_doc)

        # Sig state
        row_sig = QHBoxLayout()
        row_sig.addWidget(QLabel("Signature:"))
        self.session_sig_val = QLabel("None")
        self.session_sig_val.setObjectName("sessionValMuted")
        row_sig.addWidget(self.session_sig_val)
        state_layout.addLayout(row_sig)

        # Verify state
        row_ver = QHBoxLayout()
        row_ver.addWidget(QLabel("Verification:"))
        self.session_verify_val = QLabel("Ready")
        self.session_verify_val.setObjectName("sessionValMuted")
        row_ver.addWidget(self.session_verify_val)
        state_layout.addLayout(row_ver)

        layout.addWidget(state_box)
        return sidebar

    def _navigate_to(self, index: int):
        self.pages.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)

    # =========================================================================
    # PAGE 0: INTERACTIVE STUDIO (LivePracticalStudioView.tsx)
    # =========================================================================
    def _create_studio_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setObjectName("studioScroll")

        container = QWidget()
        container.setObjectName("studioContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(20)

        # --- Top Banner: Standalone Studio Active ---
        banner = QWidget()
        banner.setObjectName("studioBanner")
        b_layout = QVBoxLayout(banner)
        b_layout.setContentsMargins(22, 18, 22, 18)
        b_layout.setSpacing(12)

        # Banner Header & Action Buttons Row
        top_row = QHBoxLayout()
        
        info_col = QVBoxLayout()
        info_col.setSpacing(4)
        active_tag = QLabel("● STANDALONE ACADEMIC PRACTICAL STUDIO  ·  OFFLINE EXECUTION")
        active_tag.setObjectName("studioActiveTag")
        title_tag = QLabel("RSA Digital Signature Practical Studio")
        title_tag.setObjectName("studioMainTitle")
        desc_tag = QLabel(
            "Directly execute and present text file signing, SHA-256 hashing, "
            "RSA-PSS signature verification, and mathematical tampering detection in real time."
        )
        desc_tag.setObjectName("studioSubtitle")
        desc_tag.setWordWrap(True)

        info_col.addWidget(active_tag)
        info_col.addWidget(title_tag)
        info_col.addWidget(desc_tag)
        top_row.addLayout(info_col, stretch=1)

        # 1-Click Classroom execution buttons
        btn_col = QHBoxLayout()
        btn_col.setSpacing(10)

        self.btn_1click_demo = QPushButton("⚡ 1-Click Complete Classroom Execution")
        self.btn_1click_demo.setObjectName("oneClickButton")
        self.btn_1click_demo.setCursor(Qt.PointingHandCursor)
        self.btn_1click_demo.clicked.connect(self.handle_1click_classroom_demo)
        btn_col.addWidget(self.btn_1click_demo)

        btn_reset = QPushButton("↺ Reset")
        btn_reset.setObjectName("secondaryButton")
        btn_reset.setCursor(Qt.PointingHandCursor)
        btn_reset.clicked.connect(self._reset_studio)
        btn_col.addWidget(btn_reset)

        top_row.addLayout(btn_col)
        b_layout.addLayout(top_row)

        # Visual 4-Step Progress Indicator (Shown during 1-click execution)
        self.demo_progress_widget = QWidget()
        self.demo_progress_widget.setObjectName("demoProgressStrip")
        dp_layout = QHBoxLayout(self.demo_progress_widget)
        dp_layout.setContentsMargins(0, 8, 0, 0)
        dp_layout.setSpacing(8)

        self.step_pills = [
            QLabel("1. Keys Generated"),
            QLabel("2. Text Loaded"),
            QLabel("3. Signed with RSA"),
            QLabel("4. Verified Valid"),
        ]
        for pill in self.step_pills:
            pill.setObjectName("stepPillInactive")
            pill.setAlignment(Qt.AlignCenter)
            dp_layout.addWidget(pill)

        self.demo_progress_widget.hide()
        b_layout.addWidget(self.demo_progress_widget)

        layout.addWidget(banner)

        # --- 2-Column Responsive Laboratory Grid ---
        grid_splitter = QSplitter(Qt.Horizontal)
        grid_splitter.setHandleWidth(16)
        grid_splitter.setObjectName("studioSplitter")

        # LEFT COLUMN: Stage 1 (Key Pair) + Stage 2 (Document + SHA-256)
        col_left = QWidget()
        layout_left = QVBoxLayout(col_left)
        layout_left.setContentsMargins(0, 0, 0, 0)
        layout_left.setSpacing(16)

        # CARD 1: Stage 1 (RSA Key Pair Setup)
        card_1 = self._build_stage1_card()
        layout_left.addWidget(card_1)

        # CARD 2: Stage 2 (Document & SHA-256 Hash)
        card_2 = self._build_stage2_card()
        layout_left.addWidget(card_2)

        grid_splitter.addWidget(col_left)

        # RIGHT COLUMN: Stage 3 (Signing) + Stage 4 (Verification & Tampering)
        col_right = QWidget()
        layout_right = QVBoxLayout(col_right)
        layout_right.setContentsMargins(0, 0, 0, 0)
        layout_right.setSpacing(16)

        # CARD 3: Stage 3 (Digital Signing)
        card_3 = self._build_stage3_card()
        layout_right.addWidget(card_3)

        # CARD 4: Stage 4 (Verification & Tamper Test)
        card_4 = self._build_stage4_card()
        layout_right.addWidget(card_4)

        grid_splitter.addWidget(col_right)
        layout.addWidget(grid_splitter)

        scroll.setWidget(container)
        return scroll

    # STAGE 1 CARD
    def _build_stage1_card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("stageCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 18, 20, 20)
        layout.setSpacing(14)

        # Header with Step Badge & Status
        hdr = QHBoxLayout()
        b1 = QLabel("1")
        b1.setObjectName("stageBadgeBlue")
        hdr.addWidget(b1)

        t1 = QLabel("RSA Key Pair Setup")
        t1.setObjectName("stageTitle")
        hdr.addWidget(t1)
        hdr.addStretch()

        self.studio_key_status_pill = QLabel("⚠ Keys Needed")
        self.studio_key_status_pill.setObjectName("pillWarning")
        hdr.addWidget(self.studio_key_status_pill)
        layout.addLayout(hdr)

        # Key Size selection row
        ctrls = QVBoxLayout()
        ctrls.setSpacing(10)

        pills_row = QHBoxLayout()
        pills_row.setSpacing(8)

        lbl_sz = QLabel("Modulus:")
        lbl_sz.setObjectName("keyMetaLabel")
        pills_row.addWidget(lbl_sz)

        self.btn_size_2048 = QPushButton("2048-bit (Standard)")
        self.btn_size_2048.setObjectName("pillBtnActive")
        self.btn_size_2048.setCursor(Qt.PointingHandCursor)
        self.btn_size_2048.clicked.connect(lambda: self._select_key_size(2048))
        pills_row.addWidget(self.btn_size_2048)

        self.btn_size_3072 = QPushButton("3072-bit")
        self.btn_size_3072.setObjectName("pillBtn")
        self.btn_size_3072.setCursor(Qt.PointingHandCursor)
        self.btn_size_3072.clicked.connect(lambda: self._select_key_size(3072))
        pills_row.addWidget(self.btn_size_3072)

        self.btn_size_4096 = QPushButton("4096-bit")
        self.btn_size_4096.setObjectName("pillBtn")
        self.btn_size_4096.setCursor(Qt.PointingHandCursor)
        self.btn_size_4096.clicked.connect(lambda: self._select_key_size(4096))
        pills_row.addWidget(self.btn_size_4096)
        pills_row.addStretch()
        ctrls.addLayout(pills_row)

        self.btn_studio_gen_keys = QPushButton("⚡ Generate RSA Keys (e = 65537)")
        self.btn_studio_gen_keys.setObjectName("primaryButton")
        self.btn_studio_gen_keys.setCursor(Qt.PointingHandCursor)
        self.btn_studio_gen_keys.clicked.connect(lambda: self._generate_studio_keys(self.active_key_size))
        ctrls.addWidget(self.btn_studio_gen_keys)

        layout.addLayout(ctrls)

        # Key Info & Actions Container
        self.studio_key_info_box = QWidget()
        self.studio_key_info_box.setObjectName("nestedBox")
        k_layout = QVBoxLayout(self.studio_key_info_box)
        k_layout.setContentsMargins(14, 12, 14, 12)
        k_layout.setSpacing(10)

        row_meta = QHBoxLayout()
        self.studio_key_algo_lbl = QLabel("Algorithm: RSA-PSS (e = 65537)")
        self.studio_key_algo_lbl.setObjectName("keyMetaLabel")
        self.studio_key_mod_lbl = QLabel("Modulus: 2048 bits")
        self.studio_key_mod_lbl.setObjectName("keyMetaLabel")
        row_meta.addWidget(self.studio_key_algo_lbl)
        row_meta.addStretch()
        row_meta.addWidget(self.studio_key_mod_lbl)
        k_layout.addLayout(row_meta)

        # Buttons to save PEMs and view PEM
        row_pem_actions = QHBoxLayout()
        row_pem_actions.setSpacing(8)

        btn_save_pub = QPushButton("💾 Save public_key.pem")
        btn_save_pub.setObjectName("smallActionBtn")
        btn_save_pub.setCursor(Qt.PointingHandCursor)
        btn_save_pub.clicked.connect(self._save_public_key_file)
        row_pem_actions.addWidget(btn_save_pub)

        btn_save_priv = QPushButton("💾 Save private_key.pem")
        btn_save_priv.setObjectName("smallActionBtn")
        btn_save_priv.setCursor(Qt.PointingHandCursor)
        btn_save_priv.clicked.connect(self._save_private_key_file)
        row_pem_actions.addWidget(btn_save_priv)

        self.btn_toggle_pem = QPushButton("View PEM ▾")
        self.btn_toggle_pem.setObjectName("linkBtn")
        self.btn_toggle_pem.setCursor(Qt.PointingHandCursor)
        self.btn_toggle_pem.clicked.connect(self._toggle_pem_view)
        row_pem_actions.addStretch()
        row_pem_actions.addWidget(self.btn_toggle_pem)
        k_layout.addLayout(row_pem_actions)

        # Collapsible PEM viewer (Dynamic auto-expanding without strict fixed truncation)
        self.studio_pem_viewer = QTextEdit()
        self.studio_pem_viewer.setObjectName("codeViewerBox")
        self.studio_pem_viewer.setReadOnly(True)
        self.studio_pem_viewer.setMinimumHeight(130)
        self.studio_pem_viewer.setFont(QFont("Consolas", 10))
        self.studio_pem_viewer.hide()
        k_layout.addWidget(self.studio_pem_viewer)

        layout.addWidget(self.studio_key_info_box)
        self.studio_key_info_box.hide()
        return card

    # STAGE 2 CARD
    def _build_stage2_card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("stageCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(10)

        # Header
        hdr = QHBoxLayout()
        b2 = QLabel("2")
        b2.setObjectName("stageBadgeAmber")
        hdr.addWidget(b2)

        t2 = QLabel("Document Input & SHA-256 Digest")
        t2.setObjectName("stageTitle")
        hdr.addWidget(t2)
        hdr.addStretch()

        self.studio_doc_stats = QLabel("389 chars · 389 bytes")
        self.studio_doc_stats.setObjectName("statsLabel")
        hdr.addWidget(self.studio_doc_stats)
        layout.addLayout(hdr)

        # Presets & Upload Row
        p_row = QHBoxLayout()
        p_row.setSpacing(6)

        self.preset_btns: List[QPushButton] = []
        for i, doc in enumerate(self.presets):
            pbtn = QPushButton(doc["label"])
            pbtn.setObjectName("presetBtnActive" if i == 0 else "presetBtn")
            pbtn.setCursor(Qt.PointingHandCursor)
            pbtn.clicked.connect(lambda _, idx=i: self._select_studio_preset(idx))
            self.preset_btns.append(pbtn)
            p_row.addWidget(pbtn)

        p_row.addStretch()

        btn_browse = QPushButton("📁 Browse .txt")
        btn_browse.setObjectName("smallActionBtn")
        btn_browse.setCursor(Qt.PointingHandCursor)
        btn_browse.clicked.connect(self._browse_studio_file)
        p_row.addWidget(btn_browse)
        layout.addLayout(p_row)

        # Document Text Edit (Live typing updates SHA-256!)
        self.studio_doc_edit = QTextEdit()
        self.studio_doc_edit.setObjectName("documentTextEdit")
        self.studio_doc_edit.setFixedHeight(120)
        self.studio_doc_edit.setPlainText(self.presets[0]["content"])
        self.studio_doc_edit.textChanged.connect(self._on_studio_text_changed)
        layout.addWidget(self.studio_doc_edit)

        # Real-Time SHA-256 Digest Box
        hash_box = QWidget()
        hash_box.setObjectName("nestedBox")
        h_layout = QVBoxLayout(hash_box)
        h_layout.setContentsMargins(12, 10, 12, 10)
        h_layout.setSpacing(6)

        h_title_row = QHBoxLayout()
        h_title = QLabel("⚡ Real-Time SHA-256 Message Digest (256 bits / 32 bytes):")
        h_title.setObjectName("hashTitleLabel")
        h_title_row.addWidget(h_title)
        h_title_row.addStretch()

        btn_copy_hash = QPushButton("Copy Hash")
        btn_copy_hash.setObjectName("linkBtn")
        btn_copy_hash.setCursor(Qt.PointingHandCursor)
        btn_copy_hash.clicked.connect(self._copy_hash_to_clipboard)
        h_title_row.addWidget(btn_copy_hash)
        h_layout.addLayout(h_title_row)

        self.studio_hash_display = QLabel("Calculating hash...")
        self.studio_hash_display.setObjectName("hashDisplay")
        self.studio_hash_display.setWordWrap(True)
        self.studio_hash_display.setTextInteractionFlags(Qt.TextSelectableByMouse)
        h_layout.addWidget(self.studio_hash_display)

        h_note = QLabel("Deterministic, one-way hash: Even a 1-bit alteration completely changes this 64-character hex digest.")
        h_note.setObjectName("hashNoteLabel")
        h_layout.addWidget(h_note)

        layout.addWidget(hash_box)
        return card

    # STAGE 3 CARD
    def _build_stage3_card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("stageCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        b3 = QLabel("3")
        b3.setObjectName("stageBadgeIndigo")
        hdr.addWidget(b3)

        t3 = QLabel("RSA-PSS Digital Signing (Sender)")
        t3.setObjectName("stageTitle")
        hdr.addWidget(t3)
        hdr.addStretch()

        self.studio_sig_status_pill = QLabel("Not Signed")
        self.studio_sig_status_pill.setObjectName("pillMuted")
        hdr.addWidget(self.studio_sig_status_pill)
        layout.addLayout(hdr)

        # Action Buttons
        act_row = QHBoxLayout()
        act_row.setSpacing(8)

        self.btn_studio_sign = QPushButton("✍️ Sign with RSA Private Key")
        self.btn_studio_sign.setObjectName("indigoButton")
        self.btn_studio_sign.setCursor(Qt.PointingHandCursor)
        self.btn_studio_sign.clicked.connect(self._sign_studio_document)
        act_row.addWidget(self.btn_studio_sign)

        self.btn_studio_dl_sig = QPushButton("Download Detached .sig")
        self.btn_studio_dl_sig.setObjectName("smallActionBtn")
        self.btn_studio_dl_sig.setCursor(Qt.PointingHandCursor)
        self.btn_studio_dl_sig.clicked.connect(self._save_signature_file)
        self.btn_studio_dl_sig.setEnabled(False)
        act_row.addWidget(self.btn_studio_dl_sig)
        act_row.addStretch()
        layout.addLayout(act_row)

        # Signature Output Box
        self.studio_sig_box = QWidget()
        self.studio_sig_box.setObjectName("nestedBox")
        s_layout = QVBoxLayout(self.studio_sig_box)
        s_layout.setContentsMargins(12, 10, 12, 10)
        s_layout.setSpacing(6)

        s_meta = QHBoxLayout()
        self.studio_sig_size_lbl = QLabel("Signature Size: 256 bytes (2048 bits)")
        self.studio_sig_time_lbl = QLabel("Created: --")
        s_meta.addWidget(self.studio_sig_size_lbl)
        s_meta.addStretch()
        s_meta.addWidget(self.studio_sig_time_lbl)
        s_layout.addLayout(s_meta)

        sig_prev_row = QHBoxLayout()
        sig_prev_title = QLabel("Detached Signature Preview (Hex):")
        sig_prev_title.setObjectName("hashTitleLabel")
        sig_prev_row.addWidget(sig_prev_title)
        sig_prev_row.addStretch()

        btn_copy_sig = QPushButton("Copy Signature")
        btn_copy_sig.setObjectName("linkBtn")
        btn_copy_sig.setCursor(Qt.PointingHandCursor)
        btn_copy_sig.clicked.connect(self._copy_signature_to_clipboard)
        sig_prev_row.addWidget(btn_copy_sig)
        s_layout.addLayout(sig_prev_row)

        self.studio_sig_hex_preview = QLabel("Waiting for signing...")
        self.studio_sig_hex_preview.setObjectName("sigPreviewDisplay")
        self.studio_sig_hex_preview.setWordWrap(True)
        self.studio_sig_hex_preview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        s_layout.addWidget(self.studio_sig_hex_preview)

        layout.addWidget(self.studio_sig_box)
        self.studio_sig_box.hide()
        return card

    # STAGE 4 CARD
    def _build_stage4_card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("stageCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        b4 = QLabel("4")
        b4.setObjectName("stageBadgeEmerald")
        hdr.addWidget(b4)

        t4 = QLabel("Mathematical Verification & Tamper Test")
        t4.setObjectName("stageTitle")
        hdr.addWidget(t4)
        hdr.addStretch()

        self.studio_verify_status_pill = QLabel("Pending Verification")
        self.studio_verify_status_pill.setObjectName("pillMuted")
        hdr.addWidget(self.studio_verify_status_pill)
        layout.addLayout(hdr)

        # File Inputs Row (Take input of .sig and public key .pem)
        file_input_row = QHBoxLayout()
        file_input_row.setSpacing(8)

        self.btn_studio_load_sig = QPushButton("📂 Load .sig File")
        self.btn_studio_load_sig.setObjectName("smallActionBtn")
        self.btn_studio_load_sig.setCursor(Qt.PointingHandCursor)
        self.btn_studio_load_sig.clicked.connect(self._studio_load_sig_file)
        file_input_row.addWidget(self.btn_studio_load_sig)

        self.btn_studio_load_pub = QPushButton("📂 Load public_key.pem")
        self.btn_studio_load_pub.setObjectName("smallActionBtn")
        self.btn_studio_load_pub.setCursor(Qt.PointingHandCursor)
        self.btn_studio_load_pub.clicked.connect(self._studio_load_pubkey_file)
        file_input_row.addWidget(self.btn_studio_load_pub)

        self.studio_verify_files_lbl = QLabel("Inputs: Active Session Keys & Signature")
        self.studio_verify_files_lbl.setObjectName("statsLabel")
        file_input_row.addWidget(self.studio_verify_files_lbl)
        file_input_row.addStretch()
        layout.addLayout(file_input_row)

        # Action Buttons + Tamper Injections
        act_row = QHBoxLayout()
        act_row.setSpacing(8)

        self.btn_studio_verify = QPushButton("🛡️ Verify Signature with Public Key")
        self.btn_studio_verify.setObjectName("emeraldButton")
        self.btn_studio_verify.setCursor(Qt.PointingHandCursor)
        self.btn_studio_verify.clicked.connect(self._verify_studio_signature)
        act_row.addWidget(self.btn_studio_verify)

        act_row.addStretch()

        # Tampering Controls
        t_label = QLabel("Tamper Test:")
        t_label.setObjectName("hashTitleLabel")
        act_row.addWidget(t_label)

        btn_tamper_val = QPushButton("Alter Value")
        btn_tamper_val.setObjectName("roseButton")
        btn_tamper_val.setCursor(Qt.PointingHandCursor)
        btn_tamper_val.clicked.connect(lambda: self._inject_tamper("amount"))
        act_row.addWidget(btn_tamper_val)

        btn_tamper_space = QPushButton("+1 Space")
        btn_tamper_space.setObjectName("amberButton")
        btn_tamper_space.setCursor(Qt.PointingHandCursor)
        btn_tamper_space.clicked.connect(lambda: self._inject_tamper("whitespace"))
        act_row.addWidget(btn_tamper_space)

        self.btn_revert = QPushButton("↺ Revert")
        self.btn_revert.setObjectName("secondaryButton")
        self.btn_revert.setCursor(Qt.PointingHandCursor)
        self.btn_revert.clicked.connect(self._revert_tampering)
        self.btn_revert.hide()
        act_row.addWidget(self.btn_revert)

        layout.addLayout(act_row)

        # Tamper Alert Banner (Rose)
        self.studio_tamper_alert = QWidget()
        self.studio_tamper_alert.setObjectName("tamperAlertBox")
        ta_layout = QVBoxLayout(self.studio_tamper_alert)
        ta_layout.setContentsMargins(12, 10, 12, 10)
        ta_layout.setSpacing(4)
        ta_title = QLabel("⚠️ DOCUMENT MODIFIED (TAMPER TEST IN PROGRESS)")
        ta_title.setObjectName("tamperAlertTitle")
        ta_desc = QLabel("The text was altered after signing. Notice how the SHA-256 hash changed. Click 'Verify Signature with Public Key' to witness instant cryptographic rejection.")
        ta_desc.setObjectName("tamperAlertDesc")
        ta_desc.setWordWrap(True)
        ta_layout.addWidget(ta_title)
        ta_layout.addWidget(ta_desc)
        self.studio_tamper_alert.hide()
        layout.addWidget(self.studio_tamper_alert)

        # Big Verification Outcome Card
        self.studio_verification_card = QWidget()
        self.studio_verification_card.setObjectName("verifyCardValid")
        vc_layout = QVBoxLayout(self.studio_verification_card)
        vc_layout.setContentsMargins(14, 12, 14, 12)
        vc_layout.setSpacing(6)

        vc_hdr = QHBoxLayout()
        self.verify_outcome_icon = QLabel("✔")
        self.verify_outcome_icon.setObjectName("outcomeIcon")
        self.verify_outcome_title = QLabel("DIGITAL SIGNATURE VALID")
        self.verify_outcome_title.setObjectName("outcomeTitle")
        vc_hdr.addWidget(self.verify_outcome_icon)
        vc_hdr.addWidget(self.verify_outcome_title)
        vc_hdr.addStretch()
        self.verify_outcome_timing = QLabel("0.8 ms")
        self.verify_outcome_timing.setObjectName("outcomeTiming")
        vc_hdr.addWidget(self.verify_outcome_timing)
        vc_layout.addLayout(vc_hdr)

        self.verify_outcome_msg = QLabel("Authenticity & Integrity Confirmed.")
        self.verify_outcome_msg.setObjectName("outcomeMessage")
        self.verify_outcome_msg.setWordWrap(True)
        vc_layout.addWidget(self.verify_outcome_msg)

        self.verify_outcome_detail = QLabel("The decrypted signature hash matches the recomputed SHA-256 message digest. Sender private key origin proven and zero data corruption detected.")
        self.verify_outcome_detail.setObjectName("outcomeDetail")
        self.verify_outcome_detail.setWordWrap(True)
        vc_layout.addWidget(self.verify_outcome_detail)

        self.studio_verification_card.hide()
        layout.addWidget(self.studio_verification_card)

        return card

    # =========================================================================
    # EVENT HANDLERS & CRYPTOGRAPHIC ENGINE
    # =========================================================================
    def _select_key_size(self, size: int):
        self.active_key_size = size
        self.btn_size_2048.setObjectName("pillBtnActive" if size == 2048 else "pillBtn")
        self.btn_size_3072.setObjectName("pillBtnActive" if size == 3072 else "pillBtn")
        self.btn_size_4096.setObjectName("pillBtnActive" if size == 4096 else "pillBtn")
        self._apply_theme(self.is_dark_mode)

    def _generate_studio_keys(self, size: int):
        try:
            priv, pub = KeyManager.generate_key_pair(size)
            self.active_private_key = priv
            self.active_public_key = pub
            self.active_key_size = size

            self.active_priv_pem = KeyManager.export_private_key_pem(priv).decode('utf-8')
            self.active_pub_pem = KeyManager.export_public_key_pem(pub).decode('utf-8')

            # Update UI
            self.studio_key_status_pill.setText(f"✓ {size}-bit Active")
            self.studio_key_status_pill.setObjectName("pillSuccess")
            self.studio_key_mod_lbl.setText(f"Modulus: {size} bits")
            self.studio_pem_viewer.setText(self.active_pub_pem)
            self.studio_key_info_box.show()

            self.session_key_val.setText(f"{size}-bit Active")
            self.session_key_val.setObjectName("sessionValSuccess")

            self._apply_theme(self.is_dark_mode)
        except Exception as e:
            QMessageBox.critical(self, "Key Generation Error", str(e))

    def _toggle_pem_view(self):
        if self.studio_pem_viewer.isVisible():
            self.studio_pem_viewer.hide()
            self.btn_toggle_pem.setText("View PEM ▾")
        else:
            self.studio_pem_viewer.show()
            self.btn_toggle_pem.setText("Hide PEM ▴")

    def _select_studio_preset(self, idx: int):
        self.active_preset_idx = idx
        doc = self.presets[idx]
        self.active_doc_name = doc["name"]
        self.original_content_snapshot = doc["content"]
        self.is_tampered = False
        self.btn_revert.hide()
        self.studio_tamper_alert.hide()
        self.studio_verification_card.hide()

        # Update button highlights
        for i, btn in enumerate(self.preset_btns):
            btn.setObjectName("presetBtnActive" if i == idx else "presetBtn")

        # Set text without triggering unwanted tamper flags
        self.studio_doc_edit.blockSignals(True)
        self.studio_doc_edit.setPlainText(doc["content"])
        self.studio_doc_edit.blockSignals(False)

        self._on_studio_text_changed()
        self._apply_theme(self.is_dark_mode)

    def _browse_studio_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Text File to Sign", "", "Text Files (*.txt);;All Files (*.*)")
        if path:
            text = FileHandler.read_text_file(path)
            self.active_doc_name = os.path.basename(path)
            self.original_content_snapshot = text
            self.is_tampered = False
            self.btn_revert.hide()
            self.studio_tamper_alert.hide()
            self.studio_verification_card.hide()

            self.studio_doc_edit.blockSignals(True)
            self.studio_doc_edit.setPlainText(text)
            self.studio_doc_edit.blockSignals(False)

            self._on_studio_text_changed()

    def _on_studio_text_changed(self):
        text = self.studio_doc_edit.toPlainText()
        data = text.encode('utf-8')
        digest = hashlib.sha256(data).hexdigest()
        self.studio_hash_display.setText(digest)
        self.studio_doc_stats.setText(f"{len(text)} chars · {len(data)} bytes")
        self.session_doc_val.setText(f"{self.active_doc_name} ({len(data)} B)")

        # Tamper detection
        if self.active_signature_bytes is not None and text != self.original_content_snapshot:
            self.is_tampered = True
            self.btn_revert.show()
            self.studio_tamper_alert.show()
            self.studio_verification_card.hide()
            self.studio_verify_status_pill.setText("✕ TAMPERED")
            self.studio_verify_status_pill.setObjectName("pillDanger")
            self.session_verify_val.setText("Tampered")
            self.session_verify_val.setObjectName("sessionValDanger")
        elif text == self.original_content_snapshot:
            self.is_tampered = False
            self.btn_revert.hide()
            self.studio_tamper_alert.hide()
            if self.active_signature_bytes is not None:
                self.studio_verify_status_pill.setText("Pending Verification")
                self.studio_verify_status_pill.setObjectName("pillMuted")
                self.session_verify_val.setText("Ready")
                self.session_verify_val.setObjectName("sessionValMuted")

        self._apply_theme(self.is_dark_mode)

    def _sign_studio_document(self):
        if not self.active_private_key:
            # Auto-generate keys if none exist for smooth experience
            self._generate_studio_keys(2048)

        text = self.studio_doc_edit.toPlainText()
        data = text.encode('utf-8')
        sig_bytes, sha256_hex = Signer.sign_data(data, self.active_private_key)

        self.active_signature_bytes = sig_bytes
        self.active_signature_hex = sig_bytes.hex()
        self.active_signature_size = len(sig_bytes)
        self.active_signature_timestamp = time.strftime("%H:%M:%S")
        self.original_content_snapshot = text
        self.is_tampered = False
        self.btn_revert.hide()
        self.studio_tamper_alert.hide()

        # Update UI
        self.studio_sig_status_pill.setText(f"✓ {len(sig_bytes)} Bytes Signed")
        self.studio_sig_status_pill.setObjectName("pillSuccess")
        self.studio_sig_size_lbl.setText(f"Signature Size: {len(sig_bytes)} bytes ({len(sig_bytes)*8} bits)")
        self.studio_sig_time_lbl.setText(f"Created: {self.active_signature_timestamp}")
        self.studio_sig_hex_preview.setText(self.active_signature_hex[:128] + "...")
        self.studio_sig_box.show()
        self.btn_studio_dl_sig.setEnabled(True)

        self.session_sig_val.setText(f"{len(sig_bytes)} B Active")
        self.session_sig_val.setObjectName("sessionValSuccess")

        self._apply_theme(self.is_dark_mode)

    def _verify_studio_signature(self):
        if not self.active_signature_bytes or not self.active_public_key:
            QMessageBox.warning(self, "Verification Notice", "Please sign the document first to generate a signature.")
            return

        text = self.studio_doc_edit.toPlainText()
        data = text.encode('utf-8')

        is_valid, diag = Verifier.verify_signature(data, self.active_signature_bytes, self.active_public_key)
        timing = diag.get("timing_ms", 0.8)

        self.studio_verification_card.show()
        if is_valid:
            self.studio_verification_card.setObjectName("verifyCardValid")
            self.verify_outcome_icon.setText("✔")
            self.verify_outcome_title.setText("DIGITAL SIGNATURE VALID")
            self.verify_outcome_timing.setText(f"{timing} ms")
            self.verify_outcome_msg.setText("Authenticity & Integrity Confirmed.")
            self.verify_outcome_detail.setText("The decrypted signature hash matches the recomputed SHA-256 message digest. Sender private key origin proven and zero data corruption detected.")

            self.studio_verify_status_pill.setText("✓ SIGNATURE VALID")
            self.studio_verify_status_pill.setObjectName("pillSuccess")
            self.session_verify_val.setText("Mathematically Valid")
            self.session_verify_val.setObjectName("sessionValSuccess")
        else:
            self.studio_verification_card.setObjectName("verifyCardInvalid")
            self.verify_outcome_icon.setText("✖")
            self.verify_outcome_title.setText("DIGITAL SIGNATURE INVALID")
            self.verify_outcome_timing.setText(f"{timing} ms")
            self.verify_outcome_msg.setText("Tampering Detected: Hash Mismatch.")
            self.verify_outcome_detail.setText("Digest mismatch: Document content has been modified after signature creation. Public key verification failed.")

            self.studio_verify_status_pill.setText("✕ SIGNATURE INVALID")
            self.studio_verify_status_pill.setObjectName("pillDanger")
            self.session_verify_val.setText("Invalid / Tampered")
            self.session_verify_val.setObjectName("sessionValDanger")

        self._apply_theme(self.is_dark_mode)

    def _inject_tamper(self, mode: str):
        if not self.active_signature_bytes:
            QMessageBox.warning(self, "Tamper Test Notice", "Please click 'Sign with RSA Private Key' first to create a baseline signature.")
            return

        text = self.studio_doc_edit.toPlainText()
        if mode == "amount":
            if "$5,000.00 USD" in text:
                modified = text.replace("$5,000.00 USD", "$9,000.00 USD")
            elif "Amount: 5000" in text:
                modified = text.replace("Amount: 5000", "Amount: 9000")
            elif "Grade: A+ (Outstanding)" in text:
                modified = text.replace("Grade: A+ (Outstanding)", "Grade: F (Failed)")
            else:
                modified = text + "\n[TAMPERED CONTENT: $9,000.00 USD]"
        elif mode == "whitespace":
            modified = text + " "
        else:
            modified = text + "\n[Tampered]"

        self.studio_doc_edit.setPlainText(modified)

    def _revert_tampering(self):
        self.studio_doc_edit.setPlainText(self.original_content_snapshot)
        self.is_tampered = False
        self.btn_revert.hide()
        self.studio_tamper_alert.hide()
        self.studio_verification_card.hide()
        self.studio_verify_status_pill.setText("Pending Verification")
        self.studio_verify_status_pill.setObjectName("pillMuted")
        self.session_verify_val.setText("Ready")
        self.session_verify_val.setObjectName("sessionValMuted")
        self._apply_theme(self.is_dark_mode)

    def _reset_studio(self):
        self.active_private_key = None
        self.active_public_key = None
        self.active_signature_bytes = None
        self.active_signature_hex = ""
        self.is_tampered = False

        self.studio_key_status_pill.setText("⚠ Keys Needed")
        self.studio_key_status_pill.setObjectName("pillWarning")
        self.studio_key_info_box.hide()

        self._select_studio_preset(0)

        self.studio_sig_status_pill.setText("Not Signed")
        self.studio_sig_status_pill.setObjectName("pillMuted")
        self.studio_sig_box.hide()
        self.btn_studio_dl_sig.setEnabled(False)

        self.studio_verify_status_pill.setText("Pending Verification")
        self.studio_verify_status_pill.setObjectName("pillMuted")
        self.studio_verification_card.hide()
        self.btn_revert.hide()
        self.studio_tamper_alert.hide()

        self.session_key_val.setText("None")
        self.session_key_val.setObjectName("sessionValMuted")
        self.session_sig_val.setText("None")
        self.session_sig_val.setObjectName("sessionValMuted")
        self.session_verify_val.setText("Ready")
        self.session_verify_val.setObjectName("sessionValMuted")

        self.demo_progress_widget.hide()
        self._apply_theme(self.is_dark_mode)

    # 1-CLICK COMPLETE CLASSROOM EXECUTION
    def handle_1click_classroom_demo(self):
        if self.is_running_auto_demo:
            return
        self.is_running_auto_demo = True
        self.btn_1click_demo.setEnabled(False)
        self.demo_progress_widget.show()

        # Step 1: Keys
        self._set_demo_step_ui(1)
        self._generate_studio_keys(2048)

        # Step 2: Document (after 700ms)
        QTimer.singleShot(700, self._auto_step2)

    def _auto_step2(self):
        self._set_demo_step_ui(2)
        self._select_studio_preset(0)
        # Step 3: Sign (after 800ms)
        QTimer.singleShot(800, self._auto_step3)

    def _auto_step3(self):
        self._set_demo_step_ui(3)
        self._sign_studio_document()
        # Step 4: Verify (after 900ms)
        QTimer.singleShot(900, self._auto_step4)

    def _auto_step4(self):
        self._set_demo_step_ui(4)
        self._verify_studio_signature()
        # Step 5: Finish
        QTimer.singleShot(700, self._auto_finish)

    def _auto_finish(self):
        self.is_running_auto_demo = False
        self.btn_1click_demo.setEnabled(True)

    def _set_demo_step_ui(self, step: int):
        for i, pill in enumerate(self.step_pills):
            if i + 1 <= step:
                pill.setObjectName("stepPillActive")
            else:
                pill.setObjectName("stepPillInactive")
        self._apply_theme(self.is_dark_mode)

    # File and Clipboard Helpers
    def _copy_hash_to_clipboard(self):
        QApplication.clipboard().setText(self.studio_hash_display.text())
        QMessageBox.information(self, "Copied", "SHA-256 Message Digest copied to clipboard.")

    def _copy_signature_to_clipboard(self):
        QApplication.clipboard().setText(self.active_signature_hex)
        QMessageBox.information(self, "Copied", "RSA-PSS Digital Signature (Hex) copied to clipboard.")

    def _studio_load_sig_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Detached Signature File (.sig)", "", "Signature Files (*.sig);;All Files (*.*)"
        )
        if path:
            try:
                sig_data = FileHandler.read_binary_file(path)
                if len(sig_data) == 0:
                    raise ValueError("The selected signature file is empty (0 bytes).")
                self.active_signature_bytes = sig_data
                self.active_signature_hex = sig_data.hex()
                self.active_signature_size = len(sig_data)
                self.active_signature_timestamp = time.strftime("%H:%M:%S")

                fname = os.path.basename(path)
                self.studio_sig_status_pill.setText(f"✓ {len(sig_data)}B Loaded")
                self.studio_sig_status_pill.setObjectName("pillSuccess")
                self.studio_sig_size_lbl.setText(f"Loaded: {fname} ({len(sig_data)} bytes / {len(sig_data)*8} bits)")
                self.studio_sig_time_lbl.setText(f"Loaded: {self.active_signature_timestamp}")
                self.studio_sig_hex_preview.setText(self.active_signature_hex[:128] + "...")
                self.studio_sig_box.show()
                self.btn_studio_dl_sig.setEnabled(True)

                self.session_sig_val.setText(f"{len(sig_data)} B (File)")
                self.session_sig_val.setObjectName("sessionValSuccess")

                self.studio_verify_files_lbl.setText(f"Signature: {fname} ({len(sig_data)} B)")
                self._apply_theme(self.is_dark_mode)
                QMessageBox.information(self, "Signature Loaded", f"Detached signature loaded successfully from:\n{fname}\n({len(sig_data)} bytes).")
            except Exception as e:
                QMessageBox.critical(self, "Signature Read Error", f"Failed to read signature file:\n{str(e)}")

    def _studio_load_pubkey_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Public Key File (.pem)", "", "PEM Files (*.pem);;All Files (*.*)"
        )
        if path:
            try:
                pem_data = FileHandler.read_binary_file(path)
                pub_key = KeyManager.load_public_key_pem(pem_data)
                self.active_public_key = pub_key
                self.active_pub_pem = pem_data.decode('utf-8', errors='replace')
                self.active_key_size = pub_key.key_size

                fname = os.path.basename(path)
                self.studio_key_status_pill.setText(f"✓ {pub_key.key_size}-bit Loaded")
                self.studio_key_status_pill.setObjectName("pillSuccess")
                self.studio_key_mod_lbl.setText(f"Modulus: {pub_key.key_size} bits (External PEM)")
                self.studio_pem_viewer.setText(self.active_pub_pem)
                self.studio_key_info_box.show()

                self.session_key_val.setText(f"{pub_key.key_size}-bit (File)")
                self.session_key_val.setObjectName("sessionValSuccess")

                self.studio_verify_files_lbl.setText(f"Public Key: {fname} ({pub_key.key_size}-bit)")
                self._apply_theme(self.is_dark_mode)
                QMessageBox.information(self, "Public Key Loaded", f"Public key loaded successfully from:\n{fname}\n({pub_key.key_size}-bit RSA SPKI).")
            except Exception as e:
                QMessageBox.critical(self, "Public Key Error", f"Failed to parse public key PEM:\n{str(e)}")

    def _save_public_key_file(self):
        if not self.active_pub_pem:
            QMessageBox.warning(self, "Warning", "Please generate keys first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "public_key.pem", "PEM Files (*.pem)")
        if path:
            FileHandler.write_binary_file(path, self.active_pub_pem.encode('utf-8'), overwrite=True)
            QMessageBox.information(self, "Saved", f"Public Key saved to {path}")

    def _save_private_key_file(self):
        if not self.active_priv_pem:
            QMessageBox.warning(self, "Warning", "Please generate keys first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "private_key.pem", "PEM Files (*.pem)")
        if path:
            FileHandler.write_binary_file(path, self.active_priv_pem.encode('utf-8'), overwrite=True)
            QMessageBox.information(self, "Saved", f"Private Key saved to {path}")

    def _save_signature_file(self):
        if not self.active_signature_bytes:
            QMessageBox.warning(self, "Warning", "Please sign a document first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Digital Signature", f"{self.active_doc_name}.sig", "Signature Files (*.sig)")
        if path:
            FileHandler.write_binary_file(path, self.active_signature_bytes, overwrite=True)
            QMessageBox.information(self, "Saved", f"Detached Digital Signature saved to:\n{path}")

    # =========================================================================
    # OTHER PAGES (Architecture, KeyGen, Signing, Verification, Tampering, About)
    # =========================================================================
    def _create_dashboard_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setObjectName("studioScroll")

        container = QWidget()
        container.setObjectName("studioContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 32)
        layout.setSpacing(22)

        # Header Banner
        banner = QWidget()
        banner.setObjectName("studioBanner")
        b_layout = QVBoxLayout(banner)
        b_layout.setContentsMargins(24, 20, 24, 20)
        b_layout.setSpacing(8)

        tag = QLabel("● PROTOCOL ARCHITECTURE & MATHEMATICAL PIPELINE")
        tag.setObjectName("studioActiveTag")
        header = QLabel("Asymmetric Digital Signature Protocol Architecture")
        header.setObjectName("studioMainTitle")
        desc = QLabel(
            "Digital signatures solve the fundamental challenge of trust across untrusted networks by providing three "
            "indispensable mathematical guarantees: Authenticity (proving the true identity of the signer), "
            "Data Integrity (detecting any modification down to a single bit), and Non-Repudiation (preventing the "
            "signer from denying their cryptographic creation). This architecture combines SHA-256 and RSA-PSS with MGF1."
        )
        desc.setObjectName("pageLeadText")
        desc.setWordWrap(True)
        b_layout.addWidget(tag)
        b_layout.addWidget(header)
        b_layout.addWidget(desc)
        layout.addWidget(banner)

        # 3 Quick Action Cards
        cards_title = QLabel("Laboratory Practical Execution Modules")
        cards_title.setObjectName("stageTitle")
        layout.addWidget(cards_title)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(16)
        modules = [
            ("Stage 1", "RSA Key Generation", "Generate mathematically paired 2048/3072/4096-bit asymmetric keys with public exponent e = 65537 and optional PKCS#8 password encryption.", 2),
            ("Stage 2", "File Signing Engine", "Compute the cryptographic 256-bit SHA-256 digest and sign it using private key d with randomized RSA-PSS probabilistic padding.", 3),
            ("Stage 3", "Public Key Verifier", "Verify the detached .sig against original document text using sender's public key (e, n). Detects even 1-bit tampering instantly.", 4),
        ]
        for badge_txt, title, sub, target_idx in modules:
            card = QWidget()
            card.setObjectName("stageCard")
            c_lay = QVBoxLayout(card)
            c_lay.setContentsMargins(18, 16, 18, 18)
            c_lay.setSpacing(10)

            hdr_row = QHBoxLayout()
            badge = QLabel(badge_txt)
            badge.setObjectName("stageBadgeBlue")
            hdr_row.addWidget(badge)
            hdr_row.addStretch()
            c_lay.addLayout(hdr_row)

            t_lbl = QLabel(title)
            t_lbl.setObjectName("stageTitle")
            c_lay.addWidget(t_lbl)

            s_lbl = QLabel(sub)
            s_lbl.setObjectName("cardDescText")
            s_lbl.setWordWrap(True)
            c_lay.addWidget(s_lbl)
            c_lay.addStretch()

            btn = QPushButton("Open Module →")
            btn.setObjectName("primaryButton" if target_idx == 2 else "secondaryButton")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, idx=target_idx: self._navigate_to(idx))
            c_lay.addWidget(btn)
            cards_layout.addWidget(card)

        layout.addLayout(cards_layout)

        # Mathematical Workflow Group
        flow_card = QWidget()
        flow_card.setObjectName("stageCard")
        f_layout = QVBoxLayout(flow_card)
        f_layout.setContentsMargins(22, 20, 22, 22)
        f_layout.setSpacing(16)

        flow_hdr = QVBoxLayout()
        flow_hdr.setSpacing(4)
        flow_title = QLabel("Complete Verification Pipeline: Mathematical Step-by-Step Flow")
        flow_title.setObjectName("stageTitle")
        flow_sub = QLabel("Complies with NIST FIPS 186-4 (Digital Signature Standard) and PKCS#1 v2.2 specification:")
        flow_sub.setObjectName("cardDescText")
        flow_hdr.addWidget(flow_title)
        flow_hdr.addWidget(flow_sub)
        f_layout.addLayout(flow_hdr)

        # 6 Dedicated Step Cards in a sequence
        steps_grid = QVBoxLayout()
        steps_grid.setSpacing(10)

        workflow_steps = [
            ("Step 1", "Asymmetric Key Pair Generation (Alice)",
             "(d, (e, n)) ← RSA-KeyGen(k = 2048, e = 65537)",
             "Alice generates two large prime numbers p and q. The modulus n = p · q and public exponent e = 65537 form the Public Key. The private exponent d = e⁻¹ mod λ(n) is kept confidential."),
            ("Step 2", "Cryptographic Hash Computation (Alice)",
             "h = SHA-256(M) ∈ {0, 1}²⁵⁶ (32 Bytes / 64 Hex Digits)",
             "Instead of encrypting the entire document M, Alice compresses M using SHA-256. This is computationally fast and produces a fixed 32-byte digest that changes completely upon altering any bit."),
            ("Step 3", "Probabilistic RSA-PSS Digital Signing (Alice)",
             "S = Sign_d(h) = (EM)^d mod n  [Salt = 32 bytes, MGF1 = SHA-256]",
             "Alice encodes hash h using PSS padding with randomized salt to prevent deterministic replay attacks. She signs the encoded message using private exponent d to generate detached signature S."),
            ("Step 4", "Transmission Across Insecure Network",
             "Network Transmission: { M (Document), S (Signature .sig), (e, n) (Public Key .pem) }",
             "Alice sends plaintext document M, detached signature S (256 bytes for 2048-bit RSA), and her public key (e, n) to Bob over standard communication channels without needing confidentiality."),
            ("Step 5", "Recipient Public Key Verification (Bob)",
             "h' = SHA-256(M)  ≟  Verify_{(e, n)}(S) ⟹ { VALID, INVALID }",
             "Bob recomputes hash h' = SHA-256(M) from the received document. Using Alice's public key (e, n), he verifies signature S. If the reconstructed digest matches h', validity is mathematically proven."),
            ("Step 6", "Avalanche Effect & Tamper Immunity",
             "M ≠ M* ⟹ SHA-256(M) ≠ SHA-256(M*) ⟹ Verification Fails",
             "If an adversary alters even a single character, spacing, or digit (e.g. $5,000 to $9,000), Bob's recomputed hash h' diverges completely, causing the verification engine to reject the signature immediately.")
        ]

        for s_num, s_title, s_math, s_desc in workflow_steps:
            step_box = QWidget()
            step_box.setObjectName("archStepCard")
            sb_lay = QVBoxLayout(step_box)
            sb_lay.setContentsMargins(14, 12, 14, 12)
            sb_lay.setSpacing(6)

            top_row = QHBoxLayout()
            top_row.setSpacing(10)
            pill = QLabel(s_num)
            pill.setObjectName("archStepNum")
            top_row.addWidget(pill)

            t = QLabel(s_title)
            t.setObjectName("archStepTitle")
            top_row.addWidget(t)
            top_row.addStretch()

            m = QLabel(s_math)
            m.setObjectName("archStepFormula")
            top_row.addWidget(m)
            sb_lay.addLayout(top_row)

            d = QLabel(s_desc)
            d.setObjectName("archStepDesc")
            d.setWordWrap(True)
            sb_lay.addWidget(d)

            steps_grid.addWidget(step_box)

        f_layout.addLayout(steps_grid)
        layout.addWidget(flow_card)

        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    def _create_key_gen_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setObjectName("studioScroll")

        container = QWidget()
        container.setObjectName("studioContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 32)
        layout.setSpacing(20)

        # Header Banner
        banner = QWidget()
        banner.setObjectName("studioBanner")
        b_layout = QVBoxLayout(banner)
        b_layout.setContentsMargins(24, 20, 24, 20)
        b_layout.setSpacing(8)

        tag = QLabel("● ASYMMETRIC KEY PAIR GENERATOR · NIST FIPS COMPLIANT")
        tag.setObjectName("studioActiveTag")
        title = QLabel("RSA Key Pair Generation & Certificate Management")
        title.setObjectName("studioMainTitle")
        desc = QLabel(
            "Generate mathematically linked RSA private and public key pairs using the cryptography library. "
            "Private keys are formatted in PKCS#8 with optional BestAvailableEncryption (AES-256-CBC) password "
            "protection for secure local storage. Public keys are formatted in SubjectPublicKeyInfo (SPKI) PEM."
        )
        desc.setObjectName("pageLeadText")
        desc.setWordWrap(True)
        b_layout.addWidget(tag)
        b_layout.addWidget(title)
        b_layout.addWidget(desc)
        layout.addWidget(banner)

        # Key Configuration Card
        cfg_card = QWidget()
        cfg_card.setObjectName("stageCard")
        c_layout = QVBoxLayout(cfg_card)
        c_layout.setContentsMargins(22, 18, 22, 20)
        c_layout.setSpacing(14)

        cfg_hdr = QHBoxLayout()
        cfg_title = QLabel("Key Generation Parameters & Password Protection")
        cfg_title.setObjectName("stageTitle")
        cfg_hdr.addWidget(cfg_title)
        cfg_hdr.addStretch()

        self.kg_status_pill = QLabel("⚠ No Keys Generated Yet")
        self.kg_status_pill.setObjectName("pillWarning")
        cfg_hdr.addWidget(self.kg_status_pill)
        c_layout.addLayout(cfg_hdr)

        # Form Controls Grid
        form_row = QHBoxLayout()
        form_row.setSpacing(16)

        # Left Column: Key Size
        col_size = QVBoxLayout()
        col_size.setSpacing(6)
        lbl_size = QLabel("Modulus Length (Key Strength):")
        lbl_size.setObjectName("formFieldLabel")
        col_size.addWidget(lbl_size)
        self.kg_combo = QComboBox()
        self.kg_combo.setObjectName("styledComboBox")
        self.kg_combo.addItems([
            "2048 bits (Standard NIST Recommendation — Fast & Secure)",
            "3072 bits (Equivalent to 128-bit symmetric security)",
            "4096 bits (Maximum Laboratory Strength)"
        ])
        col_size.addWidget(self.kg_combo)
        form_row.addLayout(col_size, stretch=1)

        # Right Column: Password
        col_pass = QVBoxLayout()
        col_pass.setSpacing(6)
        lbl_pass = QLabel("Private Key Password Protection (Optional):")
        lbl_pass.setObjectName("formFieldLabel")
        col_pass.addWidget(lbl_pass)
        self.kg_pass = QLineEdit()
        self.kg_pass.setObjectName("styledLineEdit")
        self.kg_pass.setEchoMode(QLineEdit.Password)
        self.kg_pass.setPlaceholderText("Enter optional passphrase for PKCS#8 encryption...")
        col_pass.addWidget(self.kg_pass)
        form_row.addLayout(col_pass, stretch=1)

        c_layout.addLayout(form_row)

        # Action Buttons Row
        action_row = QHBoxLayout()
        action_row.setSpacing(10)

        gen_btn = QPushButton("⚡ Generate RSA Key Pair")
        gen_btn.setObjectName("primaryButton")
        gen_btn.setCursor(Qt.PointingHandCursor)
        gen_btn.clicked.connect(self._handle_keygen_page_generate)
        action_row.addWidget(gen_btn)

        btn_reset_keys = QPushButton("↺ Clear Current Keys")
        btn_reset_keys.setObjectName("secondaryButton")
        btn_reset_keys.setCursor(Qt.PointingHandCursor)
        btn_reset_keys.clicked.connect(self._handle_keygen_page_reset)
        action_row.addWidget(btn_reset_keys)

        action_row.addStretch()

        self.kg_meta_lbl = QLabel("Public Exponent: e = 65537 (0x10001) · SHA-256 Digest")
        self.kg_meta_lbl.setObjectName("keyMetaLabel")
        action_row.addWidget(self.kg_meta_lbl)

        c_layout.addLayout(action_row)
        layout.addWidget(cfg_card)

        # Splitter for PEMs (Dynamic Auto-expanding with scroll)
        spl = QSplitter(Qt.Horizontal)
        spl.setObjectName("studioSplitter")
        spl.setHandleWidth(14)

        # Private Key Box
        b_priv = QWidget()
        b_priv.setObjectName("stageCard")
        l_priv = QVBoxLayout(b_priv)
        l_priv.setContentsMargins(18, 16, 18, 18)
        l_priv.setSpacing(10)

        priv_hdr = QHBoxLayout()
        badge_priv = QLabel("PRIVATE")
        badge_priv.setObjectName("stageBadgeAmber")
        priv_hdr.addWidget(badge_priv)
        t_priv = QLabel("Private Key (Secret — Used for Signing)")
        t_priv.setObjectName("stageTitle")
        priv_hdr.addWidget(t_priv)
        priv_hdr.addStretch()
        l_priv.addLayout(priv_hdr)

        p_info = QLabel("PKCS#8 PEM format. Must be kept strictly confidential by signer.")
        p_info.setObjectName("cardDescText")
        l_priv.addWidget(p_info)

        self.kg_priv_edit = QTextEdit()
        self.kg_priv_edit.setObjectName("codeViewerBox")
        self.kg_priv_edit.setReadOnly(True)
        self.kg_priv_edit.setMinimumHeight(240)
        self.kg_priv_edit.setFont(QFont("Consolas", 10))
        self.kg_priv_edit.setPlaceholderText("Private key PEM will appear here after generation...")
        l_priv.addWidget(self.kg_priv_edit)

        priv_btns = QHBoxLayout()
        priv_btns.setSpacing(8)
        btn_sp = QPushButton("💾 Save private_key.pem")
        btn_sp.setObjectName("primaryButton")
        btn_sp.setCursor(Qt.PointingHandCursor)
        btn_sp.clicked.connect(self._save_private_key_file)
        priv_btns.addWidget(btn_sp)

        btn_cp_priv = QPushButton("📋 Copy Private PEM")
        btn_cp_priv.setObjectName("secondaryButton")
        btn_cp_priv.setCursor(Qt.PointingHandCursor)
        btn_cp_priv.clicked.connect(self._copy_kg_priv_pem)
        priv_btns.addWidget(btn_cp_priv)
        priv_btns.addStretch()
        l_priv.addLayout(priv_btns)

        spl.addWidget(b_priv)

        # Public Key Box
        b_pub = QWidget()
        b_pub.setObjectName("stageCard")
        l_pub = QVBoxLayout(b_pub)
        l_pub.setContentsMargins(18, 16, 18, 18)
        l_pub.setSpacing(10)

        pub_hdr = QHBoxLayout()
        badge_pub = QLabel("PUBLIC")
        badge_pub.setObjectName("stageBadgeBlue")
        pub_hdr.addWidget(badge_pub)
        t_pub = QLabel("Public Key (Shared — Used for Verification)")
        t_pub.setObjectName("stageTitle")
        pub_hdr.addWidget(t_pub)
        pub_hdr.addStretch()
        l_pub.addLayout(pub_hdr)

        u_info = QLabel("SubjectPublicKeyInfo (SPKI) PEM format. Freely distributed to recipients.")
        u_info.setObjectName("cardDescText")
        l_pub.addWidget(u_info)

        self.kg_pub_edit = QTextEdit()
        self.kg_pub_edit.setObjectName("codeViewerBox")
        self.kg_pub_edit.setReadOnly(True)
        self.kg_pub_edit.setMinimumHeight(240)
        self.kg_pub_edit.setFont(QFont("Consolas", 10))
        self.kg_pub_edit.setPlaceholderText("Public key PEM will appear here after generation...")
        l_pub.addWidget(self.kg_pub_edit)

        pub_btns = QHBoxLayout()
        pub_btns.setSpacing(8)
        btn_su = QPushButton("💾 Save public_key.pem")
        btn_su.setObjectName("primaryButton")
        btn_su.setCursor(Qt.PointingHandCursor)
        btn_su.clicked.connect(self._save_public_key_file)
        pub_btns.addWidget(btn_su)

        btn_cp_pub = QPushButton("📋 Copy Public PEM")
        btn_cp_pub.setObjectName("secondaryButton")
        btn_cp_pub.setCursor(Qt.PointingHandCursor)
        btn_cp_pub.clicked.connect(self._copy_kg_pub_pem)
        pub_btns.addWidget(btn_cp_pub)
        pub_btns.addStretch()
        l_pub.addLayout(pub_btns)

        spl.addWidget(b_pub)
        layout.addWidget(spl)

        # Bottom Mathematical Summary Box
        math_box = QWidget()
        math_box.setObjectName("nestedBox")
        mb_lay = QVBoxLayout(math_box)
        mb_lay.setContentsMargins(18, 14, 18, 14)
        mb_lay.setSpacing(6)

        mb_title = QLabel("Mathematical Asymmetric Relationship:")
        mb_title.setObjectName("stageTitle")
        mb_lay.addWidget(mb_title)

        mb_desc = QLabel(
            "• Public Key (e, n): Used by any verifier to check signatures via S^e mod n.\n"
            "• Private Key (d, n): Used only by Alice to compute S = (EM)^d mod n. Factoring n = p · q is computationally infeasible.\n"
            "• Exponent e = 65537 (2^16 + 1): Chosen because it has only two set bits, minimizing modular multiplication overhead."
        )
        mb_desc.setObjectName("cardDescText")
        mb_lay.addWidget(mb_desc)
        layout.addWidget(math_box)

        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    def _copy_kg_priv_pem(self):
        txt = self.kg_priv_edit.toPlainText().strip()
        if txt:
            QApplication.clipboard().setText(txt)
            QMessageBox.information(self, "Copied", "Private Key PEM copied to clipboard.")
        else:
            QMessageBox.warning(self, "No Key", "Please generate an RSA key pair first.")

    def _copy_kg_pub_pem(self):
        txt = self.kg_pub_edit.toPlainText().strip()
        if txt:
            QApplication.clipboard().setText(txt)
            QMessageBox.information(self, "Copied", "Public Key PEM copied to clipboard.")
        else:
            QMessageBox.warning(self, "No Key", "Please generate an RSA key pair first.")

    def _handle_keygen_page_reset(self):
        self.kg_priv_edit.clear()
        self.kg_pub_edit.clear()
        self.kg_pass.clear()
        self.kg_status_pill.setText("⚠️ No Keys Generated Yet")
        self.kg_status_pill.setObjectName("pillWarning")
        self._apply_theme(self.is_dark_mode)

    def _handle_keygen_page_generate(self):
        sz_txt = self.kg_combo.currentText()
        bits = 2048 if "2048" in sz_txt else (3072 if "3072" in sz_txt else 4096)
        pwd = self.kg_pass.text()

        try:
            priv, pub = KeyManager.generate_key_pair(bits)
            self.active_private_key = priv
            self.active_public_key = pub
            self.active_key_size = bits

            self.active_priv_pem = KeyManager.export_private_key_pem(priv, pwd).decode('utf-8')
            self.active_pub_pem = KeyManager.export_public_key_pem(pub).decode('utf-8')

            self.kg_priv_edit.setText(self.active_priv_pem)
            self.kg_pub_edit.setText(self.active_pub_pem)
            self.kg_status_pill.setText(f"✓ {bits}-bit Key Pair Active")
            self.kg_status_pill.setObjectName("pillSuccess")

            # Sync with Studio
            self.studio_key_status_pill.setText(f"✓ {bits}-bit Active")
            self.studio_key_status_pill.setObjectName("pillSuccess")
            self.studio_pem_viewer.setText(self.active_pub_pem)
            self.studio_key_info_box.show()
            self.studio_key_mod_lbl.setText(f"Modulus: {bits} bits")
            self.session_key_val.setText(f"{bits}-bit Active")
            self.session_key_val.setObjectName("sessionValSuccess")

            self._apply_theme(self.is_dark_mode)
            QMessageBox.information(self, "Keys Generated", f"Successfully generated {bits}-bit RSA Key Pair!\nPrivate and Public keys are ready for signing and verification.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _create_signing_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setObjectName("studioScroll")

        container = QWidget()
        container.setObjectName("studioContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 32)
        layout.setSpacing(18)

        # Header Banner
        banner = QWidget()
        banner.setObjectName("studioBanner")
        b_layout = QVBoxLayout(banner)
        b_layout.setContentsMargins(24, 20, 24, 20)
        b_layout.setSpacing(8)

        tag = QLabel("● RSA-PSS SIGNATURE GENERATION · DETACHED .SIG EXPORT")
        tag.setObjectName("studioActiveTag")
        header = QLabel("Sign a Text File (RSA-PSS with SHA-256 Digest)")
        header.setObjectName("studioMainTitle")
        desc = QLabel(
            "Generate a detached cryptographic digital signature (.sig) for plain text documents. "
            "The system computes the SHA-256 hash of your document, pads it using RSA-PSS with random salt (32 bytes), "
            "and encrypts it using your private key. The resulting signature proves message authenticity and data integrity."
        )
        desc.setObjectName("pageLeadText")
        desc.setWordWrap(True)
        b_layout.addWidget(tag)
        b_layout.addWidget(header)
        b_layout.addWidget(desc)
        layout.addWidget(banner)

        # Input Card
        doc_card = QWidget()
        doc_card.setObjectName("stageCard")
        dc_lay = QVBoxLayout(doc_card)
        dc_lay.setContentsMargins(20, 18, 20, 20)
        dc_lay.setSpacing(12)

        ctrls = QHBoxLayout()
        ctrls.setSpacing(10)
        btn_load = QPushButton("✨ Load Academic Sample")
        btn_load.setObjectName("secondaryButton")
        btn_load.setCursor(Qt.PointingHandCursor)
        btn_load.clicked.connect(lambda: self.sign_page_edit.setText(FileHandler.get_sample_document()))
        ctrls.addWidget(btn_load)

        btn_br = QPushButton("📂 Browse Text File (.txt)...")
        btn_br.setObjectName("secondaryButton")
        btn_br.setCursor(Qt.PointingHandCursor)
        btn_br.clicked.connect(self._browse_sign_page_file)
        ctrls.addWidget(btn_br)
        ctrls.addStretch()
        dc_lay.addLayout(ctrls)

        self.sign_page_edit = QTextEdit()
        self.sign_page_edit.setObjectName("documentTextEdit")
        self.sign_page_edit.setMinimumHeight(140)
        self.sign_page_edit.setFont(QFont("Consolas", 10))
        self.sign_page_edit.setPlaceholderText("Type or paste document text to sign...")
        self.sign_page_edit.setText(FileHandler.get_sample_document())
        dc_lay.addWidget(self.sign_page_edit)

        sign_btn = QPushButton("✍️ Sign Text File with RSA Private Key (Generate .sig)")
        sign_btn.setObjectName("primaryButton")
        sign_btn.setCursor(Qt.PointingHandCursor)
        sign_btn.clicked.connect(self._handle_sign_page_execute)
        dc_lay.addWidget(sign_btn)

        self.sign_page_out = QLabel("SHA-256 Digest: Not yet calculated\nSignature: None")
        self.sign_page_out.setObjectName("codeViewerBox")
        dc_lay.addWidget(self.sign_page_out)

        layout.addWidget(doc_card)
        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    def _browse_sign_page_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open Text File", "", "Text Files (*.txt);;All Files (*.*)")
        if p:
            self.sign_page_edit.setText(FileHandler.read_text_file(p))

    def _handle_sign_page_execute(self):
        text = self.sign_page_edit.toPlainText()
        if not text:
            QMessageBox.warning(self, "Warning", "Please enter text to sign.")
            return
        if not self.active_private_key:
            self._generate_studio_keys(2048)

        data = text.encode('utf-8')
        sig_bytes, sha256_hex = Signer.sign_data(data, self.active_private_key)
        self.active_signature_bytes = sig_bytes
        self.active_signature_hex = sig_bytes.hex()
        self.original_content_snapshot = text

        self.sign_page_out.setText(
            f"Step 2: SHA-256 Message Digest (256-bit):\n{sha256_hex}\n\n"
            f"Step 3: RSA-PSS Signature Generated ({len(sig_bytes)} bytes):\n{sig_bytes.hex()[:64]}..."
        )
        self.session_sig_val.setText(f"{len(sig_bytes)} B Active")
        self.session_sig_val.setObjectName("sessionValSuccess")

        # Prompt save
        p, _ = QFileDialog.getSaveFileName(self, "Save Digital Signature", "document.sig", "Signature Files (*.sig)")
        if p:
            FileHandler.write_binary_file(p, sig_bytes, overwrite=True)
            QMessageBox.information(self, "Saved", f"Signature saved to {p}")

    # =========================================================================
    # DEDICATED VERIFICATION MODULE (Matching VerificationView.tsx)
    # Inputs: Detached Signature (.sig), Public Key (.pem), Document (.txt)
    # Outputs: Visual cryptographic status, SHA-256 hash, timing, math details
    # =========================================================================
    def _create_verification_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setObjectName("studioScroll")

        container = QWidget()
        container.setObjectName("studioContainer")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(18)

        # 1. Top Header Banner
        banner = QWidget()
        banner.setObjectName("studioBanner")
        b_layout = QVBoxLayout(banner)
        b_layout.setContentsMargins(20, 16, 20, 16)
        b_layout.setSpacing(8)

        b_top = QHBoxLayout()
        b_info = QVBoxLayout()
        b_info.setSpacing(4)
        tag = QLabel("● RSA DIGITAL SIGNATURE VERIFICATION MODULE · STANDALONE")
        tag.setObjectName("studioActiveTag")
        title = QLabel("Signature Verification & Cryptographic Integrity Check")
        title.setObjectName("studioMainTitle")
        desc = QLabel(
            "Verify detached digital signatures by providing the document text, "
            "the sender's RSA Public Key (.pem), and the detached Signature file (.sig). "
            "Witness mathematical validation of authenticity, data integrity, and non-repudiation offline."
        )
        desc.setObjectName("studioSubtitle")
        desc.setWordWrap(True)
        b_info.addWidget(tag)
        b_info.addWidget(title)
        b_info.addWidget(desc)
        b_top.addLayout(b_info, stretch=1)

        b_actions = QHBoxLayout()
        b_actions.setSpacing(8)

        btn_load_session = QPushButton("🔄 Load from Active Session")
        btn_load_session.setObjectName("primaryButton")
        btn_load_session.setCursor(Qt.PointingHandCursor)
        btn_load_session.clicked.connect(self._ver_load_from_session)
        b_actions.addWidget(btn_load_session)

        btn_load_sample = QPushButton("✨ Load Academic Sample")
        btn_load_sample.setObjectName("secondaryButton")
        btn_load_sample.setCursor(Qt.PointingHandCursor)
        btn_load_sample.clicked.connect(self._ver_load_sample)
        b_actions.addWidget(btn_load_sample)

        btn_clear = QPushButton("🗑️ Clear Inputs")
        btn_clear.setObjectName("secondaryButton")
        btn_clear.setCursor(Qt.PointingHandCursor)
        btn_clear.clicked.connect(self._ver_clear_inputs)
        b_actions.addWidget(btn_clear)

        b_top.addLayout(b_actions)
        b_layout.addLayout(b_top)
        layout.addWidget(banner)

        # 2. Main 3 Input Cards:
        # Card 1: Document text & SHA-256
        # Card 2 & 3: Side-by-side Public Key (.pem) & Signature (.sig)

        # --- INPUT 1: DOCUMENT CARD ---
        doc_card = QWidget()
        doc_card.setObjectName("stageCard")
        dc_layout = QVBoxLayout(doc_card)
        dc_layout.setContentsMargins(18, 16, 18, 18)
        dc_layout.setSpacing(10)

        dc_hdr = QHBoxLayout()
        badge1 = QLabel("1")
        badge1.setObjectName("stageBadgeBlue")
        dc_hdr.addWidget(badge1)
        dc_title = QLabel("Document Under Verification")
        dc_title.setObjectName("stageTitle")
        dc_hdr.addWidget(dc_title)
        dc_hdr.addStretch()

        self.ver_doc_badge = QLabel("Academic_Practical_Report.txt")
        self.ver_doc_badge.setObjectName("headerBadge")
        dc_hdr.addWidget(self.ver_doc_badge)

        self.ver_doc_stats = QLabel("389 chars · 389 bytes")
        self.ver_doc_stats.setObjectName("statsLabel")
        dc_hdr.addWidget(self.ver_doc_stats)
        dc_layout.addLayout(dc_hdr)

        dc_ctrl = QHBoxLayout()
        dc_ctrl.setSpacing(8)
        btn_browse_doc = QPushButton("📂 Browse Document (.txt)")
        btn_browse_doc.setObjectName("primaryButton")
        btn_browse_doc.setCursor(Qt.PointingHandCursor)
        btn_browse_doc.clicked.connect(self._ver_browse_document)
        dc_ctrl.addWidget(btn_browse_doc)

        btn_tamper_alter = QPushButton("⚠️ Alter Value ($5,000 → $9,000)")
        btn_tamper_alter.setObjectName("roseButton")
        btn_tamper_alter.setCursor(Qt.PointingHandCursor)
        btn_tamper_alter.clicked.connect(lambda: self._ver_tamper("amount"))
        dc_ctrl.addWidget(btn_tamper_alter)

        btn_tamper_space = QPushButton("+1 Space Tamper")
        btn_tamper_space.setObjectName("amberButton")
        btn_tamper_space.setCursor(Qt.PointingHandCursor)
        btn_tamper_space.clicked.connect(lambda: self._ver_tamper("whitespace"))
        dc_ctrl.addWidget(btn_tamper_space)

        self.ver_btn_revert = QPushButton("↺ Revert Original")
        self.ver_btn_revert.setObjectName("secondaryButton")
        self.ver_btn_revert.setCursor(Qt.PointingHandCursor)
        self.ver_btn_revert.clicked.connect(self._ver_revert_doc)
        self.ver_btn_revert.hide()
        dc_ctrl.addWidget(self.ver_btn_revert)

        dc_ctrl.addStretch()
        dc_layout.addLayout(dc_ctrl)

        self.ver_doc_edit = QTextEdit()
        self.ver_doc_edit.setObjectName("documentTextEdit")
        self.ver_doc_edit.setFixedHeight(110)
        self.ver_doc_edit.setPlainText(FileHandler.get_sample_document())
        self.ver_doc_edit.textChanged.connect(self._ver_on_text_changed)
        dc_layout.addWidget(self.ver_doc_edit)

        # Real-time SHA-256 Digest Box of Document
        ver_hash_box = QWidget()
        ver_hash_box.setObjectName("nestedBox")
        vh_layout = QVBoxLayout(ver_hash_box)
        vh_layout.setContentsMargins(12, 8, 12, 8)
        vh_layout.setSpacing(4)
        vh_hdr = QHBoxLayout()
        vh_title = QLabel("Recomputed Document SHA-256 Message Digest:")
        vh_title.setObjectName("hashTitleLabel")
        vh_hdr.addWidget(vh_title)
        vh_hdr.addStretch()
        btn_copy_vh = QPushButton("Copy Hash")
        btn_copy_vh.setObjectName("linkBtn")
        btn_copy_vh.setCursor(Qt.PointingHandCursor)
        btn_copy_vh.clicked.connect(self._ver_copy_hash)
        vh_hdr.addWidget(btn_copy_vh)
        vh_layout.addLayout(vh_hdr)

        self.ver_hash_lbl = QLabel("Calculating hash...")
        self.ver_hash_lbl.setObjectName("hashDisplay")
        self.ver_hash_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vh_layout.addWidget(self.ver_hash_lbl)
        dc_layout.addWidget(ver_hash_box)

        layout.addWidget(doc_card)

        # --- INPUT 2 & 3: Side-by-Side (Public Key .pem & Signature .sig) ---
        keys_splitter = QSplitter(Qt.Horizontal)
        keys_splitter.setHandleWidth(16)
        keys_splitter.setObjectName("studioSplitter")

        # CARD 2: PUBLIC KEY (.PEM) INPUT
        pub_card = QWidget()
        pub_card.setObjectName("stageCard")
        pc_layout = QVBoxLayout(pub_card)
        pc_layout.setContentsMargins(18, 16, 18, 18)
        pc_layout.setSpacing(10)

        pc_hdr = QHBoxLayout()
        badge2 = QLabel("2")
        badge2.setObjectName("stageBadgeIndigo")
        pc_hdr.addWidget(badge2)
        pc_title = QLabel("Sender's RSA Public Key (.pem)")
        pc_title.setObjectName("stageTitle")
        pc_hdr.addWidget(pc_title)
        pc_hdr.addStretch()

        self.ver_pub_status_pill = QLabel("⚠️ Key Needed")
        self.ver_pub_status_pill.setObjectName("pillWarning")
        pc_hdr.addWidget(self.ver_pub_status_pill)
        pc_layout.addLayout(pc_hdr)

        pc_actions = QHBoxLayout()
        btn_browse_pub = QPushButton("📂 Browse Public Key (.pem)")
        btn_browse_pub.setObjectName("primaryButton")
        btn_browse_pub.setCursor(Qt.PointingHandCursor)
        btn_browse_pub.clicked.connect(self._ver_browse_pubkey)
        pc_actions.addWidget(btn_browse_pub)

        self.ver_pub_filename_lbl = QLabel("No file chosen")
        self.ver_pub_filename_lbl.setObjectName("statsLabel")
        pc_actions.addWidget(self.ver_pub_filename_lbl)
        pc_actions.addStretch()
        pc_layout.addLayout(pc_actions)

        self.ver_pub_meta_lbl = QLabel("Format: SubjectPublicKeyInfo (SPKI) PEM · e = 65537")
        self.ver_pub_meta_lbl.setObjectName("statsLabel")
        pc_layout.addWidget(self.ver_pub_meta_lbl)

        # Text edit to show PEM or paste PEM directly
        self.ver_pub_edit = QTextEdit()
        self.ver_pub_edit.setObjectName("codeViewerBox")
        self.ver_pub_edit.setFixedHeight(120)
        self.ver_pub_edit.setPlaceholderText("-----BEGIN PUBLIC KEY-----\nPaste or browse public_key.pem file here\n-----END PUBLIC KEY-----")
        self.ver_pub_edit.textChanged.connect(self._ver_on_pubkey_text_changed)
        pc_layout.addWidget(self.ver_pub_edit)

        keys_splitter.addWidget(pub_card)

        # CARD 3: DETACHED SIGNATURE (.SIG) INPUT
        sig_card = QWidget()
        sig_card.setObjectName("stageCard")
        sc_layout = QVBoxLayout(sig_card)
        sc_layout.setContentsMargins(18, 16, 18, 18)
        sc_layout.setSpacing(10)

        sc_hdr = QHBoxLayout()
        badge3 = QLabel("3")
        badge3.setObjectName("stageBadgeEmerald")
        sc_hdr.addWidget(badge3)
        sc_title = QLabel("Detached Digital Signature (.sig)")
        sc_title.setObjectName("stageTitle")
        sc_hdr.addWidget(sc_title)
        sc_hdr.addStretch()

        self.ver_sig_status_pill = QLabel("⚠️ .sig Needed")
        self.ver_sig_status_pill.setObjectName("pillWarning")
        sc_hdr.addWidget(self.ver_sig_status_pill)
        sc_layout.addLayout(sc_hdr)

        sc_actions = QHBoxLayout()
        btn_browse_sig = QPushButton("📂 Browse Signature File (.sig)")
        btn_browse_sig.setObjectName("emeraldButton")
        btn_browse_sig.setCursor(Qt.PointingHandCursor)
        btn_browse_sig.clicked.connect(self._ver_browse_signature)
        sc_actions.addWidget(btn_browse_sig)

        self.ver_sig_filename_lbl = QLabel("No file chosen")
        self.ver_sig_filename_lbl.setObjectName("statsLabel")
        sc_actions.addWidget(self.ver_sig_filename_lbl)
        sc_actions.addStretch()
        sc_layout.addLayout(sc_actions)

        self.ver_sig_meta_lbl = QLabel("Detached binary signature bytes (RSA-PSS with SHA-256)")
        self.ver_sig_meta_lbl.setObjectName("statsLabel")
        sc_layout.addWidget(self.ver_sig_meta_lbl)

        # Hex Preview Box of Signature
        sig_hex_box = QWidget()
        sig_hex_box.setObjectName("nestedBox")
        sh_layout = QVBoxLayout(sig_hex_box)
        sh_layout.setContentsMargins(10, 8, 10, 8)
        sh_layout.setSpacing(4)
        sh_hdr = QHBoxLayout()
        sh_title = QLabel("Signature Bytes Preview (Hex):")
        sh_title.setObjectName("hashTitleLabel")
        sh_hdr.addWidget(sh_title)
        sh_hdr.addStretch()
        btn_copy_sig_hex = QPushButton("Copy Hex")
        btn_copy_sig_hex.setObjectName("linkBtn")
        btn_copy_sig_hex.setCursor(Qt.PointingHandCursor)
        btn_copy_sig_hex.clicked.connect(self._ver_copy_sig_hex)
        sh_hdr.addWidget(btn_copy_sig_hex)
        sh_layout.addLayout(sh_hdr)

        self.ver_sig_hex_display = QLabel("No .sig signature loaded. Click 'Browse Signature File (.sig)' or 'Load from Active Session'.")
        self.ver_sig_hex_display.setObjectName("sigPreviewDisplay")
        self.ver_sig_hex_display.setWordWrap(True)
        self.ver_sig_hex_display.setTextInteractionFlags(Qt.TextSelectableByMouse)
        sh_layout.addWidget(self.ver_sig_hex_display)
        sc_layout.addWidget(sig_hex_box)

        keys_splitter.addWidget(sig_card)
        layout.addWidget(keys_splitter)

        # --- EXECUTION BUTTON ---
        exec_bar = QHBoxLayout()
        exec_bar.setSpacing(12)

        self.btn_ver_execute = QPushButton("🛡️ Verify Digital Signature with Public Key")
        self.btn_ver_execute.setObjectName("emeraldButton")
        self.btn_ver_execute.setFixedHeight(40)
        self.btn_ver_execute.setCursor(Qt.PointingHandCursor)
        self.btn_ver_execute.clicked.connect(self._ver_execute_verification)
        exec_bar.addWidget(self.btn_ver_execute, stretch=1)
        layout.addLayout(exec_bar)

        # --- VERIFICATION OUTCOME & DETAILED DIAGNOSTICS CONTAINER ---
        self.ver_outcome_card = QWidget()
        self.ver_outcome_card.setObjectName("verifyCardValid")
        oc_layout = QVBoxLayout(self.ver_outcome_card)
        oc_layout.setContentsMargins(18, 16, 18, 16)
        oc_layout.setSpacing(10)

        oc_hdr = QHBoxLayout()
        self.ver_res_icon = QLabel("✔")
        self.ver_res_icon.setObjectName("outcomeIcon")
        self.ver_res_title = QLabel("DIGITAL SIGNATURE VALID")
        self.ver_res_title.setObjectName("outcomeTitle")
        oc_hdr.addWidget(self.ver_res_icon)
        oc_hdr.addWidget(self.ver_res_title)
        oc_hdr.addStretch()

        self.ver_res_timing = QLabel("1.2 ms")
        self.ver_res_timing.setObjectName("outcomeTiming")
        oc_hdr.addWidget(self.ver_res_timing)
        oc_layout.addLayout(oc_hdr)

        self.ver_res_msg = QLabel("Authenticity & Data Integrity Confirmed.")
        self.ver_res_msg.setObjectName("outcomeMessage")
        self.ver_res_msg.setWordWrap(True)
        oc_layout.addWidget(self.ver_res_msg)

        self.ver_res_detail = QLabel("The decrypted signature hash matches the recomputed SHA-256 message digest.")
        self.ver_res_detail.setObjectName("outcomeDetail")
        self.ver_res_detail.setWordWrap(True)
        oc_layout.addWidget(self.ver_res_detail)

        # Diagnostics Details Box
        self.ver_diag_box = QWidget()
        self.ver_diag_box.setObjectName("nestedBox")
        diag_layout = QVBoxLayout(self.ver_diag_box)
        diag_layout.setContentsMargins(14, 12, 14, 12)
        diag_layout.setSpacing(6)

        diag_title = QLabel("Cryptographic Verification Breakdown:")
        diag_title.setObjectName("hashTitleLabel")
        diag_layout.addWidget(diag_title)

        self.ver_diag_hash_lbl = QLabel("• Recomputed SHA-256: ")
        self.ver_diag_hash_lbl.setObjectName("statsLabel")
        diag_layout.addWidget(self.ver_diag_hash_lbl)

        self.ver_diag_key_lbl = QLabel("• Verification Key: RSA Public Key (SPKI format)")
        self.ver_diag_key_lbl.setObjectName("statsLabel")
        diag_layout.addWidget(self.ver_diag_key_lbl)

        self.ver_diag_sig_lbl = QLabel("• Signature Scheme: RSA-PSS (MGF1 SHA-256, Salt = Max)")
        self.ver_diag_sig_lbl.setObjectName("statsLabel")
        diag_layout.addWidget(self.ver_diag_sig_lbl)

        self.ver_diag_math_lbl = QLabel("• Mathematical Status: Signature decrypts to matching digest")
        self.ver_diag_math_lbl.setObjectName("statsLabel")
        diag_layout.addWidget(self.ver_diag_math_lbl)

        oc_layout.addWidget(self.ver_diag_box)
        self.ver_outcome_card.hide()
        layout.addWidget(self.ver_outcome_card)

        scroll.setWidget(container)
        return scroll

    def _ver_browse_document(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Document File to Verify", "", "Text Files (*.txt);;All Files (*.*)"
        )
        if path:
            try:
                text = FileHandler.read_text_file(path)
                fname = os.path.basename(path)
                self.ver_doc_name = fname
                self.ver_original_snapshot = text
                self.ver_doc_badge.setText(fname)
                self.ver_btn_revert.hide()
                self.ver_outcome_card.hide()

                self.ver_doc_edit.blockSignals(True)
                self.ver_doc_edit.setPlainText(text)
                self.ver_doc_edit.blockSignals(False)

                self._ver_on_text_changed()
            except Exception as e:
                QMessageBox.critical(self, "File Error", f"Could not open document file:\n{str(e)}")

    def _ver_browse_pubkey(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Sender's Public Key (.pem)", "", "PEM Files (*.pem);;All Files (*.*)"
        )
        if path:
            try:
                data = FileHandler.read_binary_file(path)
                pub_key = KeyManager.load_public_key_pem(data)
                self.ver_pubkey_bytes = data
                self.ver_pubkey_obj = pub_key
                fname = os.path.basename(path)
                self.ver_pubkey_name = fname

                pem_str = data.decode('utf-8', errors='replace')
                self.ver_pub_edit.blockSignals(True)
                self.ver_pub_edit.setPlainText(pem_str)
                self.ver_pub_edit.blockSignals(False)

                self.ver_pub_filename_lbl.setText(f"File: {fname} ({pub_key.key_size}-bit)")
                self.ver_pub_status_pill.setText(f"✓ {pub_key.key_size}-bit SPKI")
                self.ver_pub_status_pill.setObjectName("pillSuccess")
                self.ver_pub_meta_lbl.setText(f"Format: SPKI PEM · Key Size: {pub_key.key_size} bits · Public Exponent: 65537")
                self.ver_outcome_card.hide()
                self._apply_theme(self.is_dark_mode)
            except Exception as e:
                QMessageBox.critical(self, "Public Key Error", f"Invalid RSA Public Key PEM file:\n{str(e)}")

    def _ver_browse_signature(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Detached Signature File (.sig)", "", "Signature Files (*.sig);;All Files (*.*)"
        )
        if path:
            try:
                data = FileHandler.read_binary_file(path)
                if len(data) == 0:
                    raise ValueError("The selected signature file is empty (0 bytes).")
                self.ver_sig_bytes = data
                fname = os.path.basename(path)
                self.ver_sig_name = fname

                self.ver_sig_filename_lbl.setText(f"File: {fname} ({len(data)} bytes)")
                self.ver_sig_status_pill.setText(f"✓ {len(data)}B Loaded")
                self.ver_sig_status_pill.setObjectName("pillSuccess")
                self.ver_sig_meta_lbl.setText(f"Detached binary signature: {len(data)} bytes ({len(data)*8} bits) · Scheme: RSA-PSS")
                self.ver_sig_hex_display.setText(data.hex())
                self.ver_outcome_card.hide()
                self._apply_theme(self.is_dark_mode)
            except Exception as e:
                QMessageBox.critical(self, "Signature Error", f"Failed to load signature file:\n{str(e)}")

    def _ver_on_text_changed(self):
        if not hasattr(self, 'ver_doc_edit') or not hasattr(self, 'ver_hash_lbl'):
            return
        text = self.ver_doc_edit.toPlainText()
        data = text.encode('utf-8')
        digest = hashlib.sha256(data).hexdigest()
        self.ver_hash_lbl.setText(digest)
        self.ver_doc_stats.setText(f"{len(text)} chars · {len(data)} bytes")
        if hasattr(self, 'ver_original_snapshot') and text != self.ver_original_snapshot:
            self.ver_btn_revert.show()
        elif hasattr(self, 'ver_btn_revert'):
            self.ver_btn_revert.hide()

    def _ver_on_pubkey_text_changed(self):
        pem_text = self.ver_pub_edit.toPlainText().strip()
        if not pem_text:
            self.ver_pubkey_obj = None
            self.ver_pub_status_pill.setText("⚠️ Key Needed")
            self.ver_pub_status_pill.setObjectName("pillWarning")
            self._apply_theme(self.is_dark_mode)
            return

        try:
            pub_key = KeyManager.load_public_key_pem(pem_text.encode('utf-8'))
            self.ver_pubkey_obj = pub_key
            self.ver_pubkey_bytes = pem_text.encode('utf-8')
            self.ver_pub_status_pill.setText(f"✓ {pub_key.key_size}-bit SPKI")
            self.ver_pub_status_pill.setObjectName("pillSuccess")
            self.ver_pub_meta_lbl.setText(f"Format: SPKI PEM · Key Size: {pub_key.key_size} bits · Public Exponent: 65537")
            self._apply_theme(self.is_dark_mode)
        except Exception:
            self.ver_pubkey_obj = None
            self.ver_pub_status_pill.setText("✕ Invalid PEM")
            self.ver_pub_status_pill.setObjectName("pillDanger")
            self._apply_theme(self.is_dark_mode)

    def _ver_copy_hash(self):
        QApplication.clipboard().setText(self.ver_hash_lbl.text())
        QMessageBox.information(self, "Copied", "Recomputed SHA-256 Digest copied to clipboard.")

    def _ver_copy_sig_hex(self):
        if self.ver_sig_bytes:
            QApplication.clipboard().setText(self.ver_sig_bytes.hex())
            QMessageBox.information(self, "Copied", "Signature hex bytes copied to clipboard.")
        else:
            QMessageBox.warning(self, "No Signature", "No signature bytes available to copy.")

    def _ver_tamper(self, mode: str):
        text = self.ver_doc_edit.toPlainText()
        if mode == "amount":
            if "$5,000.00 USD" in text:
                mod = text.replace("$5,000.00 USD", "$9,000.00 USD")
            elif "CS-2024-8891" in text:
                mod = text.replace("CS-2024-8891", "CS-2024-9999 (Tampered)")
            else:
                mod = text + "\n[TAMPERED: Altered financial / grade record]"
        else:
            mod = text + " "

        self.ver_doc_edit.setPlainText(mod)
        self.ver_btn_revert.show()
        if self.ver_pubkey_obj and self.ver_sig_bytes:
            self._ver_execute_verification()

    def _ver_revert_doc(self):
        self.ver_doc_edit.setPlainText(self.ver_original_snapshot)
        self.ver_btn_revert.hide()
        if self.ver_pubkey_obj and self.ver_sig_bytes:
            self._ver_execute_verification()

    def _ver_load_from_session(self):
        # 1. Document
        studio_text = self.studio_doc_edit.toPlainText()
        if studio_text:
            self.ver_doc_name = self.active_doc_name
            self.ver_original_snapshot = self.original_content_snapshot
            self.ver_doc_badge.setText(self.active_doc_name)
            self.ver_doc_edit.setPlainText(studio_text)

        # 2. Public Key
        if self.active_public_key and self.active_pub_pem:
            self.ver_pubkey_obj = self.active_public_key
            self.ver_pubkey_bytes = self.active_pub_pem.encode('utf-8')
            self.ver_pub_edit.setPlainText(self.active_pub_pem)
            self.ver_pub_filename_lbl.setText("Session: public_key.pem")
            self.ver_pub_status_pill.setText(f"✓ {self.active_key_size}-bit Active")
            self.ver_pub_status_pill.setObjectName("pillSuccess")
            self.ver_pub_meta_lbl.setText(f"Active Session Key · Modulus: {self.active_key_size} bits")

        # 3. Signature
        if self.active_signature_bytes:
            self.ver_sig_bytes = self.active_signature_bytes
            self.ver_sig_name = f"{self.active_doc_name.split('.')[0]}.sig"
            self.ver_sig_filename_lbl.setText(f"Session: {self.ver_sig_name} ({len(self.active_signature_bytes)} B)")
            self.ver_sig_status_pill.setText(f"✓ {len(self.active_signature_bytes)}B Active")
            self.ver_sig_status_pill.setObjectName("pillSuccess")
            self.ver_sig_meta_lbl.setText(f"Active Session Detached Signature: {len(self.active_signature_bytes)} bytes")
            self.ver_sig_hex_display.setText(self.active_signature_bytes.hex())

        self._ver_on_text_changed()
        self._apply_theme(self.is_dark_mode)

        if not self.active_public_key or not self.active_signature_bytes:
            QMessageBox.information(
                self, "Loaded Partial Session",
                "Loaded available session data. Tip: If you haven't generated keys or signed in 'Interactive Studio' yet, click '✨ Load Academic Sample' or browse external files."
            )
        else:
            QMessageBox.information(
                self, "Session Synchronized",
                "Successfully synchronized Document, Public Key (.pem), and Detached Signature (.sig) from your active laboratory session!"
            )

    def _ver_load_sample(self):
        sample_doc = FileHandler.get_sample_document()
        self.ver_doc_name = "Academic_Practical_Report.txt"
        self.ver_original_snapshot = sample_doc
        self.ver_doc_badge.setText("Academic_Practical_Report.txt")
        self.ver_doc_edit.setPlainText(sample_doc)

        # Ensure we have a valid key & signature
        if not self.active_private_key:
            self._generate_studio_keys(2048)

        data = sample_doc.encode('utf-8')
        sig_bytes, sha256_hex = Signer.sign_data(data, self.active_private_key)
        self.active_signature_bytes = sig_bytes

        # Populate verification inputs
        self.ver_pubkey_obj = self.active_public_key
        self.ver_pubkey_bytes = self.active_pub_pem.encode('utf-8')
        self.ver_pub_edit.setPlainText(self.active_pub_pem)
        self.ver_pub_filename_lbl.setText("Sample: public_key.pem")
        self.ver_pub_status_pill.setText("✓ 2048-bit SPKI")
        self.ver_pub_status_pill.setObjectName("pillSuccess")

        self.ver_sig_bytes = sig_bytes
        self.ver_sig_name = "Academic_Practical_Report.sig"
        self.ver_sig_filename_lbl.setText("Sample: Academic_Practical_Report.sig (256 B)")
        self.ver_sig_status_pill.setText("✓ 256B Loaded")
        self.ver_sig_status_pill.setObjectName("pillSuccess")
        self.ver_sig_hex_display.setText(sig_bytes.hex())

        self._ver_on_text_changed()
        self._apply_theme(self.is_dark_mode)
        QMessageBox.information(self, "Sample Loaded", "Standard Academic Practical document, 2048-bit public key (.pem), and valid detached signature (.sig) loaded!")

    def _ver_clear_inputs(self):
        self.ver_doc_edit.clear()
        self.ver_pub_edit.clear()
        self.ver_pubkey_obj = None
        self.ver_pubkey_bytes = None
        self.ver_pub_filename_lbl.setText("No file chosen")
        self.ver_pub_status_pill.setText("⚠️ Key Needed")
        self.ver_pub_status_pill.setObjectName("pillWarning")

        self.ver_sig_bytes = None
        self.ver_sig_filename_lbl.setText("No file chosen")
        self.ver_sig_status_pill.setText("⚠️ .sig Needed")
        self.ver_sig_status_pill.setObjectName("pillWarning")
        self.ver_sig_hex_display.setText("No .sig signature loaded.")

        self.ver_outcome_card.hide()
        self._ver_on_text_changed()
        self._apply_theme(self.is_dark_mode)

    def _ver_execute_verification(self):
        doc_text = self.ver_doc_edit.toPlainText()
        if not doc_text:
            QMessageBox.warning(self, "Missing Document", "Please enter document text or click '📂 Browse Document (.txt)'.")
            return

        if not self.ver_pubkey_obj:
            pem_str = self.ver_pub_edit.toPlainText().strip()
            if pem_str:
                try:
                    self.ver_pubkey_obj = KeyManager.load_public_key_pem(pem_str.encode('utf-8'))
                except Exception as e:
                    QMessageBox.warning(self, "Invalid Public Key", f"The public key in the input box is invalid:\n{str(e)}")
                    return
            else:
                QMessageBox.warning(self, "Missing Public Key (.pem)", "Please load a public key file (.pem) or paste PEM text.")
                return

        if not self.ver_sig_bytes or len(self.ver_sig_bytes) == 0:
            QMessageBox.warning(self, "Missing Signature (.sig)", "Please load a detached digital signature file (.sig) using '📂 Browse Signature File (.sig)'.")
            return

        doc_bytes = doc_text.encode('utf-8')
        digest_hex = hashlib.sha256(doc_bytes).hexdigest()

        is_valid, diag = Verifier.verify_signature(doc_bytes, self.ver_sig_bytes, self.ver_pubkey_obj)
        timing = diag.get("timing_ms", 1.0)
        key_size = getattr(self.ver_pubkey_obj, "key_size", 2048)
        sig_len = len(self.ver_sig_bytes)

        self.ver_outcome_card.show()
        if is_valid:
            self.ver_outcome_card.setObjectName("verifyCardValid")
            self.ver_res_icon.setText("✔")
            self.ver_res_title.setText("DIGITAL SIGNATURE VALID — AUTHENTIC & UNTAMPERED")
            self.ver_res_timing.setText(f"{timing} ms")
            self.ver_res_msg.setText("Mathematical Verification Succeeded: Authenticity, Integrity & Non-Repudiation Guaranteed.")
            self.ver_res_detail.setText(
                "The detached signature was mathematically verified using the provided RSA public key (.pem). "
                "The document's SHA-256 digest matches the signature exactly. Zero bytes have been altered."
            )
            self.ver_diag_math_lbl.setText("• Mathematical Status: PASS — Recomputed SHA-256 matches decrypted RSA-PSS signature digest")
        else:
            self.ver_outcome_card.setObjectName("verifyCardInvalid")
            self.ver_res_icon.setText("✖")
            self.ver_res_title.setText("DIGITAL SIGNATURE INVALID — CRYPTOGRAPHIC REJECTION")
            self.ver_res_timing.setText(f"{timing} ms")
            self.ver_res_msg.setText("Tampering Detected or Key Mismatch: Signature Verification Failed.")
            self.ver_res_detail.setText(
                "The recomputed SHA-256 digest does NOT match the signature bytes under this public key. "
                "Either the document was altered after signing, an invalid signature file was provided, or the public key belongs to another party."
            )
            self.ver_diag_math_lbl.setText("• Mathematical Status: FAIL — Cryptography InvalidSignature Exception (Digest mismatch)")

        self.ver_diag_hash_lbl.setText(f"• Document SHA-256: {digest_hex}")
        self.ver_diag_key_lbl.setText(f"• RSA Public Key: {key_size}-bit SPKI (e = 65537) from '{self.ver_pubkey_name}'")
        self.ver_diag_sig_lbl.setText(f"• Signature Scheme: {sig_len} bytes ({sig_len*8} bits) RSA-PSS (MGF1 SHA-256) from '{self.ver_sig_name}'")

        self._apply_theme(self.is_dark_mode)

    def _create_about_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)

        header = QLabel("About RSA Digital Signature Studio")
        header.setObjectName("pageHeader")
        layout.addWidget(header)

        lbl = QLabel(
            "Academic Practical Suite: Digital Signature-Based File Signing and Verification Using RSA.\n\n"
            "Key Cryptographic Features:\n"
            "• RSA-PSS (Probabilistic Signature Scheme) with SHA-256 Digest\n"
            "• MGF1 Mask Generation with Maximum Salt Length (32 bytes)\n"
            "• Password-Protected Private Keys with BestAvailableEncryption (PKCS#8)\n"
            "• Immediate Hash Avalanche Effect and Mathematical Tamper Detection\n"
            "• Windows 11 Native Fluent UI with Light and Dark Theme Support\n\n"
            "Execution Standards:\n"
            "Complies with NIST FIPS 186-4 and PKCS#1 v2.2 specifications for modern public-key cryptography."
        )
        lbl.setWordWrap(True)
        layout.addWidget(lbl)
        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    # =========================================================================
    # THEME ENGINE & STYLESHEETS
    # =========================================================================
    def _toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self._apply_theme(self.is_dark_mode)
        if self.is_dark_mode:
            self.theme_btn.setText("☀️ Switch to Light Mode")
        else:
            self.theme_btn.setText("🌙 Switch to Dark Mode")

    def _toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
            self.fullscreen_btn.setText("⛶ Fullscreen")
        else:
            self.showFullScreen()
            self.fullscreen_btn.setText("🗗 Exit Fullscreen")

    def _apply_theme(self, is_dark: bool):
        if not is_dark:
            # WINDOWS 11 LIGHT THEME (Exact Tailwind Palette from Web Preview)
            self.setStyleSheet("""
            QMainWindow {
                background-color: #f8fafc;
                color: #0f172a;
                font-family: 'Segoe UI Variable Text', 'Segoe UI', -apple-system, sans-serif;
                font-size: 13.5px;
            }
            #headerBar {
                background-color: #f1f5f9;
                border-bottom: 1px solid #e2e8f0;
            }
            #headerTitle {
                font-size: 14px;
                font-weight: 700;
                color: #0f172a;
            }
            #headerBadge {
                font-size: 11px;
                font-weight: 600;
                color: #2563eb;
                background-color: #eff6ff;
                border: 1px solid #bfdbfe;
                padding: 3px 8px;
                border-radius: 4px;
            }
            #headerCenterInfo {
                font-size: 12px;
                color: #64748b;
            }
            #headerActionBtn {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 500;
                color: #334155;
            }
            #headerActionBtn:hover {
                background-color: #f8fafc;
                border-color: #94a3b8;
                color: #0f172a;
            }

            #sidebar {
                background-color: #ffffff;
                border-right: 1px solid #e2e8f0;
            }
            #sbTitle {
                font-size: 15px;
                font-weight: 700;
                color: #0f172a;
            }
            #sbSubtitle {
                font-size: 12px;
                color: #64748b;
            }
            #navButton {
                text-align: left;
                background-color: transparent;
                color: #334155;
                border: none;
                border-radius: 6px;
                padding: 9px 14px;
                font-size: 13px;
                font-weight: 500;
            }
            #navButton:hover {
                background-color: #f1f5f9;
                color: #0f172a;
            }
            #navButton:checked {
                background-color: #2563eb;
                color: #ffffff;
                font-weight: 600;
            }

            #sessionStateBox {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                font-size: 11px;
                font-weight: 700;
                color: #64748b;
                margin-top: 10px;
                padding-top: 12px;
            }
            #sessionValMuted {
                font-size: 11.5px;
                color: #94a3b8;
                font-weight: 500;
            }
            #sessionValText {
                font-size: 11.5px;
                color: #0f172a;
                font-weight: 600;
            }
            #sessionValSuccess {
                font-size: 11.5px;
                color: #059669;
                font-weight: 700;
            }
            #sessionValDanger {
                font-size: 11.5px;
                color: #e11d48;
                font-weight: 700;
            }

            #studioScroll, #studioContainer {
                background-color: #f8fafc;
            }
            #studioBanner {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }
            #studioActiveTag {
                font-size: 11px;
                font-weight: 700;
                color: #2563eb;
                letter-spacing: 0.5px;
            }
            #studioMainTitle {
                font-size: 22px;
                font-weight: 700;
                color: #0f172a;
            }
            #studioSubtitle {
                font-size: 13.5px;
                color: #64748b;
            }
            #pageLeadText {
                font-size: 14px;
                color: #334155;
                line-height: 1.5;
            }
            #cardDescText {
                font-size: 13px;
                color: #475569;
                line-height: 1.4;
            }
            #formFieldLabel {
                font-size: 13px;
                font-weight: 600;
                color: #334155;
            }
            #oneClickButton {
                background-color: #2563eb;
                border: 1px solid #1d4ed8;
                color: #ffffff;
                border-radius: 8px;
                padding: 10px 18px;
                font-size: 13px;
                font-weight: 600;
            }
            #oneClickButton:hover {
                background-color: #1d4ed8;
            }
            #stepPillActive {
                background-color: #eff6ff;
                border: 1px solid #bfdbfe;
                color: #1d4ed8;
                font-size: 12px;
                font-weight: 600;
                border-radius: 6px;
                padding: 8px 12px;
            }
            #stepPillInactive {
                background-color: #f1f5f9;
                color: #94a3b8;
                font-size: 12px;
                font-weight: 500;
                border-radius: 6px;
                padding: 8px 12px;
            }

            #stageCard {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
            }
            #stageTitle {
                font-size: 15px;
                font-weight: 700;
                color: #0f172a;
            }
            #stageBadgeBlue {
                background-color: #eff6ff;
                color: #2563eb;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #stageBadgeAmber {
                background-color: #fffbeb;
                color: #d97706;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #stageBadgeIndigo {
                background-color: #eef2ff;
                color: #4f46e5;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #stageBadgeEmerald {
                background-color: #ecfdf5;
                color: #059669;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #pillSuccess {
                background-color: #ecfdf5;
                color: #059669;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 12px;
                padding: 4px 10px;
            }
            #pillWarning {
                background-color: #fffbeb;
                color: #d97706;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 12px;
                padding: 4px 10px;
            }
            #pillDanger {
                background-color: #fff1f2;
                color: #e11d48;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 12px;
                padding: 4px 10px;
            }
            #pillMuted {
                background-color: #f1f5f9;
                color: #64748b;
                font-size: 11.5px;
                font-weight: 600;
                border-radius: 12px;
                padding: 4px 10px;
            }

            #pillBtn {
                background-color: #f1f5f9;
                border: 1px solid #e2e8f0;
                color: #475569;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            #pillBtn:hover {
                background-color: #e2e8f0;
                color: #0f172a;
            }
            #pillBtnActive {
                background-color: #2563eb;
                border: 1px solid #1d4ed8;
                color: #ffffff;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 700;
            }
            #presetBtn {
                background-color: #f1f5f9;
                border: 1px solid #e2e8f0;
                color: #475569;
                border-radius: 5px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 500;
            }
            #presetBtn:hover {
                background-color: #e2e8f0;
                color: #0f172a;
            }
            #presetBtnActive {
                background-color: #eff6ff;
                border: 1px solid #bfdbfe;
                color: #2563eb;
                border-radius: 5px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            #nestedBox {
                background-color: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
            }
            #codeViewerBox {
                background-color: #f8fafc;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                color: #0f172a;
                padding: 10px;
            }
            #documentTextEdit {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                color: #0f172a;
                padding: 10px;
            }
            #documentTextEdit:focus {
                border: 1.5px solid #2563eb;
            }

            #hashTitleLabel {
                font-size: 12.5px;
                font-weight: 700;
                color: #d97706;
            }
            #hashDisplay {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 5px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                font-weight: 600;
                color: #0f172a;
                padding: 8px;
            }
            #hashNoteLabel {
                font-size: 11.5px;
                color: #64748b;
            }

            #primaryButton {
                background-color: #2563eb;
                border: 1px solid #1d4ed8;
                color: #ffffff;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: 600;
            }
            #primaryButton:hover {
                background-color: #1d4ed8;
            }
            #indigoButton {
                background-color: #4f46e5;
                border: 1px solid #4338ca;
                color: #ffffff;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: 600;
            }
            #indigoButton:hover {
                background-color: #4338ca;
            }
            #emeraldButton {
                background-color: #059669;
                border: 1px solid #047857;
                color: #ffffff;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: 600;
            }
            #emeraldButton:hover {
                background-color: #047857;
            }
            #roseButton {
                background-color: #fff1f2;
                border: 1px solid #fecdd3;
                color: #e11d48;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            #roseButton:hover {
                background-color: #ffe4e6;
            }
            #amberButton {
                background-color: #fffbeb;
                border: 1px solid #fde68a;
                color: #d97706;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            #amberButton:hover {
                background-color: #fef3c7;
            }
            #secondaryButton {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                color: #334155;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 500;
            }
            #secondaryButton:hover {
                background-color: #f8fafc;
                border-color: #94a3b8;
                color: #0f172a;
            }
            #smallActionBtn {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                color: #334155;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 11.5px;
                font-weight: 500;
            }
            #smallActionBtn:hover {
                background-color: #f1f5f9;
                border-color: #94a3b8;
                color: #0f172a;
            }
            #linkBtn {
                background: transparent;
                border: none;
                color: #2563eb;
                font-size: 12px;
                font-weight: 600;
                padding: 2px 4px;
            }
            #linkBtn:hover {
                text-decoration: underline;
            }

            #sigPreviewDisplay {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 4px;
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                color: #4f46e5;
                padding: 8px;
            }

            #tamperAlertBox {
                background-color: #fff1f2;
                border: 1px solid #fecdd3;
                border-radius: 8px;
            }
            #tamperAlertTitle {
                font-size: 13px;
                font-weight: 700;
                color: #e11d48;
            }
            #tamperAlertDesc {
                font-size: 12.5px;
                color: #9f1239;
            }

            #verifyCardValid {
                background-color: #ecfdf5;
                border: 1.5px solid #a7f3d0;
                border-radius: 10px;
            }
            #verifyCardInvalid {
                background-color: #fff1f2;
                border: 1.5px solid #fecdd3;
                border-radius: 10px;
            }
            #outcomeIcon {
                font-size: 20px;
                font-weight: 700;
            }
            #outcomeTitle {
                font-size: 15px;
                font-weight: 700;
            }
            #outcomeTiming {
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                font-weight: 600;
                background-color: rgba(255, 255, 255, 0.7);
                padding: 3px 8px;
                border-radius: 4px;
            }
            #outcomeMessage {
                font-size: 13px;
                font-weight: 600;
            }
            #outcomeDetail {
                font-size: 12.5px;
                color: #334155;
            }
            #pageHeader {
                font-size: 22px;
                font-weight: 700;
                color: #0f172a;
            }
            #statsLabel {
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                color: #64748b;
            }
            #keyMetaLabel {
                font-size: 12px;
                font-weight: 600;
                color: #475569;
            }
            #archStepCard {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
            }
            #archStepNum {
                background-color: #eff6ff;
                color: #2563eb;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 4px;
                padding: 2px 8px;
                border: 1px solid #bfdbfe;
            }
            #archStepTitle {
                font-size: 14.5px;
                font-weight: 700;
                color: #0f172a;
            }
            #archStepFormula {
                background-color: #f1f5f9;
                color: #4338ca;
                border: 1px solid #e2e8f0;
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                font-weight: 600;
                padding: 3px 8px;
                border-radius: 4px;
            }
            #archStepDesc {
                font-size: 13px;
                color: #475569;
                line-height: 1.4;
            }
            QTextEdit, QLineEdit, QComboBox {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                color: #0f172a;
                font-size: 12.5px;
                padding: 7px;
            }
            """)
        else:
            # WINDOWS 11 DARK THEME (Matching Tailwind dark: Palette)
            self.setStyleSheet("""
            QMainWindow {
                background-color: #090d16;
                color: #f8fafc;
                font-family: 'Segoe UI Variable Text', 'Segoe UI', -apple-system, sans-serif;
                font-size: 13.5px;
            }
            #headerBar {
                background-color: #0f172a;
                border-bottom: 1px solid #1e293b;
            }
            #headerTitle {
                font-size: 14px;
                font-weight: 700;
                color: #f8fafc;
            }
            #headerBadge {
                font-size: 11px;
                font-weight: 600;
                color: #60a5fa;
                background-color: #1e293b;
                border: 1px solid #3b82f6;
                padding: 3px 8px;
                border-radius: 4px;
            }
            #headerCenterInfo {
                font-size: 12px;
                color: #94a3b8;
            }
            #headerActionBtn {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 500;
                color: #e2e8f0;
            }
            #headerActionBtn:hover {
                background-color: #334155;
            }

            #sidebar {
                background-color: #020617;
                border-right: 1px solid #1e293b;
            }
            #sbTitle {
                font-size: 15px;
                font-weight: 700;
                color: #f8fafc;
            }
            #sbSubtitle {
                font-size: 12px;
                color: #94a3b8;
            }
            #navButton {
                text-align: left;
                background-color: transparent;
                color: #cbd5e1;
                border: none;
                border-radius: 6px;
                padding: 9px 14px;
                font-size: 13px;
                font-weight: 500;
            }
            #navButton:hover {
                background-color: #1e293b;
                color: #ffffff;
            }
            #navButton:checked {
                background-color: #2563eb;
                color: #ffffff;
                font-weight: 600;
            }

            #sessionStateBox {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 8px;
                font-size: 11px;
                font-weight: 700;
                color: #94a3b8;
                margin-top: 10px;
                padding-top: 12px;
            }
            #sessionValMuted {
                font-size: 11.5px;
                color: #64748b;
                font-weight: 500;
            }
            #sessionValText {
                font-size: 11.5px;
                color: #f8fafc;
                font-weight: 600;
            }
            #sessionValSuccess {
                font-size: 11.5px;
                color: #34d399;
                font-weight: 700;
            }
            #sessionValDanger {
                font-size: 11.5px;
                color: #fb7185;
                font-weight: 700;
            }

            #studioScroll, #studioContainer {
                background-color: #090d16;
            }
            #studioBanner {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 12px;
            }
            #studioActiveTag {
                font-size: 11px;
                font-weight: 700;
                color: #60a5fa;
                letter-spacing: 0.5px;
            }
            #studioMainTitle {
                font-size: 22px;
                font-weight: 700;
                color: #f8fafc;
            }
            #studioSubtitle {
                font-size: 13.5px;
                color: #94a3b8;
            }
            #pageLeadText {
                font-size: 14px;
                color: #cbd5e1;
                line-height: 1.5;
            }
            #cardDescText {
                font-size: 13px;
                color: #94a3b8;
                line-height: 1.4;
            }
            #formFieldLabel {
                font-size: 13px;
                font-weight: 600;
                color: #cbd5e1;
            }
            #oneClickButton {
                background-color: #2563eb;
                border: 1px solid #1d4ed8;
                color: #ffffff;
                border-radius: 8px;
                padding: 10px 18px;
                font-size: 13px;
                font-weight: 600;
            }
            #oneClickButton:hover {
                background-color: #1d4ed8;
            }
            #stepPillActive {
                background-color: #1e3a8a;
                border: 1px solid #3b82f6;
                color: #bfdbfe;
                font-size: 12px;
                font-weight: 600;
                border-radius: 6px;
                padding: 8px 12px;
            }
            #stepPillInactive {
                background-color: #1e293b;
                color: #64748b;
                font-size: 12px;
                font-weight: 500;
                border-radius: 6px;
                padding: 8px 12px;
            }

            #stageCard {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 10px;
            }
            #stageTitle {
                font-size: 15px;
                font-weight: 700;
                color: #f8fafc;
            }
            #stageBadgeBlue {
                background-color: #1e3a8a;
                color: #93c5fd;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #stageBadgeAmber {
                background-color: #78350f;
                color: #fcd34d;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #stageBadgeIndigo {
                background-color: #312e81;
                color: #c7d2fe;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #stageBadgeEmerald {
                background-color: #064e3b;
                color: #6ee7b7;
                font-size: 12px;
                font-weight: 700;
                border-radius: 5px;
                padding: 3px 8px;
            }
            #pillSuccess {
                background-color: #064e3b;
                color: #6ee7b7;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 12px;
                padding: 4px 10px;
            }
            #pillWarning {
                background-color: #78350f;
                color: #fcd34d;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 12px;
                padding: 4px 10px;
            }
            #pillDanger {
                background-color: #881337;
                color: #fda4af;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 12px;
                padding: 4px 10px;
            }
            #pillMuted {
                background-color: #1e293b;
                color: #94a3b8;
                font-size: 11.5px;
                font-weight: 600;
                border-radius: 12px;
                padding: 4px 10px;
            }

            #pillBtn {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #cbd5e1;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            #pillBtn:hover {
                background-color: #334155;
                color: #ffffff;
            }
            #pillBtnActive {
                background-color: #2563eb;
                border: 1px solid #3b82f6;
                color: #ffffff;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 700;
            }
            #presetBtn {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #cbd5e1;
                border-radius: 5px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 500;
            }
            #presetBtn:hover {
                background-color: #334155;
                color: #ffffff;
            }
            #presetBtnActive {
                background-color: #1e3a8a;
                border: 1px solid #3b82f6;
                color: #93c5fd;
                border-radius: 5px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            #nestedBox {
                background-color: #020617;
                border: 1px solid #1e293b;
                border-radius: 8px;
            }
            #codeViewerBox {
                background-color: #020617;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                color: #f8fafc;
                padding: 10px;
            }
            #documentTextEdit {
                background-color: #020617;
                border: 1px solid #334155;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                color: #f8fafc;
                padding: 10px;
            }
            #documentTextEdit:focus {
                border: 1.5px solid #3b82f6;
            }

            #hashTitleLabel {
                font-size: 12.5px;
                font-weight: 700;
                color: #f59e0b;
            }
            #hashDisplay {
                background-color: #0f172a;
                border: 1px solid #334155;
                border-radius: 5px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                font-weight: 600;
                color: #f8fafc;
                padding: 8px;
            }
            #hashNoteLabel {
                font-size: 11.5px;
                color: #64748b;
            }

            #primaryButton {
                background-color: #2563eb;
                border: 1px solid #3b82f6;
                color: #ffffff;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: 600;
            }
            #primaryButton:hover {
                background-color: #1d4ed8;
            }
            #indigoButton {
                background-color: #4f46e5;
                border: 1px solid #6366f1;
                color: #ffffff;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: 600;
            }
            #indigoButton:hover {
                background-color: #4338ca;
            }
            #emeraldButton {
                background-color: #059669;
                border: 1px solid #10b981;
                color: #ffffff;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12.5px;
                font-weight: 600;
            }
            #emeraldButton:hover {
                background-color: #047857;
            }
            #roseButton {
                background-color: #881337;
                border: 1px solid #f43f5e;
                color: #fecdd3;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            #roseButton:hover {
                background-color: #9f1239;
            }
            #amberButton {
                background-color: #78350f;
                border: 1px solid #f59e0b;
                color: #fde68a;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            #amberButton:hover {
                background-color: #92400e;
            }
            #secondaryButton {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #cbd5e1;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 500;
            }
            #secondaryButton:hover {
                background-color: #334155;
                border-color: #64748b;
                color: #ffffff;
            }
            #smallActionBtn {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #cbd5e1;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 11.5px;
                font-weight: 500;
            }
            #smallActionBtn:hover {
                background-color: #334155;
                border-color: #64748b;
                color: #ffffff;
            }
            #linkBtn {
                background: transparent;
                border: none;
                color: #60a5fa;
                font-size: 12px;
                font-weight: 600;
                padding: 2px 4px;
            }
            #linkBtn:hover {
                text-decoration: underline;
            }

            #sigPreviewDisplay {
                background-color: #0f172a;
                border: 1px solid #334155;
                border-radius: 4px;
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                color: #818cf8;
                padding: 8px;
            }

            #tamperAlertBox {
                background-color: #881337;
                border: 1px solid #f43f5e;
                border-radius: 8px;
            }
            #tamperAlertTitle {
                font-size: 13px;
                font-weight: 700;
                color: #fecdd3;
            }
            #tamperAlertDesc {
                font-size: 12.5px;
                color: #fda4af;
            }

            #verifyCardValid {
                background-color: #064e3b;
                border: 1.5px solid #10b981;
                border-radius: 10px;
            }
            #verifyCardInvalid {
                background-color: #881337;
                border: 1.5px solid #f43f5e;
                border-radius: 10px;
            }
            #outcomeIcon {
                font-size: 20px;
                font-weight: 700;
            }
            #outcomeTitle {
                font-size: 15px;
                font-weight: 700;
            }
            #outcomeTiming {
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                font-weight: 600;
                background-color: rgba(0, 0, 0, 0.4);
                padding: 3px 8px;
                border-radius: 4px;
            }
            #outcomeMessage {
                font-size: 13px;
                font-weight: 600;
            }
            #outcomeDetail {
                font-size: 12.5px;
                color: #cbd5e1;
            }
            #pageHeader {
                font-size: 22px;
                font-weight: 700;
                color: #f8fafc;
            }
            #statsLabel {
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                color: #64748b;
            }
            #keyMetaLabel {
                font-size: 12px;
                font-weight: 600;
                color: #94a3b8;
            }
            #archStepCard {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 8px;
            }
            #archStepNum {
                background-color: #1e3a8a;
                color: #93c5fd;
                font-size: 11.5px;
                font-weight: 700;
                border-radius: 4px;
                padding: 2px 8px;
                border: 1px solid #3b82f6;
            }
            #archStepTitle {
                font-size: 14.5px;
                font-weight: 700;
                color: #f8fafc;
            }
            #archStepFormula {
                background-color: #1e293b;
                color: #a5b4fc;
                border: 1px solid #334155;
                font-family: 'Consolas', monospace;
                font-size: 11.5px;
                font-weight: 600;
                padding: 3px 8px;
                border-radius: 4px;
            }
            #archStepDesc {
                font-size: 13px;
                color: #94a3b8;
                line-height: 1.4;
            }
            QTextEdit, QLineEdit, QComboBox {
                background-color: #020617;
                border: 1px solid #334155;
                border-radius: 6px;
                color: #f8fafc;
                font-size: 12.5px;
                padding: 7px;
            }
            """)


def main():
    app = QApplication(sys.argv)
    # Default to Light Mode matching web preview
    start_in_dark = "--dark" in sys.argv
    window = MainWindow(is_dark=start_in_dark)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
