"""
DatabaseManager: إدارة قاعدة بيانات SQLite لجميع العمليات الإحصائية والتعلم
"""

import sqlite3
import time
import json

class DatabaseManager:
    """
    كلاس لإدارة جميع عمليات التخزين والاستعلام في قاعدة بيانات SQLite الخاصة بأنماط المفاتيح والتاريخ الإحصائي.
    """
    def __init__(self, db_path="ai_data.db"):
        """
        تهيئة الاتصال بقاعدة البيانات وإنشاء الجداول والفهارس إذا لم تكن موجودة.
        Args:
            db_path (str): مسار قاعدة بيانات SQLite.
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()
        self.create_indexes()

    def create_tables(self):
        """إنشاء جميع الجداول الضرورية إذا لم تكن موجودة."""
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS ai_knowledge_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                found_key TEXT,
                target_addr TEXT,
                range_start TEXT,
                range_stop TEXT,
                zeros_prefix INTEGER,
                zeros_suffix INTEGER,
                length INTEGER,
                entropy INTEGER,
                has_dead BOOLEAN,
                has_beef BOOLEAN,
                found_time INTEGER
            );
            CREATE TABLE IF NOT EXISTS ai_knowledge_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_addr TEXT,
                range_start TEXT,
                range_stop TEXT,
                success BOOLEAN,
                tries INTEGER,
                time_spent REAL,
                mode TEXT,
                timestamp INTEGER
            );
            CREATE TABLE IF NOT EXISTS molds_train (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                success BOOLEAN,
                found_key TEXT,
                target_addr TEXT,
                range_start TEXT,
                range_stop TEXT,
                tries INTEGER,
                mode TEXT,
                time_spent REAL,
                timestamp INTEGER
            );
            CREATE TABLE IF NOT EXISTS molds_stats (
                id INTEGER PRIMARY KEY,
                total_success INTEGER,
                total_fail INTEGER
            );
            CREATE TABLE IF NOT EXISTS top10_close_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value INTEGER,
                difference REAL,
                timestamp INTEGER
            );
            CREATE TABLE IF NOT EXISTS search_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_start INTEGER,
                session_end INTEGER,
                range_start TEXT,
                range_stop TEXT,
                mode TEXT,
                total_tries INTEGER,
                found BOOLEAN,
                winner_key TEXT,
                winner_address TEXT
            );
            CREATE TABLE IF NOT EXISTS report_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_json TEXT,
                created_at INTEGER
            );
        ''')
        self.conn.commit()

    def create_indexes(self):
        """إنشاء فهارس لتحسين الأداء."""
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_patterns_zeros_prefix ON ai_knowledge_patterns(zeros_prefix)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_patterns_entropy ON ai_knowledge_patterns(entropy)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_patterns_range_start ON ai_knowledge_patterns(range_start)")
        self.conn.commit()

    def insert_pattern(self, pattern):
        """إدراج نمط جديد في جدول الأنماط."""
        sql = '''
            INSERT INTO ai_knowledge_patterns (found_key, target_addr, range_start, range_stop, zeros_prefix, zeros_suffix, length, entropy, has_dead, has_beef, found_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        self.conn.execute(sql, (
            pattern.get("found_key"),
            pattern.get("target_addr"),
            pattern.get("range", {}).get("start"),
            pattern.get("range", {}).get("stop"),
            pattern.get("zeros_prefix"),
            pattern.get("zeros_suffix"),
            pattern.get("length"),
            pattern.get("entropy"),
            int(pattern.get("has_dead", False)),
            int(pattern.get("has_beef", False)),
            pattern.get("found_time")
        ))
        self.conn.commit()

    def insert_history(self, history):
        """إدراج محاولة بحث في جدول التاريخ."""
        sql = '''
            INSERT INTO ai_knowledge_history (target_addr, range_start, range_stop, success, tries, time_spent, mode, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        self.conn.execute(sql, (
            history.get("target_addr"),
            history.get("range", {}).get("start"),
            history.get("range", {}).get("stop"),
            int(history.get("success", False)),
            history.get("tries", 0),
            history.get("time_spent", 0.0),
            history.get("mode"),
            history.get("timestamp")
        ))
        self.conn.commit()

    def insert_training(self, entry):
        """إدراج سجل تدريب جديد."""
        sql = '''
            INSERT INTO molds_train (success, found_key, target_addr, range_start, range_stop, tries, mode, time_spent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        self.conn.execute(sql, (
            int(entry.get("success")),
            entry.get("found_key"),
            entry.get("target_addr"),
            entry.get("range", {}).get("start"),
            entry.get("range", {}).get("stop"),
            entry.get("tries"),
            entry.get("mode"),
            entry.get("time_spent"),
            entry.get("timestamp")
        ))
        self.conn.commit()

    def update_molds_stats(self, success=True):
        """تحديث عدادات النجاح/الفشل."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM molds_stats WHERE id=1")
        row = cur.fetchone()
        if row is None:
            total_success = 1 if success else 0
            total_fail = 0 if success else 1
            cur.execute("INSERT INTO molds_stats (id, total_success, total_fail) VALUES (1, ?, ?)", (total_success, total_fail))
        else:
            ts = row["total_success"]
            tf = row["total_fail"]
            if success:
                ts += 1
            else:
                tf += 1
            cur.execute("UPDATE molds_stats SET total_success=?, total_fail=? WHERE id=1", (ts, tf))
        self.conn.commit()

    def insert_search_session(self, session):
        """إدراج سجل جلسة بحث."""
        sql = '''
            INSERT INTO search_sessions (session_start, session_end, range_start, range_stop, mode, total_tries, found, winner_key, winner_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        self.conn.execute(sql, (
            session.get("session_start"),
            session.get("session_end"),
            session.get("range", {}).get("start"),
            session.get("range", {}).get("stop"),
            session.get("mode"),
            session.get("total_tries"),
            int(session.get("found", False)),
            session.get("winner_key"),
            session.get("winner_address")
        ))
        self.conn.commit()

    def insert_report_log(self, report_json):
        """تخزين تقرير جلسة بحث بتنسيق JSON."""
        sql = '''
            INSERT INTO report_logs (report_json, created_at)
            VALUES (?, ?)
        '''
        self.conn.execute(sql, (report_json, int(time.time())))
        self.conn.commit()

    def get_recent_patterns(self, limit=30):
        """الحصول على أحدث الأنماط."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM ai_knowledge_patterns ORDER BY found_time DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        return [dict(row) for row in rows]

    def get_training_records(self, mode=None):
        """الحصول على سجلات التدريب."""
        cur = self.conn.cursor()
        if mode:
            cur.execute("SELECT * FROM molds_train WHERE mode = ?", (mode,))
        else:
            cur.execute("SELECT * FROM molds_train")
        return [dict(row) for row in cur.fetchall()]

    def get_stats(self):
        """الحصول على إحصائيات شاملة."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM molds_stats WHERE id=1")
        row = cur.fetchone()
        return dict(row) if row else {"total_success": 0, "total_fail": 0}

    def export_db(self, filename):
        """تصدير جميع الأنماط والتدريب والتاريخ إلى ملف JSON."""
        export = {
            "patterns": self.get_recent_patterns(10000),
            "training": self.get_training_records(),
            "stats": self.get_stats()
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)

    def import_db(self, filename):
        """استيراد الأنماط والتدريب من ملف JSON."""
        with open(filename, encoding="utf-8") as f:
            data = json.load(f)
        for pat in data.get("patterns", []):
            self.insert_pattern(pat)
        for tr in data.get("training", []):
            self.insert_training(tr)
        # تحديث الإحصائيات
        stats = data.get("stats", {})
        cur = self.conn.cursor()
        cur.execute("DELETE FROM molds_stats WHERE id=1")
        cur.execute("INSERT INTO molds_stats (id, total_success, total_fail) VALUES (1, ?, ?)", (
            stats.get("total_success", 0), stats.get("total_fail", 0)
        ))
        self.conn.commit()

    def close(self):
        """إغلاق الاتصال بقاعدة البيانات."""
        self.conn.close()