#!/usr/bin/env python3
"""
البرنامج الرئيسي للبحث عن مفاتيح بيتكوين باستخدام الذكاء الاصطناعي وتخزين النتائج
"""

import sys
import os
import time
import json
import argparse
import multiprocessing
import signal

import numpy as np
try:
    from tqdm import tqdm
except ImportError:
    tqdm = lambda x, **kwargs: x

from settings import *
from db_manager import DatabaseManager
from ai_utils import *

def print_logo():
    print(r"""
     ___    _    __  __ _      ____     ___   ____  _  __
    / _ \  / \  |  \/  | |    / ___|   / _ \ / ___|| |/ /
   | | | |/ _ \ | |\/| | |   | |  _   | | | | |    | ' / 
   | |_| / ___ \| |  | | |___| |_| |  | |_| | |___ | . \ 
    \___/_/   \_\_|  |_|____(_)____(_) \___/ \____||_|\_\
    """)

def signal_handler(signum, frame):
    print("\n🛑 [EXIT] إنهاء البرنامج وحفظ البيانات...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def update_molds_on_success(found_hex_key, target_addr, range_info, db_manager):
    """تسجيل النجاح وتحديث الأنماط والتعلم."""
    pattern = extended_analyze_key(found_hex_key, start_hex=range_info.get("start"), stop_hex=range_info.get("stop"))
    pattern["found_key"] = found_hex_key
    pattern["target_addr"] = target_addr
    pattern["range"] = range_info
    pattern["found_time"] = int(time.time())
    db_manager.insert_pattern(pattern)
    db_manager.update_molds_stats(success=True)
    append_learning_log(pattern)

def update_molds_on_failure(target_addr, range_info, db_manager, tries=0):
    """تسجيل محاولة فاشلة ضمن قاعدة البيانات."""
    history = {
        "target_addr": target_addr,
        "range": range_info,
        "success": False,
        "tries": tries,
        "time_spent": 0,
        "mode": "AI",
        "timestamp": int(time.time())
    }
    db_manager.insert_history(history)
    db_manager.update_molds_stats(success=False)

def log_training(success, priv_hex, target_addr, range_info, tries, time_spent, mode, db_manager):
    """تسجيل محاولة تدريب في جدول مخصص."""
    entry = {
        "success": success,
        "found_key": priv_hex,
        "target_addr": target_addr,
        "range": range_info,
        "tries": tries,
        "mode": mode,
        "time_spent": time_spent,
        "timestamp": int(time.time())
    }
    db_manager.insert_training(entry)

def get_training_stats(db_manager, current_range, mode):
    """إحصائيات سريعة حول التدريب."""
    records = db_manager.get_training_records(mode)
    if not records:
        return 0.0, 0.0, None
    total = len(records)
    successes = [x for x in records if x["success"]]
    success_rate = (len(successes) / total) * 100 if total else 0.0
    avg_time = float(np.mean([x["time_spent"] for x in successes])) if successes else 0.0
    last_similar = None
    best_diff = float('inf')
    cur_start = int(current_range["start"], 16)
    cur_stop = int(current_range["stop"], 16)
    cur_size = cur_stop - cur_start
    for x in records:
        try:
            size = int(x["range_stop"], 16) - int(x["range_start"], 16)
            diff = abs(size - cur_size)
            if diff < best_diff:
                best_diff = diff
                last_similar = x
        except:
            continue
    return success_rate, avg_time, last_similar

def get_all_patterns(db_manager):
    return db_manager.get_recent_patterns(30)

def show_learning_level(db_manager):
    """طباعة ملخص مستوى التعلم"""
    stats = db_manager.get_stats()
    patterns = db_manager.get_recent_patterns(30)
    print("\n==============================")
    print("📈 AI Knowledge Progress")
    print(f"🔑 Successful keys: {stats.get('total_success', 0)}")
    print(f"❌ Failed attempts: {stats.get('total_fail', 0)}")
    print(f"🧠 Learned patterns: {len(patterns)}")
    if patterns:
        last = patterns[0]
        print("📝 Last learned key pattern:")
        for k, v in last.items():
            if k not in ("found_key", "id"):
                print(f"   {k}: {v}")
    else:
        print("No patterns learned yet.")
    print("==============================\n")

def ai_confidence_indicator(this_range, db_manager):
    """مؤشر ثقة الذكاء الاصطناعي في إيجاد المفتاح."""
    all_patterns = get_all_patterns(db_manager)
    if not all_patterns:
        return 0
    cur_start = int(this_range["start"], 16)
    cur_stop = int(this_range["stop"], 16)
    cur_size = cur_stop - cur_start
    similar = 0
    for p in all_patterns:
        try:
            s = int(p.get("range_start", "0"), 16)
            e = int(p.get("range_stop", "0"), 16)
            size = e - s
            diff = abs(size - cur_size)
            if diff < (cur_size // 4):
                similar += 1
        except:
            continue
    sr, _, _ = get_training_stats(db_manager, this_range, "AI")
    conf = min(100, int((similar * 20) + (sr * 0.7)))
    return conf

def make_run_report(report, db_manager):
    """تخزين تقرير جلسة البحث في قاعدة البيانات."""
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    db_manager.insert_report_log(report_json)
    print("\n📋 تم حفظ تقرير الجلسة في قاعدة البيانات ضمن report_logs.\n")

def search_worker(start, stop, queue, process_id, mode_name, db_path, target_address):
    """وظيفة كل عملية فرعية للبحث."""
    db_manager = DatabaseManager(db_path)
    tried = 0
    found = False
    checked = set()
    local_report = {
        "process_id": process_id,
        "mode": mode_name,
        "tries": 0,
        "found": False,
        "found_key": None,
        "found_address": None,
        "errors": [],
        "start": start,
        "stop": stop
    }
    last_update = 0
    while not found:
        try:
            all_patterns = get_all_patterns(db_manager)
            if mode_name == "AI":
                batch_size = 50000
                candidates = ai_candidate_generator(start, stop, batch_size, all_patterns)
            elif mode_name == "Genetic":
                candidates = genetic_candidates(start, stop, population=50000)
            elif mode_name == "GPU":
                batch_size = 2000000
                try:
                    import cupy as cp
                    cp.cuda.Device(0).use()
                    candidates = cp.random.randint(start, stop + 1, size=int(batch_size * 2), dtype=cp.int64)
                    scores = cp.random.uniform(0, 1, size=candidates.shape)
                    indices = cp.argsort(scores)[::-1]
                    candidates = cp.asnumpy(candidates[indices])[:batch_size].tolist()
                except Exception as e:
                    candidates = ai_candidate_generator(start, stop, batch_size, all_patterns)
            else:
                candidates = list(range(start, stop + 1))
            for priv_int in candidates:
                if priv_int in checked:
                    continue
                checked.add(priv_int)
                priv_key_hex = hex(priv_int)[2:].zfill(64)
                priv_bytes = bytes.fromhex(priv_key_hex)
                try:
                    address = privatekey_to_address(priv_bytes)
                except Exception as e:
                    continue
                if address == target_address:
                    queue.put((True, priv_key_hex, address, process_id, tried, mode_name))
                    local_report.update({
                        "found": True,
                        "found_key": priv_key_hex,
                        "found_address": address
                    })
                    found = True
                    break
                tried += 1
                if tried - last_update >= 5000:
                    queue.put((False, None, None, process_id, tried - last_update, mode_name))
                    last_update = tried
        except Exception as e:
            local_report["errors"].append(str(e))
            continue
    local_report["tries"] = tried
    tmp_report = f"proc_report_{process_id}.json"
    with open(tmp_report, "w", encoding="utf-8") as f:
        json.dump(local_report, f, indent=2, ensure_ascii=False)
    if not found:
        queue.put((False, None, None, process_id, tried, mode_name))
    db_manager.close()

def manager(start, stop, num_processes, modes, db_path, target_address):
    """إدارة توزيع البحث على العمليات واستلام النتائج."""
    manager_mp = multiprocessing.Manager()
    queue = manager_mp.Queue()
    total_tries = 0
    found = False
    step = (stop - start + 1) // num_processes
    processes = []
    session_start_time = int(time.time())
    for i in range(num_processes):
        s = start + i * step
        e = start + (i + 1) * step - 1 if i < num_processes - 1 else stop
        mode = modes[i % len(modes)]
        p = multiprocessing.Process(target=search_worker, args=(s, e, queue, i + 1, mode, db_path, target_address))
        processes.append(p)
        p.start()

    pbar = tqdm(total=stop - start + 1, desc="🔎 Adaptive Search", ncols=80)
    t0 = time.time()
    final_report = {
        "success": False,
        "target_address": target_address,
        "range": {"start": hex(start), "stop": hex(stop)},
        "process_reports": [],
        "winner_process": None,
        "winner_key": None,
        "winner_address": None,
        "winner_mode": None,
        "winner_tries": None,
        "time_spent": None,
        "errors": []
    }
    found_mode = None

    while not found and any(p.is_alive() for p in processes):
        try:
            result = queue.get(timeout=1)
            is_found, priv, addr, proc_id, delta, mode = result
            proc_report_file = f"proc_report_{proc_id}.json"
            proc_report = {}
            if os.path.exists(proc_report_file):
                with open(proc_report_file, encoding="utf-8") as f:
                    proc_report = json.load(f)
                final_report["process_reports"].append(proc_report)
                os.remove(proc_report_file)
            else:
                proc_report = {"process_id": proc_id, "mode": mode, "tries": delta, "found": is_found}
                final_report["process_reports"].append(proc_report)
            if not is_found:
                total_tries += delta
                pbar.update(delta)
            else:
                t1 = time.time()
                elapsed = t1 - t0
                print(f"\n\n🎯 تم العثور على المفتاح في العملية #{proc_id} [{mode} Mode]")
                print("Private Key (HEX):", priv[:8] + "..." + priv[-8:])  # إظهار جزء فقط للحماية
                print("Address:", addr)
                with open(FOUND_KEY_FILE, "w", encoding="utf-8") as f:
                    f.write(f"Private Key (HEX): {priv}\n")
                    f.write(f"Address: {addr}\n")
                update_molds_on_success(priv, target_address, {"start": hex(start), "stop": hex(stop)}, DatabaseManager(db_path))
                log_training(True, priv, target_address, {"start": hex(start), "stop": hex(stop)}, total_tries, elapsed, mode, DatabaseManager(db_path))
                found = True
                found_mode = mode
                final_report.update({
                    "success": True,
                    "winner_process": proc_id,
                    "winner_key": priv,
                    "winner_address": addr,
                    "winner_mode": mode,
                    "winner_tries": total_tries,
                    "time_spent": elapsed
                })
                break
        except Exception as e:
            final_report["errors"].append(str(e))
            continue

    for p in processes:
        p.terminate()
    for p in processes:
        p.join()
    pbar.close()
    if not found:
        elapsed = time.time() - t0
        print(f"\n🚫 لم يتم العثور على العنوان الهدف ضمن النطاق المحدد (تم تجربة ~{total_tries:,} مفتاح، الوقت: {elapsed:.2f} ثانية).")
        update_molds_on_failure(target_address, {"start": hex(start), "stop": hex(stop)}, DatabaseManager(db_path), total_tries)
        log_training(False, None, target_address, {"start": hex(start), "stop": hex(stop)}, total_tries, elapsed, "AI", DatabaseManager(db_path))
        final_report["time_spent"] = elapsed

    session_end_time = int(time.time())
    dbm = DatabaseManager(db_path)
    dbm.insert_search_session({
        "session_start": session_start_time,
        "session_end": session_end_time,
        "range": {"start": hex(start), "stop": hex(stop)},
        "mode": found_mode if found_mode else "None",
        "total_tries": total_tries,
        "found": found,
        "winner_key": final_report.get("winner_key"),
        "winner_address": final_report.get("winner_address")
    })
    dbm.close()
    make_run_report(final_report, DatabaseManager(db_path))

def main():
    print_logo()
    parser = argparse.ArgumentParser(description="AI Key Search and Learning Tool")
    parser.add_argument('--mode', type=str, default='scan', choices=['scan', 'train', 'export-db', 'import-db'],
                        help="وضع التشغيل")
    parser.add_argument('--db', type=str, default=DEFAULT_DB_PATH, help="مسار قاعدة البيانات SQLite")
    parser.add_argument('--target', type=str, default=DEFAULT_TARGET_ADDRESS, help="العنوان الهدف (بيتكوين)")
    parser.add_argument('--start', type=str, default=DEFAULT_START_HEX, help="مفتاح البداية بالنظام السادس عشر")
    parser.add_argument('--stop', type=str, default=DEFAULT_STOP_HEX, help="مفتاح النهاية بالنظام السادس عشر")
    parser.add_argument('--export-file', type=str, default=EXPORT_DB_FILE, help="ملف التصدير")
    parser.add_argument('--import-file', type=str, default=IMPORT_DB_FILE, help="ملف الاستيراد")
    args = parser.parse_args()

    db_path = args.db
    db_manager = DatabaseManager(db_path)
    target_address = args.target
    start_hex = args.start
    stop_hex = args.stop

    save_key_range_info(target_address, start_hex, stop_hex)

    if args.mode == 'export-db':
        print("تصدير قاعدة البيانات إلى ملف خارجي...")
        db_manager.export_db(args.export_file)
        print(f"تم تصدير البيانات إلى {args.export_file}")
    elif args.mode == 'import-db':
        print("استيراد قاعدة البيانات من ملف خارجي...")
        db_manager.import_db(args.import_file)
        print(f"تم استيراد البيانات من {args.import_file}")
    elif args.mode == 'train':
        print("تشغيل وضع التدريب (غير مفعل عمليًا في هذا الإصدار) ...")
    else:  # وضع البحث (scan)
        show_learning_level(db_manager)
        start_int = int(start_hex, 16)
        stop_int = int(stop_hex, 16)
        num_processes = os.cpu_count() or 4
        # كشف تلقائي لدعم GPU
        try:
            import cupy as cp
            modes = ["GPU"] + ["AI"] * (num_processes - 1)
        except ImportError:
            modes = ["AI"] * num_processes
        print(f"\nTarget address: {target_address}")
        print(f"Range: {hex(start_int)} -> {hex(stop_int)}")
        print(f"Processes: {num_processes}")
        print("Modes:", modes)
        ai_conf = ai_confidence_indicator({"start": hex(start_int), "stop": hex(stop_int)}, db_manager)
        print(f"\n🧠 AI Solve Confidence: {ai_conf}%\n")
        sr, at, ls = get_training_stats(db_manager, {"start": hex(start_int), "stop": hex(stop_int)}, "AI")
        print(f"📊 [AI Mode] نسبة النجاح السابقة: {sr:.2f}% | الوقت المتوقع: {at:.1f} ثانية")
        print("Searching... (Ctrl+C to stop)\n")
        manager(start_int, stop_int, num_processes, modes, db_path, target_address)
        export_all_patterns_to_file(db_manager)
    db_manager.close()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()