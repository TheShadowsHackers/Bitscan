"""
دوال مساعدة: تحليل المفاتيح، توليد الأنماط، التعامل مع الملفات الخارجية، الذكاء الاصطناعي
"""

import os
import json
import time
import random
import hashlib
import base58
import numpy as np

try:
    from coincurve import PrivateKey
except ImportError:
    PrivateKey = None

from settings import LEARNING_LOG_FILE, ALL_PATTERNS_FILE, KEY_RANGE_INFO_FILE

def privatekey_to_address(priv_bytes):
    """
    تحويل bytes مفتاح خاص إلى عنوان بيتكوين (P2PKH).
    """
    if PrivateKey is None:
        raise ImportError("يرجى تثبيت مكتبة coincurve لاستخراج العنوان")
    pubkey = PrivateKey(priv_bytes).public_key.format(compressed=True)
    sha256 = hashlib.sha256(pubkey).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    prefixed = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    address_bytes = prefixed + checksum
    return base58.b58encode(address_bytes).decode()

def analyze_key(hex_key):
    """
    تحليل سريع لخصائص المفتاح (بادئة/لاحقة أصفار، طول، أنماط).
    """
    pattern = {}
    pattern['zeros_prefix'] = len(hex_key) - len(hex_key.lstrip("0"))
    pattern['zeros_suffix'] = len(hex_key) - len(hex_key.rstrip("0"))
    pattern['length'] = len(hex_key)
    pattern['has_dead'] = "dead" in hex_key.lower()
    pattern['has_beef'] = "beef" in hex_key.lower()
    pattern['entropy'] = len(set(hex_key))
    return pattern

def extended_analyze_key(hex_key, start_hex=None, stop_hex=None):
    """
    تحليل موسع للمفتاح يشمل إحصائيات وتقنيات إضافية.
    """
    pattern = analyze_key(hex_key)
    length = len(hex_key)
    pattern["entropy_ratio"] = pattern["entropy"] / length if length > 0 else 0.0
    if start_hex and stop_hex:
        try:
            k = int(hex_key, 16)
            s = int(start_hex, 16)
            e = int(stop_hex, 16)
            if s < e:
                rel_pos = (k - s) / (e - s)
                pattern["relative_position"] = round(rel_pos, 6)
            else:
                pattern["relative_position"] = None
        except Exception:
            pattern["relative_position"] = None
    if hex_key.startswith("0" * 4):
        pattern["prefix_type"] = "all-zero"
    elif hex_key[0].lower() in "fede":
        pattern["prefix_type"] = "high"
    else:
        pattern["prefix_type"] = "other"
    if hex_key.endswith("0" * 4):
        pattern["suffix_type"] = "all-zero"
    elif hex_key[-1].lower() in "fede":
        pattern["suffix_type"] = "high"
    else:
        pattern["suffix_type"] = "other"
    pattern["starts_with_high_hex"] = hex_key[0].lower() in "fede"
    pattern["chunk_repeats"] = sum(
        1 for i in range(0, len(hex_key)-3, 2)
        if hex_key[i:i+2] == hex_key[i+2:i+4]
    )
    try:
        bits = bin(int(hex_key, 16))[2:]
        pattern["bit_density"] = bits.count("1") / len(bits)
    except Exception:
        pattern["bit_density"] = 0.0
    reversed_hex = hex_key[::-1]
    pattern["has_reversed_words"] = any(w in reversed_hex for w in ["daed", "feeb"])
    return pattern

def append_learning_log(data, filename=LEARNING_LOG_FILE):
    """
    إضافة سجل تعلم خارجي إلى ملف JSON.
    """
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                existing = json.load(f)
        else:
            existing = []
    except Exception:
        existing = []
    existing.append(data)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

def export_all_patterns_to_file(db_manager, filename=ALL_PATTERNS_FILE):
    """
    تصدير جميع أنماط التعلم إلى ملف خارجي.
    """
    patterns = db_manager.get_recent_patterns(limit=1000)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2, ensure_ascii=False)

def save_key_range_info(target_address, start_key, stop_key, filename=KEY_RANGE_INFO_FILE):
    """
    حفظ معلومات النطاق والعنوان الهدف في ملف خارجي.
    """
    info = {
        "target_address": target_address,
        "start_key": start_key,
        "stop_key": stop_key
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)

def ai_suspicious_score(priv_int, all_patterns):
    """
    حساب درجة الشك لمفتاح معين بناءً على الأنماط السابقة.
    """
    hex_key = hex(priv_int)[2:].zfill(64)
    score = 0.0
    for pat in all_patterns:
        if pat.get("zeros_prefix", 0) >= 5 and hex_key.startswith("0" * pat["zeros_prefix"]):
            score += 2.0
        if pat.get("zeros_suffix", 0) >= 4 and hex_key.endswith("0" * pat["zeros_suffix"]):
            score += 1.5
        if pat.get("has_dead", False) and "dead" in hex_key.lower():
            score += 1.5
        if pat.get("has_beef", False) and "beef" in hex_key.lower():
            score += 1.5
    if hex_key.startswith("1"*5) or hex_key.endswith("f"*4):
        score += 1.2
    if "dead" in hex_key.lower():
        score += 1.0
    mean = int("0000000000000000000000000000000000000000000000000000000006000000", 16)
    stdev = int("400000", 16)
    score += float(np.exp(-((priv_int - mean) ** 2) / (2 * stdev ** 2)))
    score += random.uniform(0, 0.1)
    return float(score)

def generate_key_from_pattern(pattern, start, stop):
    """
    توليد مفتاح جديد بناءً على نمط معين وحدود النطاق.
    """
    zeros_prefix = pattern.get('zeros_prefix', 0)
    zeros_suffix = pattern.get('zeros_suffix', 0)
    length = 64
    core_length = length - zeros_prefix - zeros_suffix
    if core_length < 1:
        return None
    for _ in range(3):
        core = ''.join(random.choices('0123456789abcdef', k=core_length))
        key = '0' * zeros_prefix + core + '0' * zeros_suffix
        if len(key) != 64:
            continue
        key_int = int(key, 16)
        if key_int < start or key_int > stop:
            continue
        return key
    return None

def ai_candidate_generator(start, stop, batch_size, all_patterns):
    """
    توليد دفعة مرشحين باستخدام الأنماط والتعلم.
    """
    privs = []
    for pat in all_patterns:
        for _ in range(2):
            k = generate_key_from_pattern(pat, start, stop)
            if k:
                privs.append((1000, int(k, 16)))
    random_candidates = []
    for _ in range(batch_size * 2):
        candidate = random.randint(start, stop)
        score = ai_suspicious_score(candidate, all_patterns)
        random_candidates.append((score, candidate))
    random_candidates.sort(reverse=True)
    privs.extend(random_candidates[:batch_size])
    seen = set()
    out = []
    for s, c in privs:
        if c not in seen:
            seen.add(c)
            out.append(c)
            if len(out) >= batch_size:
                break
    return out

def genetic_candidates(start, stop, population=100):
    """
    توليد مرشحين باستخدام أسلوب جينيتيك (عشوائي).
    """
    return [random.randint(start, stop) for _ in range(population)]