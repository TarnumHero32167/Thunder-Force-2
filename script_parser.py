import os
import re
import sys
import json
import struct
import bisect
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXPORT_DIR = os.path.join(SCRIPT_DIR, 'export')

INSTR_FUNC_MAP = {}
INSTR_COLOR_MAP = {}
MAP_FILE = os.path.join(SCRIPT_DIR, 'evt_instr_map.json')
if os.path.exists(MAP_FILE):
    with open(MAP_FILE, 'r', encoding='utf-8') as f:
        raw_map = json.load(f)
    for k, v in raw_map.items():
        if isinstance(v, dict):
            INSTR_FUNC_MAP[k] = v.get('func', '')
            if v.get('color'):
                INSTR_COLOR_MAP[k] = v['color']
        else:
            INSTR_FUNC_MAP[k] = v


# ── 公共工具 ──────────────────────────────────────────

def xor_decrypt(data, key=0xFF):
    return bytes([b ^ key for b in data])


def read_u32_le(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def clean_text(text):
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)


def decode_big5(data):
    try:
        text = data.decode('big5', errors='replace')
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
        text = text.replace('\r', '').replace('\n', '')
        return text
    except Exception:
        return ''


def get_instr_prefix(hex_str):
    parts = hex_str.split(' ')
    if len(parts) >= 5:
        b0 = parts[0]
        b4 = parts[4]
        return '{}000000{}'.format(b0, b4)
    return ''


# ── 样式 ──────────────────────────────────────────────

header_font = Font(name='微软雅黑', bold=True, color='FFFFFF', size=11)
header_fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
header_align = Alignment(horizontal='center', vertical='center', wrap_text=True)
cell_align = Alignment(vertical='top', wrap_text=True)
thin_border = Border(
    left=Side(style='thin'),
    right=Side(style='thin'),
    top=Side(style='thin'),
    bottom=Side(style='thin')
)
skip_fill = PatternFill(start_color='F2F2F2', end_color='F2F2F2', fill_type='solid')
seg_fill = PatternFill(start_color='D9E2F3', end_color='D9E2F3', fill_type='solid')
last_fill = PatternFill(start_color='FFF2CC', end_color='FFF2CC', fill_type='solid')


def apply_header(ws, headers):
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_align
        cell.border = thin_border


def set_col_widths(ws, widths):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[chr(64 + i)].width = w


# ── EVT 解析 ──────────────────────────────────────────

def parse_evt(decrypted):
    entry_count = decrypted[10]
    menu_start = 274

    all_entries = []
    for i in range(entry_count):
        off = menu_start + i * 16
        if off + 16 > len(decrypted):
            break
        seg_id = read_u32_le(decrypted, off)
        count = read_u32_le(decrypted, off + 4)
        all_entries.append({'offset': off, 'id': seg_id, 'count': count})

    all_seg_ids = sorted(set(e['id'] for e in all_entries if e['id'] != 0))

    valid_entries = []
    seen_ids = set()
    for entry in all_entries:
        if entry['count'] == 0:
            continue
        if entry['id'] in seen_ids:
            continue
        seen_ids.add(entry['id'])
        valid_entries.append(entry)

    all_instructions = []
    for seg in valid_entries:
        seg_id = seg['id']
        count = seg['count']

        if seg_id == 0x0442:
            continue

        menu_offset = seg_id
        entries = []
        for i in range(count):
            entry_off = menu_offset + i * 4
            if entry_off + 4 > len(decrypted):
                break
            inst_off = read_u32_le(decrypted, entry_off)
            entries.append(inst_off)

        idx_in_sorted = bisect.bisect_left(all_seg_ids, seg_id)
        if idx_in_sorted + 1 < len(all_seg_ids):
            next_seg_start = all_seg_ids[idx_in_sorted + 1]
        else:
            next_seg_start = len(decrypted)

        for i, inst_off in enumerate(entries):
            if i + 1 < len(entries):
                end_off = entries[i + 1]
            else:
                end_off = next_seg_start

            if inst_off >= len(decrypted):
                inst_hex = '[超出文件范围]'
                inst_len = 0
            else:
                actual_end = min(end_off, len(decrypted))
                inst_bytes = decrypted[inst_off:actual_end]
                inst_hex = ' '.join('{:02X}'.format(b) for b in inst_bytes)
                inst_len = len(inst_bytes)

            all_instructions.append({
                'seg_id': '0x{:04X}'.format(seg_id),
                'seg_offset': '0x{:04X}'.format(menu_offset),
                'inst_index': i,
                'inst_offset': '0x{:04X}'.format(inst_off),
                'end_offset': '0x{:04X}'.format(end_off),
                'length': inst_len,
                'hex': inst_hex,
            })

    return all_entries, valid_entries, all_instructions


def save_evt_excel(all_entries, valid_entries, all_instructions, output_path):
    wb = Workbook()

    ws1 = wb.active
    ws1.title = '一级菜单'

    valid_ids = {e['id'] for e in valid_entries}
    headers1 = ['序号', '一级指令段ID', '一级菜单Offset', '指令数量', '是否跳过', '备注']
    apply_header(ws1, headers1)

    for row_idx, entry in enumerate(all_entries, 1):
        seg_id = entry['id']
        count = entry['count']
        is_skipped = (count == 0) or (seg_id == 0x0442) or (seg_id not in valid_ids)
        note = ''
        if seg_id == 0x0442:
            note = '第一段，默认跳过'
        elif count == 0:
            note = '无指令(count=0)'
        elif seg_id not in valid_ids:
            note = '重复段ID'

        values = [
            row_idx,
            '0x{:04X}'.format(seg_id),
            '0x{:04X}'.format(entry['offset']),
            count,
            '是' if is_skipped else '否',
            note,
        ]
        for col, v in enumerate(values, 1):
            cell = ws1.cell(row=row_idx + 1, column=col, value=v)
            cell.alignment = header_align
            cell.border = thin_border
            if is_skipped:
                cell.fill = skip_fill

    set_col_widths(ws1, [6, 18, 18, 10, 10, 20])
    ws1.freeze_panes = 'A2'

    ws2 = wb.create_sheet('指令明细')
    headers2 = ['序号', '所属一级段ID', '二级菜单Offset', '指令序号',
                '指令Offset', '结束Offset', '长度(字节)', '指令内容(HEX)',
                '具体指令', '指令作用']
    apply_header(ws2, headers2)

    current_seg = None
    for row_idx, inst in enumerate(all_instructions, 1):
        is_new_seg = inst['seg_id'] != current_seg
        current_seg = inst['seg_id']

        is_last = False
        if row_idx < len(all_instructions):
            next_inst = all_instructions[row_idx]
            if next_inst['seg_id'] != current_seg:
                is_last = True
        else:
            is_last = True

        prefix = get_instr_prefix(inst['hex']) if inst['hex'] != '[超出文件范围]' else ''
        func = INSTR_FUNC_MAP.get(prefix, '') if prefix else ''

        values = [
            row_idx,
            inst['seg_id'] if is_new_seg else '',
            inst['seg_offset'] if is_new_seg else '',
            inst['inst_index'],
            inst['inst_offset'],
            inst['end_offset'],
            inst['length'],
            inst['hex'],
            prefix,
            func,
        ]
        for col, v in enumerate(values, 1):
            cell = ws2.cell(row=row_idx + 1, column=col, value=v)
            cell.alignment = cell_align
            cell.border = thin_border
            if is_new_seg:
                cell.fill = seg_fill
            elif is_last:
                cell.fill = last_fill

    set_col_widths(ws2, [6, 16, 18, 10, 14, 14, 12, 80, 14, 16])
    ws2.freeze_panes = 'A2'

    wb.save(output_path)


# ── MSG 解析 ──────────────────────────────────────────

def parse_msg(decrypted):
    entry_count = decrypted[10]
    menu_start = 274

    all_entries = []
    for i in range(entry_count):
        off = menu_start + i * 16
        if off + 16 > len(decrypted):
            break
        seg_id = read_u32_le(decrypted, off)
        count = read_u32_le(decrypted, off + 4)
        all_entries.append({'offset': off, 'id': seg_id, 'count': count})

    all_seg_ids = sorted(set(e['id'] for e in all_entries if e['id'] != 0))

    valid_entries = []
    seen_ids = set()
    for entry in all_entries:
        if entry['count'] == 0:
            continue
        if entry['id'] in seen_ids:
            continue
        seen_ids.add(entry['id'])
        valid_entries.append(entry)

    all_instructions = []
    for seg in valid_entries:
        seg_id = seg['id']
        count = seg['count']
        menu_offset = seg_id

        raw_entries = []
        for i in range(count + 1):
            entry_off = menu_offset + i * 4
            if entry_off + 4 > len(decrypted):
                break
            inst_off = read_u32_le(decrypted, entry_off)
            raw_entries.append(inst_off)

        valid_raw = [e for e in raw_entries if e != 0]
        if not valid_raw:
            continue

        idx_in_sorted = bisect.bisect_left(all_seg_ids, seg_id)
        if idx_in_sorted + 1 < len(all_seg_ids):
            next_seg_start = all_seg_ids[idx_in_sorted + 1]
        else:
            next_seg_start = len(decrypted)

        for i, inst_off in enumerate(valid_raw):
            if i + 1 < len(valid_raw):
                end_off = valid_raw[i + 1]
            else:
                end_off = next_seg_start

            if inst_off >= len(decrypted):
                inst_hex = '[超出文件范围]'
                inst_text = ''
                inst_len = 0
            else:
                actual_end = min(end_off, len(decrypted))
                inst_bytes = decrypted[inst_off:actual_end]
                inst_hex = ' '.join('{:02X}'.format(b) for b in inst_bytes)
                inst_len = len(inst_bytes)
                inst_text = clean_text(inst_bytes.decode('big5', errors='replace'))

            all_instructions.append({
                'seg_id': '0x{:04X}'.format(seg_id),
                'seg_offset': '0x{:04X}'.format(menu_offset),
                'inst_index': i,
                'inst_offset': '0x{:04X}'.format(inst_off),
                'end_offset': '0x{:04X}'.format(end_off),
                'length': inst_len,
                'hex': inst_hex,
                'text': inst_text,
            })

    return all_entries, valid_entries, all_instructions


def save_msg_excel(all_entries, valid_entries, all_instructions, output_path):
    wb = Workbook()

    ws1 = wb.active
    ws1.title = '一级菜单'

    valid_ids = {e['id'] for e in valid_entries}
    headers1 = ['序号', '一级指令段ID', '一级菜单Offset', '指令数量', '是否跳过', '备注']
    apply_header(ws1, headers1)

    for row_idx, entry in enumerate(all_entries, 1):
        seg_id = entry['id']
        count = entry['count']
        is_skipped = (count == 0) or (seg_id == 0) or (seg_id not in valid_ids)
        note = ''
        if count == 0:
            note = '无指令(count=0)'
        elif seg_id == 0:
            note = '空段ID'
        elif seg_id not in valid_ids:
            note = '重复段ID'

        values = [
            row_idx,
            '0x{:04X}'.format(seg_id),
            '0x{:04X}'.format(entry['offset']),
            count,
            '是' if is_skipped else '否',
            note,
        ]
        for col, v in enumerate(values, 1):
            cell = ws1.cell(row=row_idx + 1, column=col, value=v)
            cell.alignment = header_align
            cell.border = thin_border
            if is_skipped:
                cell.fill = skip_fill

    set_col_widths(ws1, [6, 18, 18, 10, 10, 20])
    ws1.freeze_panes = 'A2'

    ws2 = wb.create_sheet('指令明细')
    headers2 = ['序号', '所属一级段ID', '二级菜单Offset', '指令序号',
                '指令Offset', '结束Offset', '长度(字节)', '指令内容(HEX)', '文字内容(Big5)']
    apply_header(ws2, headers2)

    current_seg = None
    for row_idx, inst in enumerate(all_instructions, 1):
        is_new_seg = inst['seg_id'] != current_seg
        current_seg = inst['seg_id']

        is_last = False
        if row_idx < len(all_instructions):
            next_inst = all_instructions[row_idx]
            if next_inst['seg_id'] != current_seg:
                is_last = True
        else:
            is_last = True

        values = [
            row_idx,
            inst['seg_id'] if is_new_seg else '',
            inst['seg_offset'] if is_new_seg else '',
            inst['inst_index'],
            inst['inst_offset'],
            inst['end_offset'],
            inst['length'],
            inst['hex'],
            inst['text'],
        ]
        for col, v in enumerate(values, 1):
            cell = ws2.cell(row=row_idx + 1, column=col, value=v)
            cell.alignment = cell_align
            cell.border = thin_border
            if is_new_seg:
                cell.fill = seg_fill
            elif is_last:
                cell.fill = last_fill

    set_col_widths(ws2, [6, 16, 18, 10, 14, 14, 12, 60, 60])
    ws2.freeze_panes = 'A2'

    wb.save(output_path)


# ── DAT 解析 ──────────────────────────────────────────

def parse_dat(decrypted):
    entry_count = decrypted[10]
    menu_start = 274

    all_entries = []
    for i in range(entry_count):
        off = menu_start + i * 16
        if off + 16 > len(decrypted):
            break
        seg_id = read_u32_le(decrypted, off)
        count = read_u32_le(decrypted, off + 4)
        record_size = read_u32_le(decrypted, off + 8)
        total_size = read_u32_le(decrypted, off + 12)
        all_entries.append({
            'index': i,
            'offset': off,
            'seg_id': seg_id,
            'count': count,
            'record_size': record_size,
            'total_size': total_size,
        })

    all_seg_ids = sorted(set(e['seg_id'] for e in all_entries if e['seg_id'] != 0))

    valid_entries = []
    seen_ids = set()
    for entry in all_entries:
        if entry['count'] == 0:
            continue
        if entry['seg_id'] == 0:
            continue
        if entry['seg_id'] in seen_ids:
            continue
        seen_ids.add(entry['seg_id'])
        valid_entries.append(entry)

    all_records = []
    for entry in valid_entries:
        seg_id = entry['seg_id']
        count = entry['count']
        record_size = entry['record_size']

        if record_size == 0:
            if entry['total_size'] > 0 and count > 0:
                record_size = entry['total_size'] // count
            else:
                record_size = 0

        if count == 1 and record_size == 0:
            record_size = entry['total_size']

        idx_in_sorted = bisect.bisect_left(all_seg_ids, seg_id)
        if idx_in_sorted + 1 < len(all_seg_ids):
            next_seg_start = all_seg_ids[idx_in_sorted + 1]
        else:
            next_seg_start = len(decrypted)

        for i in range(count):
            rec_off = seg_id + i * record_size
            if i + 1 < count:
                end_off = seg_id + (i + 1) * record_size
            else:
                end_off = min(seg_id + entry['total_size'], next_seg_start) if entry['total_size'] > 0 else next_seg_start

            if rec_off >= len(decrypted):
                rec_hex = '[超出文件范围]'
                rec_len = 0
                rec_big5 = ''
                rec_group = ''
                rec_num = ''
                rec_name = ''
                rec_coord = ''
                rec_bytes = b''
            else:
                actual_end = min(end_off, len(decrypted))
                rec_bytes = decrypted[rec_off:actual_end]
                rec_hex = ' '.join('{:02X}'.format(b) for b in rec_bytes)
                if len(rec_bytes) >= 4 and rec_bytes[3] == 0x00 and not all(b == 0 for b in rec_bytes) and (rec_bytes[0] != 0 or rec_bytes[1] != 0 or rec_bytes[2] != 0):
                    rec_group = '{:02X}'.format(rec_bytes[0])
                    rec_num = '{:02X}{:02X}'.format(rec_bytes[1], rec_bytes[2])
                    is_char_data = True
                else:
                    rec_group = ''
                    rec_num = ''
                    is_char_data = False
                if is_char_data and len(rec_bytes) >= 12:
                    name_bytes = rec_bytes[4:12].rstrip(b'\x00')
                    rec_name = name_bytes.decode('big5', errors='replace')
                elif not is_char_data:
                    if all(b == 0 for b in rec_bytes):
                        rec_group = None
                        rec_num = None
                        rec_name = None
                        rec_coord = None
                    else:
                        name_raw = rec_bytes.rstrip(b'\x00').decode('big5', errors='replace')
                        rec_name = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', name_raw)
                else:
                    rec_name = ''
                if is_char_data and len(rec_bytes) >= 28:
                    rec_x = struct.unpack_from('<H', rec_bytes, 24)[0]
                    rec_y = struct.unpack_from('<H', rec_bytes, 26)[0]
                    rec_coord = '{}, {}'.format(rec_x, rec_y)
                else:
                    rec_coord = ''
                rec_len = len(rec_bytes)
                rec_big5 = decode_big5(rec_bytes)

            if all(b == 0 for b in rec_bytes):
                continue

            all_records.append({
                'seg_index': entry['index'],
                'seg_id': '0x{:04X}'.format(seg_id),
                'seg_offset': '0x{:04X}'.format(seg_id),
                'record_index': i,
                'record_offset': '0x{:04X}'.format(rec_off),
                'end_offset': '0x{:04X}'.format(end_off),
                'length': rec_len,
                'hex': rec_hex,
                'big5': rec_big5,
                'group': rec_group,
                'num': rec_num,
                'name': rec_name,
                'coord': rec_coord,
            })

    return all_entries, valid_entries, all_records


def save_dat_excel(all_entries, valid_entries, all_records, output_path):
    wb = Workbook()

    ws1 = wb.active
    ws1.title = '一级菜单'

    valid_ids = {e['seg_id'] for e in valid_entries}
    headers1 = ['序号', '数据段ID', '菜单Offset', '记录数', '记录大小(字节)', '总大小(字节)', '是否跳过', '备注']
    apply_header(ws1, headers1)

    for row_idx, entry in enumerate(all_entries, 1):
        seg_id = entry['seg_id']
        count = entry['count']
        is_skipped = (count == 0) or (seg_id == 0) or (seg_id not in valid_ids)
        note = ''
        if count == 0:
            note = '无记录(count=0)'
        elif seg_id == 0:
            note = '段ID为0'
        elif seg_id not in valid_ids:
            note = '重复段ID'

        values = [
            row_idx,
            '0x{:04X}'.format(seg_id),
            '0x{:04X}'.format(entry['offset']),
            count,
            entry['record_size'],
            entry['total_size'],
            '是' if is_skipped else '否',
            note,
        ]
        for col, v in enumerate(values, 1):
            cell = ws1.cell(row=row_idx + 1, column=col, value=v)
            cell.alignment = header_align
            cell.border = thin_border
            if is_skipped:
                cell.fill = skip_fill

    set_col_widths(ws1, [6, 16, 16, 10, 16, 16, 10, 20])
    ws1.freeze_panes = 'A2'

    ws2 = wb.create_sheet('数据明细')
    headers2 = ['序号', '所属数据段ID', '数据段Offset', '记录序号',
                '记录Offset', '结束Offset', '长度(字节)',
                '记录内容(HEX)', '分组', '编号', '姓名', '坐标(X,Y)']
    apply_header(ws2, headers2)

    current_seg = None
    for row_idx, rec in enumerate(all_records, 1):
        is_new_seg = rec['seg_id'] != current_seg
        current_seg = rec['seg_id']

        is_last = False
        if row_idx < len(all_records):
            next_rec = all_records[row_idx]
            if next_rec['seg_id'] != current_seg:
                is_last = True
        else:
            is_last = True

        values = [
            row_idx - 1,
            rec['seg_id'] if is_new_seg else '',
            rec['seg_offset'] if is_new_seg else '',
            rec['record_index'],
            rec['record_offset'],
            rec['end_offset'],
            rec['length'],
            rec['hex'],
            rec['group'],
            rec['num'],
            rec['name'],
            rec['coord'],
        ]
        for col, v in enumerate(values, 1):
            cell = ws2.cell(row=row_idx + 1, column=col, value=v)
            cell.alignment = cell_align
            cell.border = thin_border
            if is_new_seg:
                cell.fill = seg_fill
            elif is_last:
                cell.fill = last_fill

    set_col_widths(ws2, [6, 16, 16, 10, 14, 14, 12, 80, 8, 10, 12, 12])
    ws2.freeze_panes = 'A2'

    wb.save(output_path)


# ── 主程序 ─────────────────────────────────────────────

def process_file(file_path, ext):
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    with open(file_path, 'rb') as f:
        raw = f.read()
    decrypted = xor_decrypt(raw)

    if len(decrypted) < 3 or decrypted[0:3] != b'SE3':
        print('  [{}] {} -> 文件格式不正确（非SE3格式），跳过'.format(ext.upper(), os.path.basename(file_path)))
        return None, None, None

    if ext == '.evt':
        all_entries, valid_entries, all_instructions = parse_evt(decrypted)
        output_name = '{}_指令解析.xlsx'.format(base_name)
        save_evt_excel(all_entries, valid_entries, all_instructions, os.path.join(EXPORT_DIR, output_name))
        return all_entries, valid_entries, all_instructions
    elif ext == '.msg':
        all_entries, valid_entries, all_instructions = parse_msg(decrypted)
        output_name = '{}_对话解析.xlsx'.format(base_name)
        save_msg_excel(all_entries, valid_entries, all_instructions, os.path.join(EXPORT_DIR, output_name))
        return all_entries, valid_entries, all_instructions
    elif ext == '.dat':
        all_entries, valid_entries, all_records = parse_dat(decrypted)
        output_name = '{}_数据解析.xlsx'.format(base_name)
        save_dat_excel(all_entries, valid_entries, all_records, os.path.join(EXPORT_DIR, output_name))
        return all_entries, valid_entries, all_records
    return None, None, None


def get_stage_name(evt_entries):
    if not evt_entries:
        return ''
    for entry in evt_entries:
        if entry.get('id') == 0x0442:
            continue
        if entry.get('count', 0) > 0:
            return '0x{:04X}'.format(entry['id'])
    return ''


def save_mix_excel(stage_name, evt_data, msg_data, dat_data, output_path):
    wb = Workbook()
    ws = wb.active
    ws.title = '整合数据'
    headers = ['二级菜单Offset', '指令序号', '指令内容(HEX)', '具体指令', '指令作用', '指令内容']
    apply_header(ws, headers)
    set_col_widths(ws, [18, 10, 40, 14, 16, 30])
    ws.freeze_panes = 'A2'

    msg_lookup = []
    if msg_data and msg_data[2]:
        seg_map = {}
        for mi in msg_data[2]:
            so = mi['seg_offset']
            if so not in seg_map:
                seg_map[so] = []
            seg_map[so].append(mi)
        msg_lookup = [seg_map[k] for k in sorted(seg_map.keys())]

    dat_group_names = {}
    if dat_data and dat_data[2]:
        for rec in dat_data[2]:
            g = rec.get('group', '')
            n = rec.get('name', '')
            if g and n:
                dat_group_names.setdefault(g, []).append(n)

    current_seg = None
    row_idx = 0
    if evt_data and evt_data[2]:
        for inst in evt_data[2]:
            row_idx += 1
            is_new_seg = inst['seg_offset'] != current_seg
            current_seg = inst['seg_offset']
            prefix = get_instr_prefix(inst['hex']) if inst['hex'] != '[超出文件范围]' else ''
            func = INSTR_FUNC_MAP.get(prefix, '') if prefix else ''
            content = ''
            if inst['hex'] != '[超出文件范围]':
                hex_bytes = inst['hex'].split(' ')
                if prefix == '1400000014':
                    if len(hex_bytes) >= 12:
                        seg_idx = int(hex_bytes[10], 16)
                        dlg_idx = int(hex_bytes[11], 16)
                        if seg_idx < len(msg_lookup) and dlg_idx < len(msg_lookup[seg_idx]):
                            content = '"{}"'.format(msg_lookup[seg_idx][dlg_idx].get('text', ''))
                elif prefix == '0E0000000E':
                    if len(hex_bytes) >= 17:
                        jump_val = struct.unpack_from('<I', bytes([int(h, 16) for h in hex_bytes[13:17]]), 0)[0]
                        content = '跳转至{}指令'.format(jump_val)
                elif prefix == '0C0000000C':
                    if len(hex_bytes) > 5:
                        name_bytes = []
                        for h in hex_bytes[5:]:
                            b = int(h, 16)
                            if b == 0:
                                break
                            name_bytes.append(b)
                        if name_bytes:
                            content = clean_text(bytes(name_bytes).decode('big5', errors='replace'))
                elif prefix == '0100000001':
                    if len(hex_bytes) > 5:
                        grp = '{:02X}'.format(int(hex_bytes[5], 16))
                        if grp in dat_group_names:
                            content = '、'.join(dat_group_names[grp])
                elif prefix == '1000000010':
                    if len(hex_bytes) >= 12:
                        jump_val = int(hex_bytes[11], 16)
                        content = '跳转至{}指令'.format(jump_val)
                elif prefix == '1E0000001E':
                    if len(hex_bytes) > 5:
                        name_bytes = []
                        for h in hex_bytes[5:]:
                            b = int(h, 16)
                            if b == 0:
                                break
                            name_bytes.append(b)
                        if name_bytes:
                            content = clean_text(bytes(name_bytes).decode('big5', errors='replace'))
            values = [
                inst['seg_offset'] if is_new_seg else '',
                inst['inst_index'],
                inst['hex'],
                prefix,
                func,
                content,
            ]
            row_fill = None
            if prefix and prefix in INSTR_COLOR_MAP:
                row_fill = PatternFill(start_color=INSTR_COLOR_MAP[prefix],
                                       end_color=INSTR_COLOR_MAP[prefix],
                                       fill_type='solid')
            for col, v in enumerate(values, 1):
                if isinstance(v, str):
                    v = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', v)
                cell = ws.cell(row=row_idx + 1, column=col, value=v)
                cell.alignment = cell_align
                cell.border = thin_border
                if row_fill:
                    cell.fill = row_fill

    wb.save(output_path)


def main():
    os.chdir(SCRIPT_DIR)
    print('=' * 50)
    print('  致命武力2脚本批量解析工具 (EVT / MSG / DAT)')
    print('=' * 50)
    print()

    if len(sys.argv) >= 2:
        folder = sys.argv[1].strip().strip('"')
    else:
        folder = input('请输入脚本文件夹路径: ').strip().strip('"')
    if not folder:
        print('未输入路径，程序退出。')
        return
    if not os.path.isdir(folder):
        print('错误: 文件夹不存在 - {}'.format(folder))
        return

    if not os.path.exists(EXPORT_DIR):
        os.makedirs(EXPORT_DIR)

    files = []
    for f in sorted(os.listdir(folder)):
        ext = os.path.splitext(f)[1].lower()
        if ext in ('.evt', '.msg', '.dat'):
            files.append((os.path.join(folder, f), ext))

    if not files:
        print('文件夹中没有 .evt / .msg / .dat 文件。')
        return

    print('找到 {} 个文件:'.format(len(files)))
    for fp, ext in files:
        print('  {} ({})'.format(os.path.basename(fp), ext))
    print()

    parsed = {}
    for fp, ext in files:
        name = os.path.basename(fp)
        try:
            data = process_file(fp, ext)
            if data[0] is not None:
                if ext == '.evt':
                    count = len(data[2])
                    parsed.setdefault(name, {})['.evt'] = data
                elif ext == '.msg':
                    count = len(data[2])
                    parsed.setdefault(name, {})['.msg'] = data
                elif ext == '.dat':
                    count = len(data[2])
                    parsed.setdefault(name, {})['.dat'] = data
                label = {'.evt': '指令', '.msg': '对话', '.dat': '记录'}[ext]
                print('  [{}] {} -> {} 条{}'.format(ext.upper(), name, count, label))
        except Exception as e:
            print('  [{}] {} -> 错误: {}'.format(ext.upper(), name, e))

    MIX_DIR = os.path.join(SCRIPT_DIR, 'mix')
    if not os.path.exists(MIX_DIR):
        os.makedirs(MIX_DIR)

    stage_groups = {}
    for fname, types in parsed.items():
        for ftype, data in types.items():
            base = re.sub(r'^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_)+', '', os.path.splitext(fname)[0])
            stage_groups.setdefault(base, {})[ftype] = data

    for stage_name, types in stage_groups.items():
        evt_data = types.get('.evt', (None, None, None))
        msg_data = types.get('.msg', (None, None, None))
        dat_data = types.get('.dat', (None, None, None))
        mix_name = '{}_整合表.xlsx'.format(stage_name)
        save_mix_excel(stage_name, evt_data, msg_data, dat_data, os.path.join(MIX_DIR, mix_name))
        print('  [MIX] {} -> {}'.format(stage_name, mix_name))

    print()
    print('完成! 所有 Excel 文件已保存到:')
    print('  export 文件夹: {}'.format(EXPORT_DIR))
    print('  mix 文件夹:   {}'.format(MIX_DIR))
    print()
    try:
        input('按回车键退出...')
    except EOFError:
        pass


if __name__ == '__main__':
    main()
