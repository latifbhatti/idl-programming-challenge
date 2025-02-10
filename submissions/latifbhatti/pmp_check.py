import sys
import re

def parse_pmp_config(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        pmpcfg = [int(line.strip(), 16) & 0xFF for line in lines[:64]]
        pmpaddr = [int(line.strip(), 16) for line in lines[64:128]]
    return pmpcfg, pmpaddr

def get_pmp_region(base, a, pmpaddr_value, pmpaddr):
    if a == 1:
        if base == 0:
            prev_base = 0
        else:
            prev_base = (pmpaddr[base - 1])
        region_start, region_end = prev_base, (pmpaddr_value)
    elif a == 2:
        region_start = (pmpaddr_value)
        region_end = region_start + 3
    elif a == 3:
        n = 0
        mask = 1
        while (pmpaddr_value & mask) == mask:
            n += 1
            mask = (mask << 1) | 1
        size = 1 << (n + 2)
        region_start = (pmpaddr_value << 2) & ~(size - 1)
        region_end = region_start + size - 1
    else:
        return None
    return region_start, region_end

def check_pmp_access(pmpcfg, pmpaddr, addr, mode, operation):
    addr = int(addr, 16)
    matching_index = -1
    for i in range(0, 64, 1):
        cfg = pmpcfg[i]
        a = (cfg >> 3) & 0x3
        if a == 0:
            continue
        region = get_pmp_region(i, a, pmpaddr[i], pmpaddr)
        if not region:
            continue
        region_start, region_end = region
        if region_start <= addr <= region_end:
            matching_index = i            
            break
    cfg = pmpcfg[matching_index]
    l = (cfg >> 7) & 0x1
    r = (cfg >> 0) & 0x1
    w = (cfg >> 1) & 0x1
    x = (cfg >> 2) & 0x1
    print("value of pmpcfg = " , hex(cfg) ,"\noperation R     = " , r,"\noperation W     = " , w,"\noperation X     = " , x)
    if matching_index == -1:
        if mode in ['S', 'U']:
            return False
        else:
            return True
        
    if mode == 'M':
        if l:
            return True
    elif mode in ['S', 'U']:
        if l:
            return False
    if operation == 'R' and not r:
        return False
    if operation == 'W' and not w:
        return False
    if operation == 'X' and not x:
        return False
    return True

def validate_hex_address(addr):
    return re.match(r'^0x[0-9a-fA-F]+$', addr) is not None

def main():
    if len(sys.argv) != 5:
        print("Usage: python pmp_check.py <pmp_config_file> <physical_address> <privilege_mode> <operation>")
        sys.exit(1)
    if not validate_hex_address(sys.argv[2]):
        print("Invalid physical address format. Must be in hexadecimal with a leading '0x'.")
        sys.exit(1)
    pmpcfg, pmpaddr = parse_pmp_config(sys.argv[1])
    addr = sys.argv[2]
    mode = sys.argv[3].upper()
    operation = sys.argv[4].upper()
    if mode not in ['M', 'S', 'U'] or operation not in ['R', 'W', 'X']:
        print("Invalid privilege mode or operation.")
        sys.exit(1)
    if check_pmp_access(pmpcfg, pmpaddr, addr, mode, operation):
        print("Access allowed.")
    else:
        print("Access fault.")

if __name__ == "__main__":
    main()