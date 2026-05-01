import os
import struct

def read_key(key_path):
    key_list = []
    with open(key_path, "rb") as keyfile:
        for _ in range(0x100):
            chunk = keyfile.read(4)
            if len(chunk) != 4:
                raise ValueError(f"密钥文件长度不足: {key_path}")
            key_list.append(struct.unpack("<L", chunk)[0])
    return key_list

def decrypt_single_rld(src_path, dst_path, other_key_list, def_key_list, xor_key_val, def_xor_key_val):
    with open(src_path, "rb") as src:
        src.seek(0, os.SEEK_END)
        filesize = src.tell()
        src.seek(0, os.SEEK_SET)

        with open(dst_path, "wb") as dst:
            dst.write(src.read(0x10))
            j = ((filesize - 0x10) >> 2) & 0xFFFF
            if j > 0x3FF0:
                j = 0x3FF0

            if src_path.stem == "def":
                key_list = def_key_list
                xor_key = def_xor_key_val
            else:
                key_list = other_key_list
                xor_key = xor_key_val

            for k in range(j):
                en_temp = struct.unpack("<L", src.read(4))[0]
                temp_key = key_list[k & 0xFF] ^ xor_key
                de_temp = en_temp ^ temp_key
                dst.write(struct.pack("<L", de_temp))

            dst.write(src.read(filesize - src.tell()))

def decrypt_rld_folder(rld_dir, out_dir, key_bin, key_def_bin, xor_key, def_xor_key, log_cb, status_cb):
    try:
        status_cb("正在解密 RLD...")
        if not rld_dir.exists():
            raise FileNotFoundError(f"RLD 文件夹不存在: {rld_dir}")
        if not key_bin.exists():
            raise FileNotFoundError(f"未找到: {key_bin}")
        if not key_def_bin.exists():
            raise FileNotFoundError(f"未找到: {key_def_bin}")

        out_dir.mkdir(parents=True, exist_ok=True)
        other_key_list = read_key(key_bin)
        def_key_list = read_key(key_def_bin)

        count = 0
        for file_path in rld_dir.iterdir():
            if file_path.suffix.lower() != ".rld":
                continue
            decrypt_single_rld(
                file_path,
                out_dir / file_path.with_suffix(".bin").name,
                other_key_list,
                def_key_list,
                xor_key,
                def_xor_key,
            )
            log_cb(f"已解密: {file_path.name}")
            count += 1

        log_cb(f"RLD 解密完成，共处理 {count} 个文件")
        status_cb("RLD 解密完成")
    except Exception as exc:
        log_cb(f"解密报错: {exc}")
        status_cb("解密失败")

def encrypt_single_rld(src_path, dst_path, other_key_list, def_key_list, xor_key_val, def_xor_key_val):
    with open(src_path, "rb") as src:
        src.seek(0, os.SEEK_END)
        filesize = src.tell()
        src.seek(0, os.SEEK_SET)

        with open(dst_path, "wb") as dst:
            dst.write(src.read(0x10))
            j = ((filesize - 0x10) >> 2) & 0xFFFF
            if j > 0x3FF0:
                j = 0x3FF0

            if src_path.stem == "def":
                key_list = def_key_list
                xor_key = def_xor_key_val
            else:
                key_list = other_key_list
                xor_key = xor_key_val

            for k in range(j):
                en_temp = struct.unpack("<L", src.read(4))[0]
                temp_key = key_list[k & 0xFF] ^ xor_key
                de_temp = en_temp ^ temp_key
                dst.write(struct.pack("<L", de_temp))

            dst.write(src.read(filesize - src.tell()))

def encrypt_rld_folder(bin_dir, out_dir, key_bin, key_def_bin, xor_key, def_xor_key, log_cb, status_cb):
    try:
        status_cb("正在加密 RLD...")
        if not bin_dir.exists():
            raise FileNotFoundError(f"BIN 文件夹不存在: {bin_dir}")
        if not key_bin.exists():
            raise FileNotFoundError(f"未找到: {key_bin}")
        if not key_def_bin.exists():
            raise FileNotFoundError(f"未找到: {key_def_bin}")

        out_dir.mkdir(parents=True, exist_ok=True)
        other_key_list = read_key(key_bin)
        def_key_list = read_key(key_def_bin)

        count = 0
        for file_path in bin_dir.iterdir():
            if file_path.suffix.lower() != ".bin":
                continue
            encrypt_single_rld(
                file_path,
                out_dir / file_path.with_suffix(".rld").name,
                other_key_list,
                def_key_list,
                xor_key,
                def_xor_key,
            )
            log_cb(f"已加密: {file_path.name}")
            count += 1

        log_cb(f"RLD 加密完成，共处理 {count} 个文件")
        status_cb("RLD 加密完成")
    except Exception as exc:
        log_cb(f"加密报错: {exc}")
        status_cb("加密失败")
