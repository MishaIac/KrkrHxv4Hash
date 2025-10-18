import ctypes
import os
import sys
import tkinter as tk
from tkinter import scrolledtext, font

if getattr(sys, 'frozen', False):
    base_path = os.path.dirname(sys.executable)
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

dll_path = os.path.join(base_path, "KrkrHxv4Hash.dll")
mylib = ctypes.CDLL(dll_path)

mylib.get_filename_hash.argtypes = [ctypes.c_wchar_p]
mylib.get_filename_hash.restype = ctypes.POINTER(ctypes.c_uint8)

mylib.get_path_hash.argtypes = [ctypes.c_wchar_p]
mylib.get_path_hash.restype = ctypes.c_uint64

def str_to_utf16_ptr(s: str):
    utf16_bytes = s.encode("utf-16le") + b"\x00\x00"
    buf = ctypes.create_string_buffer(utf16_bytes)
    return ctypes.cast(buf, ctypes.c_wchar_p)

def update_hashes(event=None):
    input_textbox.edit_modified(False)
    input_text = input_textbox.get("1.0", tk.END).strip()

    output_textbox.config(state="normal")
    output_textbox.delete("1.0", tk.END)

    for line in input_text.splitlines():
        line = line.strip()
        if not line:
            output_textbox.insert(tk.END, "\n")
            continue

        try:
            ptr = str_to_utf16_ptr(line)
            if "/" in line:
                num = mylib.get_path_hash(ptr)
                hash_result = f"{num:016X}"
            else:
                arr_ptr = mylib.get_filename_hash(ptr)
                hash_result = ''.join(f"{arr_ptr[i]:02X}" for i in range(32))
            ptr = None
            arr_ptr = None
        except Exception:
            hash_result = "Error"

        output_textbox.insert(tk.END, f"{hash_result}:{line}\n")

    output_textbox.config(state="disabled")

root = tk.Tk()
root.title("KrkrHxv4HashGUI")

mono_font = font.Font(family="Consolas", size=9)

input_textbox = scrolledtext.ScrolledText(root, width=40, height=22, font=mono_font)
input_textbox.grid(row=0, column=0, padx=(8, 5), pady=8, sticky="nsew")
input_textbox.bind("<<Modified>>", update_hashes)

output_textbox = scrolledtext.ScrolledText(root, width=100, height=22, font=mono_font, state="disabled")
output_textbox.grid(row=0, column=1, padx=(5, 8), pady=8, sticky="nsew")

root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=3)
root.grid_rowconfigure(0, weight=1)

root.mainloop()
