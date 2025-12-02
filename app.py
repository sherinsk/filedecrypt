import os
import ctypes
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 64 * 1024


# ------------------ FIX WINDOWS BLURRY TEXT ------------------
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except:
        pass


# ======================================================
#               CENTER WINDOW FUNCTION
# ======================================================
def center_window(win, width=900, height=600):
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = (sw - width) // 2
    y = (sh - height) // 2
    win.geometry(f"{width}x{height}+{x}+{y}")


# ======================================================
#              AES ENCRYPT / DECRYPT
# ======================================================
def encrypt_file(input_path, output_path, key):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(nonce)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(cipher.encrypt(chunk))
        fout.write(cipher.digest())


def decrypt_file(input_path, output_path, key):
    filesize = os.path.getsize(input_path)
    with open(input_path, "rb") as fin:
        nonce = fin.read(16)
        fin.seek(filesize - 16)
        tag = fin.read(16)
        fin.seek(16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        with open(output_path, "wb") as fout:
            while fin.tell() < filesize - 16:
                chunk = fin.read(CHUNK_SIZE)
                fout.write(cipher.decrypt(chunk))
            cipher.verify(tag)


# ======================================================
#                    MARQUEE
# ======================================================
class Marquee(Frame):
    def __init__(self, parent, width=450, text="", font=("Ubuntu", 8), speed=2, bg="white"):
        super().__init__(parent, bg=bg)
        self.speed = speed
        self.box_width = width

        self.canvas = Canvas(self, bg=bg, width=width, height=30,
                             highlightthickness=1, highlightbackground="#ccc")
        self.canvas.pack()

        self.text_id = self.canvas.create_text(0, 15, text=text, font=font, anchor="w")
        self.after(50, self.animate)

    def set_text(self, new_text):
        self.canvas.itemconfig(self.text_id, text=new_text)
        self.canvas.update()
        bbox = self.canvas.bbox(self.text_id)
        text_w = bbox[2] - bbox[0]
        start_x = (self.box_width - text_w) // 2
        self.canvas.coords(self.text_id, start_x, 15)

    def animate(self):
        x, y = self.canvas.coords(self.text_id)
        x -= self.speed
        tw = self.canvas.bbox(self.text_id)[2]
        if x < -tw:
            x = self.box_width
        self.canvas.coords(self.text_id, x, y)
        self.after(20, self.animate)


# ======================================================
#                MAIN APPLICATION UI
# ======================================================
class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        root.title("ENCRYPT/DECRYPT")
        center_window(root, 900, 600)
        root.resizable(False, False)

        style = ttk.Style()
        style.configure("TButton", font=("Ubuntu", 14), padding=10)
        style.configure("TNotebook.Tab", font=("Ubuntu", 16, "bold"))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.encrypt_tab = Frame(notebook, bg="white")
        self.decrypt_tab = Frame(notebook, bg="white")
        notebook.add(self.encrypt_tab, text="Encrypt")
        notebook.add(self.decrypt_tab, text="Decrypt")

        self.build_encrypt_tab()
        self.build_decrypt_tab()

    # --------------------- ENCRYPT TAB -----------------------
    def build_encrypt_tab(self):
        self.enc_file_path = None
        self.enc_key = None

        Label(self.encrypt_tab, text="ENCRYPT", font=("Ubuntu", 18, "bold"),
              bg="white").pack(pady=20)

        ttk.Button(self.encrypt_tab, text="Select File",
                   command=self.select_file_encrypt).pack(pady=10)

        self.enc_marquee = Marquee(self.encrypt_tab, width=450)
        self.enc_marquee.pack(pady=5)

        ttk.Button(self.encrypt_tab, text="Generate Key",
                   command=self.generate_key_encrypt).pack(pady=10)

        ttk.Button(self.encrypt_tab, text="Load Key",
                   command=self.load_key_encrypt).pack(pady=10)

        ttk.Button(self.encrypt_tab, text="Encrypt File",
                   command=self.encrypt_action).pack(pady=30)

    def select_file_encrypt(self):
        self.enc_file_path = filedialog.askopenfilename()
        if self.enc_file_path:
            self.enc_marquee.set_text(self.enc_file_path)

    def generate_key_encrypt(self):
        key = get_random_bytes(32)
        save = filedialog.asksaveasfilename(defaultextension=".key")
        if save:
            open(save, "wb").write(key)
            self.enc_key = key
            messagebox.showinfo("Success", f"Key saved at {save}")

    def load_key_encrypt(self):
        p = filedialog.askopenfilename(filetypes=[("Key", "*.key")])
        if p:
            self.enc_key = open(p, "rb").read()

    def encrypt_action(self):
        if not self.enc_file_path or not self.enc_key:
            return
        out = self.enc_file_path + ".enc"
        encrypt_file(self.enc_file_path, out, self.enc_key)
        messagebox.showinfo("Done", "File encrypted successfully.")

    # --------------------- DECRYPT TAB -----------------------
    def build_decrypt_tab(self):
        self.dec_file_path = None
        self.dec_key = None

        Label(self.decrypt_tab, text="DECRYPT", font=("Ubuntu", 18, "bold"),
              bg="white").pack(pady=20)

        ttk.Button(self.decrypt_tab, text="Select File",
                   command=self.select_file_decrypt).pack(pady=10)

        self.dec_marquee = Marquee(self.decrypt_tab, width=450)
        self.dec_marquee.pack(pady=5)

        ttk.Button(self.decrypt_tab, text="Load Key",
                   command=self.load_key_decrypt).pack(pady=20)

        ttk.Button(self.decrypt_tab, text="Decrypt File",
                   command=self.decrypt_action).pack(pady=30)

    def select_file_decrypt(self):
        self.dec_file_path = filedialog.askopenfilename(filetypes=[("Encrypted", "*.enc")])
        if self.dec_file_path:
            self.dec_marquee.set_text(self.dec_file_path)

    def load_key_decrypt(self):
        p = filedialog.askopenfilename(filetypes=[("Key", "*.key")])
        if p:
            self.dec_key = open(p, "rb").read()

    def decrypt_action(self):
        if not self.dec_file_path or not self.dec_key:
            return
        out = os.path.splitext(self.dec_file_path)[0]
        decrypt_file(self.dec_file_path, out, self.dec_key)
        messagebox.showinfo("Done", "Decrypted successfully.")


# ======================================================
#                      SPLASH SCREEN
# ======================================================
class SplashScreen:
    def __init__(self, root, on_finish):
        self.root = root
        self.on_finish = on_finish

        self.splash = Toplevel(root)
        self.splash.overrideredirect(True)
        center_window(self.splash, 900, 600)
        self.splash.configure(bg="white")

        frame = Frame(self.splash, bg="white")
        frame.pack(expand=True)

        # TITLE
        Label(frame,
              text="FILE ENCRYPT / DECRYPT",
              font=("Ubuntu", 20, "bold"),
              bg="white",
              fg="black").pack()

        # SUBTEXT
        Label(frame,
              text="By Akhilraj",
              font=("Ubuntu", 9),
              bg="white",
              fg="gray").pack(pady=10)

        self.splash.after(2000, self.close)

    def close(self):
        self.splash.destroy()
        self.on_finish()


# ======================================================
#                    START APPLICATION
# ======================================================
def start_app():
    main = Tk()
    FileEncryptorApp(main)
    main.mainloop()


if __name__ == "__main__":
    root = Tk()
    root.withdraw()

    SplashScreen(root, on_finish=start_app)

    root.mainloop()
