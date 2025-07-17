import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import threading
import base64
import speech_recognition as sr
from steg.image_steg import encode_message, decode_message, get_max_message_length
from crypto.aes import generate_key, encrypt_message, decrypt_message, save_key_info, load_key_info

class StegaChatUI:
    def __init__(self, root):
        self.root = root
        self.root.title("StegaChat - Secure Image Steganography")
        self.root.geometry("600x500")

        self.current_fernet = None
        self.current_salt = None

        self.privacy_notice_shown = False  # New flag
        self.setup_ui()

    def setup_ui(self):
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(main_frame, text="StegaChat", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))

        input_frame = tk.LabelFrame(main_frame, text="Message Input", padx=10, pady=10)
        input_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(input_frame, text="Enter your message:").pack(anchor=tk.W)
        self.text_entry = tk.Text(input_frame, height=4, width=50)
        self.text_entry.pack(fill=tk.X, pady=(5, 10))

        mic_btn = tk.Button(input_frame, text="🎤 Voice Input", command=self.start_voice_input, bg="#FF9800", fg="white")
        mic_btn.pack(anchor=tk.W, padx=5, pady=(0, 5))

        # 🆕 Status label for voice recognition state
        self.voice_status_label = tk.Label(input_frame, text="", fg="gray")
        self.voice_status_label.pack(anchor=tk.W, padx=5, pady=(0, 5))

        encrypt_frame = tk.LabelFrame(main_frame, text="Encryption", padx=10, pady=10)
        encrypt_frame.pack(fill=tk.X, pady=(0, 10))

        self.encrypt_var = tk.IntVar()
        self.encrypt_check = tk.Checkbutton(encrypt_frame, text="Encrypt message", variable=self.encrypt_var, command=self.on_encrypt_toggle)
        self.encrypt_check.pack(anchor=tk.W)

        self.password_frame = tk.Frame(encrypt_frame)
        tk.Label(self.password_frame, text="Password:").pack(side=tk.LEFT)
        self.password_entry = tk.Entry(self.password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=(5, 0))

        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.encode_button = tk.Button(button_frame, text="Encode & Save", command=self.encode_message, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.encode_button.pack(side=tk.LEFT, padx=(0, 10))

        self.decode_button = tk.Button(button_frame, text="Decode Message", command=self.decode_message, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.decode_button.pack(side=tk.LEFT)

        status_frame = tk.LabelFrame(main_frame, text="Status", padx=10, pady=10)
        status_frame.pack(fill=tk.BOTH, expand=True)

        self.status_text = tk.Text(status_frame, height=8, state=tk.DISABLED)
        self.status_text.pack(fill=tk.BOTH, expand=True)

        self.password_frame.pack_forget()

    def on_encrypt_toggle(self):
        if self.encrypt_var.get():
            self.password_frame.pack(anchor=tk.W, pady=(5, 0))
        else:
            self.password_frame.pack_forget()
            self.current_fernet = None
            self.current_salt = None

    def log_status(self, message: str):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)

    # ✅ Enhanced voice input with feedback, privacy notice, error handling
    def start_voice_input(self):
        if not self.privacy_notice_shown:
            messagebox.showinfo(
                "Privacy Notice",
                "Your voice input will be processed using Google's Speech Recognition API.\nEnsure you're connected to the internet."
            )
            self.privacy_notice_shown = True

        def recognize():
            recognizer = sr.Recognizer()

            mic_names = sr.Microphone.list_microphone_names()
            if not mic_names:
                self.log_status("No microphone detected. Please connect a microphone.")
                messagebox.showerror("Microphone Error", "No microphone detected. Please connect a microphone.")
                return

            try:
                with sr.Microphone() as source:
                    self.voice_status_label.config(text="🎙 Listening...", fg="orange")
                    self.log_status("Listening for voice input...")
                    audio = recognizer.listen(source, timeout=6)

                self.voice_status_label.config(text="⏳ Processing...", fg="blue")
                self.log_status("Processing voice input...")

                text = recognizer.recognize_google(audio)
                self.text_entry.insert(tk.END, text)
                self.log_status(f"Voice recognized: {text}")
                self.voice_status_label.config(text="✅ Done", fg="green")

            except sr.WaitTimeoutError:
                self.voice_status_label.config(text="⚠ Timeout", fg="red")
                self.log_status("Listening timed out. Please try again.")
                messagebox.showwarning("Timeout", "Listening timed out. Please try again.")

            except sr.UnknownValueError:
                self.voice_status_label.config(text="⚠ Couldn't understand", fg="red")
                self.log_status("Could not understand the audio.")
                messagebox.showwarning("Unrecognized Speech", "Could not understand the audio.")

            except sr.RequestError as e:
                self.voice_status_label.config(text="❌ API Error", fg="red")
                self.log_status(f"Speech Recognition service failed: {e}")
                messagebox.showerror("API Error", f"Speech Recognition service error: {e}")

            except Exception as e:
                self.voice_status_label.config(text="❌ Error", fg="red")
                self.log_status(f"Unexpected error: {e}")
                messagebox.showerror("Error", f"An unexpected error occurred: {e}")

        threading.Thread(target=recognize).start()

    def encode_message(self):
        try:
            message = self.text_entry.get("1.0", tk.END).strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message to encode.")
                return

            img_path = filedialog.askopenfilename(title="Select input image", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")])
            if not img_path:
                return

            try:
                max_length = get_max_message_length(img_path)
                if len(message) > max_length:
                    messagebox.showerror("Error", f"Message too long. Maximum {max_length} characters allowed for this image.")
                    return
            except Exception as e:
                messagebox.showerror("Error", f"Could not analyze image: {e}")
                return

            if self.encrypt_var.get():
                password = self.password_entry.get()
                if not password:
                    messagebox.showerror("Error", "Please enter a password for encryption.")
                    return
                try:
                    self.current_fernet, self.current_salt = generate_key(password)
                    encrypted_message = encrypt_message(self.current_fernet, message)
                    message = base64.b64encode(encrypted_message).decode('ascii')
                    self.log_status("Message encrypted successfully")
                except Exception as e:
                    messagebox.showerror("Error", f"Encryption failed: {e}")
                    return

            output_path = filedialog.asksaveasfilename(title="Save encoded image as", defaultextension=".png", filetypes=[("PNG files", ".png"), ("All files", ".*")])
            if not output_path:
                return

            success = encode_message(img_path, message, output_path)
            if success:
                if self.encrypt_var.get() and self.current_salt:
                    key_info_path = output_path + ".key"
                    save_key_info(self.current_fernet, self.current_salt, key_info_path)
                    self.log_status(f"Key info saved to: {key_info_path}")

                self.log_status(f"Message encoded successfully: {output_path}")
                messagebox.showinfo("Success", f"Message encoded and saved to:\n{output_path}")
            else:
                messagebox.showerror("Error", "Failed to encode message.")

        except Exception as e:
            self.log_status(f"Error: {e}")
            messagebox.showerror("Error", f"Encoding failed: {e}")

    def decode_message(self):
        try:
            img_path = filedialog.askopenfilename(title="Select image to decode", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")])
            if not img_path:
                return

            message = decode_message(img_path)

            try:
                decoded = base64.b64decode(message)
                is_encrypted = decoded.startswith(b'gAAAAA')
            except Exception:
                is_encrypted = False

            if is_encrypted:
                password = simpledialog.askstring("Password Required", "This message appears to be encrypted. Enter the password:")
                if not password:
                    return
                try:
                    key_info_path = img_path + ".key"
                    if os.path.exists(key_info_path):
                        salt = load_key_info(key_info_path)
                        fernet, _ = generate_key(password, salt)
                    else:
                        fernet, _ = generate_key(password)

                    encrypted_bytes = base64.b64decode(message)
                    decrypted_message = decrypt_message(fernet, encrypted_bytes)
                    message = decrypted_message
                    self.log_status("Message decrypted successfully")
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {e}")
                    return

            self.log_status(f"Decoded message: {message}")
            messagebox.showinfo("Decoded Message", message)

        except Exception as e:
            self.log_status(f"Error: {e}")
            messagebox.showerror("Error", f"Decoding failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StegaChatUI(root) 