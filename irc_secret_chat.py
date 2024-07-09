import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import base64
import uuid
import os

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "adminpass"

# In-memory database for users
users = {}
KEY_LIMIT = 20

class IRCChatGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("IRC Secret Chat")
        self.geometry("500x400")  # Adjusted main window size

        self.main_frame = tk.Frame(self)
        self.main_frame.pack(padx=20, pady=20)

        join_chat_button = tk.Button(self.main_frame, text="Join Chat", command=self.join_chat_popup)
        join_chat_button.pack(padx=10, pady=10, fill=tk.X)

        register_button = tk.Button(self.main_frame, text="Register", command=self.register_popup)
        register_button.pack(padx=10, pady=10, fill=tk.X)

        admin_login_button = tk.Button(self.main_frame, text="Admin Login", command=self.admin_login_popup)
        admin_login_button.pack(padx=10, pady=10, fill=tk.X)

        start_server_button = tk.Button(self.main_frame, text="Start Server", command=self.toggle_server)
        start_server_button.pack(padx=10, pady=10, fill=tk.X)

        # Simulated database of valid keys
        self.valid_keys = {}  # This will store valid keys after registration

        # Initialize channel_var as an instance variable
        self.channel_var = tk.StringVar(self)
        self.channel_var.set("general_chat")  # Default channel selection

        # Server state flag
        self.server_running = False

    def join_chat_popup(self):
        join_chat_window = tk.Toplevel(self)
        join_chat_window.title("Join Chat")
        join_chat_window.geometry("300x250")  # Adjusted join chat window size
        join_chat_window.attributes('-topmost', True)

        # Username entry
        username_label = tk.Label(join_chat_window, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.E)
        self.username_entry = tk.Entry(join_chat_window)
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)

        # Nickname entry
        nickname_label = tk.Label(join_chat_window, text="Nickname:")
        nickname_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.E)
        self.nickname_entry = tk.Entry(join_chat_window)
        self.nickname_entry.grid(row=1, column=1, padx=10, pady=5)

        # Channel selection
        channel_label = tk.Label(join_chat_window, text="Channel:")
        channel_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.E)
        channel_option_menu = ttk.OptionMenu(join_chat_window, self.channel_var, "general_chat", "general_chat", "hot_chat")
        channel_option_menu.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

        # Join button
        join_button = tk.Button(join_chat_window, text="Join", command=self.authenticate_and_join)
        join_button.grid(row=3, columnspan=2, padx=10, pady=10)

    def authenticate_and_join(self):
        username = self.username_entry.get()
        nickname = self.nickname_entry.get()
        channel = self.channel_var.get()

        if username in users:
            self.join_chat(username, nickname, channel)
        else:
            messagebox.showerror("Authentication Failed", "Invalid username.")

    def join_chat(self, username, nickname, channel):
        self.client_panel(username, nickname, channel)

    def client_panel(self, username, nickname, channel):
        client_panel = tk.Toplevel(self)
        client_panel.title(f"Chat Room - {channel}")
        client_panel.geometry("500x300")  # Adjusted client panel size
        client_panel.attributes('-topmost', True)

        chat_display = scrolledtext.ScrolledText(client_panel, wrap=tk.WORD, width=40, height=15)
        chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        message_entry = tk.Entry(client_panel, width=40)
        message_entry.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        send_button = tk.Button(client_panel, text="Send", command=lambda: self.send_message(chat_display, message_entry, nickname))
        send_button.pack(padx=10, pady=10)

        file_button = tk.Button(client_panel, text="Send File", command=lambda: self.send_file(channel))
        file_button.pack(padx=10, pady=10)

    def send_message(self, chat_display, message_entry, nickname):
        message = message_entry.get()
        if message:
            chat_display.insert(tk.END, f"{nickname}: {message}\n")
            message_entry.delete(0, tk.END)

    def send_file(self, channel):
        file_path = filedialog.askopenfilename()
        if file_path:
            # Placeholder for file sending logic
            print(f"Sending file: {file_path}")

    def admin_login_popup(self):
        login_window = tk.Toplevel(self)
        login_window.title("Admin Login")
        login_window.geometry("300x150")
        login_window.attributes('-topmost', True)

        username_label = tk.Label(login_window, text="Username:")
        username_label.pack(padx=10, pady=5)
        username_entry = tk.Entry(login_window)
        username_entry.pack(padx=10, pady=5)

        password_label = tk.Label(login_window, text="Password:")
        password_label.pack(padx=10, pady=5)
        password_entry = tk.Entry(login_window, show='*')
        password_entry.pack(padx=10, pady=5)

        login_button = tk.Button(login_window, text="Login", command=lambda: self.admin_login(username_entry.get(), password_entry.get(), login_window))
        login_button.pack(padx=10, pady=10)

    def admin_login(self, username, password, login_window):
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            login_window.destroy()
            self.admin_panel()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def admin_panel(self):
        admin_panel = tk.Toplevel(self)
        admin_panel.title("Admin Panel")
        admin_panel.geometry("600x400")
        admin_panel.attributes('-topmost', True)

        # Display active users in a TreeView
        user_tree = ttk.Treeview(admin_panel, columns=("Nickname", "Channel"), show="headings")
        user_tree.heading("Nickname", text="Nickname")
        user_tree.heading("Channel", text="Channel")
        user_tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Populate active users
        for username, info in users.items():
            user_tree.insert("", "end", values=(info['nickname'], info['channel']))

        # Action buttons under each username
        for child in user_tree.get_children():
            username = user_tree.item(child)['values'][0]
            block_button = tk.Button(admin_panel, text="Block", command=lambda u=username: self.block_user(u))
            block_button.pack()

            remove_button = tk.Button(admin_panel, text="Remove", command=lambda u=username: self.remove_user(u))
            remove_button.pack()

            mute_button = tk.Button(admin_panel, text="Mute", command=lambda u=username: self.mute_user(u))
            mute_button.pack()

            unmute_button = tk.Button(admin_panel, text="Unmute", command=lambda u=username: self.unmute_user(u))
            unmute_button.pack()

    def block_user(self, username):
        # Placeholder for blocking user logic
        print(f"Blocking user: {username}")

    def remove_user(self, username):
        # Placeholder for removing user logic
        print(f"Removing user: {username}")

    def mute_user(self, username):
        # Placeholder for muting user logic
        print(f"Muting user: {username}")

    def unmute_user(self, username):
        # Placeholder for unmuting user logic
        print(f"Unmuting user: {username}")

    def toggle_server(self):
        if not self.server_running:
            self.start_server()
        else:
            self.stop_server()

    def start_server(self):
        # Placeholder for actual server start logic
        print("Server started")
        self.server_running = True

    def stop_server(self):
        # Placeholder for actual server stop logic
        print("Server stopped")
        self.server_running = False

    def register_popup(self):
        register_window = tk.Toplevel(self)
        register_window.title("Register")
        register_window.geometry("300x250")
        register_window.attributes('-topmost', True)

        username_label = tk.Label(register_window, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.E)
        username_entry = tk.Entry(register_window)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        nickname_label = tk.Label(register_window, text="Nickname:")
        nickname_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.E)
        nickname_entry = tk.Entry(register_window)
        nickname_entry.grid(row=1, column=1, padx=10, pady=5)

        channel_label = tk.Label(register_window, text="Channel:")
        channel_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.E)
        channel_option_menu = ttk.OptionMenu(register_window, self.channel_var, "general_chat", "general_chat", "hot_chat")
        channel_option_menu.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

        register_button = tk.Button(register_window, text="Register", command=lambda: self.register(username_entry.get(), nickname_entry.get(), self.channel_var.get(), register_window))
        register_button.grid(row=3, columnspan=2, padx=10, pady=10)

    def register(self, username, nickname, channel, register_window):
        if len(users) >= KEY_LIMIT:
            messagebox.showwarning("Registration Limit", f"Maximum {KEY_LIMIT} users already registered.")
            return

        user_id = str(uuid.uuid4())
        key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

        users[username] = {'nickname': nickname, 'channel': channel, 'key': key}

        self.valid_keys[username] = key  # Store valid keys for authentication

        self.show_key_info(username, nickname, channel, key)

        register_window.destroy()

    def show_key_info(self, username, nickname, channel, key):
        key_window = tk.Toplevel(self)
        key_window.title("Generated Key Info")
        key_window.geometry("300x200")
        key_window.attributes('-topmost', True)

        tk.Label(key_window, text=f"Username: {username}").pack(padx=10, pady=5)
        tk.Label(key_window, text=f"Nickname: {nickname}").pack(padx=10, pady=5)
        tk.Label(key_window, text=f"Channel: {channel}").pack(padx=10, pady=5)
        tk.Label(key_window, text="Generated Key:").pack(padx=10, pady=5)

        key_entry = tk.Entry(key_window, width=30)
        key_entry.insert(tk.END, key)
        key_entry.pack(padx=10, pady=5)

        copy_key_button = tk.Button(key_window, text="Copy Key", command=lambda: self.copy_to_clipboard(key))
        copy_key_button.pack(padx=10, pady=5)

        copy_all_button = tk.Button(key_window, text="Copy All Info", command=lambda: self.copy_all_info(username, nickname, channel, key))
        copy_all_button.pack(padx=10, pady=5)

    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def copy_all_info(self, username, nickname, channel, key):
        all_info = f"Username: {username}\nNickname: {nickname}\nChannel: {channel}\nGenerated Key: {key}"
        self.clipboard_clear()
        self.clipboard_append(all_info)

if __name__ == "__main__":
    app = IRCChatGUI()
    app.mainloop()
