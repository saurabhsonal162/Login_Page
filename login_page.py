import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import bcrypt
import pickle
import os

# Database Setup
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
conn.commit()

# Check if user is remembered
REMEMBER_FILE = "remember_me.pkl"

def hash_password(password):
    """Hash a password for storing."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_password, entered_password):
    """Verify a stored password with entered password."""
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password)

def register():
    """Register a new user with hashed password storage."""
    username = entry_user.get()
    password = entry_pass.get()

    if not username or not password:
        messagebox.showwarning("Error", "Fields cannot be empty!")
        return

    try:
        hashed_pw = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        messagebox.showinfo("Success", "Account Created! Please Login.")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")

def login():
    """Authenticate user and handle login process."""
    username = entry_user.get()
    password = entry_pass.get()
    
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if result and verify_password(result[0], password):
        messagebox.showinfo("Success", f"Welcome, {username}!")
        
        if remember_var.get():
            with open(REMEMBER_FILE, "wb") as f:
                pickle.dump(username, f)
        
        main_screen(username)
    else:
        messagebox.showerror("Error", "Invalid Username or Password!")

def logout():
    """Log the user out and return to login screen."""
    root.withdraw()
    os.remove(REMEMBER_FILE) if os.path.exists(REMEMBER_FILE) else None
    show_login_screen()

def show_login_screen():
    """Display the login UI."""
    global entry_user, entry_pass, remember_var

    login_win = tk.Toplevel(root)
    login_win.title("Login System")
    login_win.geometry("400x300")

    ttk.Label(login_win, text="Username:").pack(pady=5)
    entry_user = ttk.Entry(login_win)
    entry_user.pack(pady=5)

    ttk.Label(login_win, text="Password:").pack(pady=5)
    entry_pass = ttk.Entry(login_win, show="*")
    entry_pass.pack(pady=5)

    remember_var = tk.BooleanVar()
    ttk.Checkbutton(login_win, text="Remember Me", variable=remember_var).pack(pady=5)

    ttk.Button(login_win, text="Login", command=login).pack(pady=5)
    ttk.Button(login_win, text="Register", command=register).pack(pady=5)

    login_win.mainloop()

def main_screen(username):
    """Show the main application screen after login."""
    global root
    root.deiconify()
    for widget in root.winfo_children():
        widget.destroy()

    ttk.Label(root, text=f"Welcome, {username}!", font=("Arial", 16)).pack(pady=20)
    ttk.Button(root, text="Logout", command=logout).pack(pady=10)

root = tk.Tk()
root.withdraw()

# Auto-login if "Remember Me" was checked before
if os.path.exists(REMEMBER_FILE):
    with open(REMEMBER_FILE, "rb") as f:
        remembered_user = pickle.load(f)
    main_screen(remembered_user)
else:
    show_login_screen()

root.mainloop()
