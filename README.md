# 🔐 Tiny Password Manager

A small offline password manager I put together because sometimes writing a simple tool feels better than using a massive app. It stores everything in a single encrypted JSON file and protects it with your master password. When you run the script, it asks for your master password, unlocks the vault, and shows a menu so you can add, view, list, delete, or generate passwords right there in the terminal.

## 🖥️ How It Works When You Run It
1. You run `python password_manager.py`
2. It asks for your master password  
3. If the vault exists, it unlocks it; if not, it creates a new one  
4. You see a menu:
   - Add a password  
   - View a saved one  
   - List all services  
   - Delete an entry  
   - Generate a random password  
   - Exit  
5. Everything you do is saved back into the encrypted vault automatically

## ⚠️ Disclaimer
This is a simple personal tool, not a professional-grade security product. If your passwords get lost, corrupted, leak, or suddenly decide to disappear forever, that’s on you. Use it if you want something lightweight and offline, but don’t expect it to carry your entire digital life on its shoulders.
