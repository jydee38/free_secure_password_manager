import os
import uuid
import hashlib
import tkinter as tk
from tkinter import messagebox, ttk, Menu, filedialog
import pyperclip
import random
import string
import json
from cryptography.fernet import Fernet
import base64
from datetime import datetime
import csv

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("1200x900")
        self.setup_style()
        
        # Configuration de la sécurité
        self.data_file = "passwords.vault"
        self.key_file = "master.key"
        self.master_code = None
        self.master_password = None
        self.cipher = None
        
        # Configuration de la langue
        self.language = "FR"  # Par défaut en français
        self.texts = self.load_language_texts()
        
        # Initialisation
        self.initialize_security()
        
        # Vérifier si c'est le premier lancement
        if not os.path.exists(self.data_file):
            self.show_language_selection()
        else:
            self.show_auth_window()
    
    def load_language_texts(self):
        """Charge les textes selon la langue sélectionnée"""
        # Dictionnaire de textes en français
        fr_texts = {
            "app_title": "Gestionnaire de Mots de Passe Sécurisé",
            "auth_title": "Authentification Requise",
            "code_label": "Votre code personnel d'accès :",
            "password_label": "Votre mot de passe d'accès :",
            "show": "👁",
            "unlock_btn": "Déverrouiller",
            "initial_setup_btn": "Première configuration (cliquez ici après avoir renseigné/choisi un mot passe et un code personnel | Veuillez bien mémoriser ce mot de passe et ce code)",
            "setup_success": "Configuration initiale terminée !",
            "auth_error": "Code ou mot de passe incorrect",
            "main_title": "Gestionnaire de Mots de Passe",
            "tab_records": "Enregistrements",
            "tab_add": "Ajouter un enregistrement",
            "tab_generator": "Générateur de mots de passe",
            "search_label": "Rechercher :",
            "service_col": "Service/Site",
            "username_col": "Nom d'utilisateur",
            "password_col": "Mot de passe",
            "show_btn": "Afficher Mot de Passe",
            "copy_btn": "Copier Mot de Passe ",
            "edit_btn": "Éditer",
            "import_csv_btn": "Importer CSV",
            "export_csv_btn": "Exporter CSV",
            "delete_btn": "Supprimer",
            "service_label": "Service/Site :",
            "username_label": "Nom d'utilisateur :",
            "password_label": "Mot de passe :",
            "paste_pwd_btn": "Coller MDP",
            "hide_btn": "Masquer",
            "add_btn": "Ajouter à la liste",
            "updt_btn": "Mettre à jour l'enregistrement ",
            "length_label": "Longueur totale :",
            "digits_label": "Nombre de chiffres :",
            "special_label": "Caractères spéciaux :",
            "exclude_label": "Exclure ces caractères :",
            "generated_label": "Mot de passe généré :",
            "strength_label": "Force :",
            "generate_btn": "Générer",
            "copied": "Mot de passe copié !",
            "warning_generate": "Générez d'abord un mot de passe",
            "delete_confirm": "Êtes-vous sûr de vouloir supprimer le mot de passe pour {}?",
            "delete_success": "Mot de passe supprimé",
            "select_warning": "Veuillez sélectionner une entrée",
            "all_fields": "Veuillez remplir tous les champs",
            "add_success": "Enregistrement ajouté avec succès !",
            "error": "Erreur",
            "success": "Succès",
            "warning": "Avertissement",
            "strength_verystrong": "Très fort",
            "strength_strong": "Fort",
            "strength_medium": "Moyen",
            "strength_weak": "Faible",
            "language_selection": "Sélection de la langue",
            "select_language": "Choisissez votre langue :",
            "french": "Français",
            "english": "Anglais",
            "continue": "Continuer",
            "initial_setup": "Configuration Initiale",
            "import_error_columns": "Le fichier CSV doit contenir les colonnes: service, username, password",
            "import_success": "Importation terminée:\nOK : {} \nKO : {}",
            "json_invalid": "Format JSON invalide",
            "export_success": "Exportation terminée avec succès!",
            "file_not_supported": "Format de fichier non supporté",
            "import_error": "Échec de l'importation: {}",
            "export_error": "Échec de l'exportation: {}",
            "entry_not_found": "Entrée introuvable",
            "service_exists": "Ce service existe déjà",
            "record_updated": "Enregistrement mis à jour",
            "password_not_found": "Mot de passe introuvable",
            "length_too_small": "La longueur est trop petite pour les critères",
            "invalid_values": "Veuillez entrer des valeurs valides",
            "cancel": "Annuler",
            "close": "Fermer",
            "password_for": "Mot de passe pour {}:"
        }
        
        # Dictionnaire de textes en anglais
        en_texts = {
            "app_title": "Secure Password Manager",
            "auth_title": "Authentication Required",
            "code_label": "Your personal access code:",
            "password_label": "Your access password:",
            "show": "👁",
            "unlock_btn": "Unlock",
            "initial_setup_btn": "Initial setup (click here after entering/choosing a password and a personal code | Please memorize this password and code)",
            "setup_success": "Initial setup completed!",
            "auth_error": "Incorrect code or password",
            "main_title": "Password Manager",
            "tab_records": "Records",
            "tab_add": "Add Record",
            "tab_generator": "Password Generator",
            "search_label": "Search:",
            "service_col": "Service/Site",
            "username_col": "Username",
            "password_col": "Password",
            "show_btn": "Show Password",
            "copy_btn": "Copy Password",
            "edit_btn": "Edit",
            "import_csv_btn": "Import CSV",
            "export_csv_btn": "Export CSV",
            "delete_btn": "Delete",
            "service_label": "Service/Site:",
            "username_label": "Username:",
            "password_label": "Password:",
            "paste_pwd_btn": "Paste PWD",
            "hide_btn": "Hide",
            "add_btn": "Add to list",
            "updt_btn": "Update record ",
            "length_label": "Total length:",
            "digits_label": "Number of digits:",
            "special_label": "Special characters:",
            "exclude_label": "Exclude these characters:",
            "generated_label": "Generated password:",
            "strength_label": "Strength:",
            "generate_btn": "Generate",
            "copied": "Password copied!",
            "warning_generate": "Generate a password first",
            "delete_confirm": "Are you sure you want to delete the password for {}?",
            "delete_success": "Password deleted",
            "select_warning": "Please select an entry",
            "all_fields": "Please fill in all fields",
            "add_success": "Record added successfully!",
            "error": "Error",
            "success": "Success",
            "warning": "Warning",
            "strength_verystrong": "Very strong",
            "strength_strong": "Strong",
            "strength_medium": "Medium",
            "strength_weak": "Weak",
            "language_selection": "Language Selection",
            "select_language": "Choose your language:",
            "french": "French",
            "english": "English",
            "continue": "Continue",
            "initial_setup": "Initial Setup",
            "import_error_columns": "CSV file must contain columns: service, username, password",
            "import_success": "Import completed:\nOK: {} \nSkipped: {}",
            "json_invalid": "Invalid JSON format",
            "export_success": "Export completed successfully!",
            "file_not_supported": "File format not supported",
            "import_error": "Import failed: {}",
            "export_error": "Export failed: {}",
            "entry_not_found": "Entry not found",
            "service_exists": "This service already exists",
            "record_updated": "Record updated",
            "password_not_found": "Password not found",
            "length_too_small": "The length is too small for the criteria",
            "invalid_values": "Please enter valid values",
            "cancel": "Cancel",
            "close": "Close",
            "password_for": "Password for {}:"
        }
        
        if self.language == "FR":
            return fr_texts
        else:
            return en_texts
    
    def show_language_selection(self):
        """Affiche la fenêtre de sélection de langue"""
        self.clear_window()
        
        # Les textes de cette partie sont en français et anglais directement
        main_frame = ttk.Frame(self.root)
        main_frame.pack(pady=50, padx=50, fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Sélection de la langue / Language Selection", 
                  font=self.font_title, foreground=self.text_color).pack(pady=20)
        
        ttk.Label(main_frame, text="Choisissez votre langue / Choose your language:", 
                  font=self.font_subtitle, foreground=self.text_color).pack(pady=10)
        
        # Variable pour stocker la sélection
        self.lang_var = tk.StringVar(value="FR")
        
        # Options de langue
        lang_frame = ttk.Frame(main_frame)
        lang_frame.pack(pady=20)
        
        ttk.Radiobutton(lang_frame, text="Français", variable=self.lang_var, 
                        value="FR").pack(anchor=tk.W, pady=5)
        ttk.Radiobutton(lang_frame, text="English", variable=self.lang_var, 
                        value="EN").pack(anchor=tk.W, pady=5)
        
        # Bouton continuer
        ttk.Button(main_frame, text="Continuer / Continue", style='Primary.TButton',
                   command=self.apply_language).pack(pady=20)
    
    def apply_language(self):
        """Applique la langue sélectionnée et continue"""
        self.language = self.lang_var.get()
        self.texts = self.load_language_texts()
        
        # Mettre à jour le titre de l'application
        self.root.title(self.texts["app_title"])
        
        # Passer à la fenêtre d'authentification
        self.show_auth_window()
    
    def create_context_menu(self, widget):
        """Crée un menu contextuel pour copier/coller"""
        menu = Menu(self.root, tearoff=0)
        menu.add_command(label=self.texts["copy_btn"], command=lambda: self.copy_to_clipboard(widget))
        menu.add_command(label=self.texts["paste_pwd_btn"], command=lambda: self.paste_from_clipboard(widget))
        widget.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))

    def copy_to_clipboard(self, widget):
        """Copie le texte dans le presse-papiers"""
        if widget.winfo_class() == 'Entry':
            text = widget.get()
        elif widget.winfo_class() == 'TEntry':
            text = widget.get()
        else:
            return
        
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo(self.texts["success"], self.texts["copied"])

    def paste_from_clipboard(self, widget):
        """Colle le texte depuis le presse-papiers"""
        try:
            text = self.root.clipboard_get()
            if widget.winfo_class() == 'Entry' or widget.winfo_class() == 'TEntry':
                widget.delete(0, tk.END)
                widget.insert(0, text)
        except tk.TclError:
            pass
            
    def paste_generated_password(self, widget):
        """Colle le mot de passe généré depuis l'onglet générateur"""
        try:
            password = self.result_entry.get()
            if password:
                widget.delete(0, tk.END)
                widget.insert(0, password)
            else:
                messagebox.showwarning(self.texts["warning"], self.texts["warning_generate"])
        except Exception as e:
            messagebox.showerror(self.texts["error"], f"Impossible de récupérer le mot de passe généré: {str(e)}")

    def setup_style(self):
        """Configure le style visuel"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Couleurs
        self.bg_color = "#2c3e50"
        self.primary_color = "#2980b9"
        self.secondary_color = "#3498db"
        self.accent_color = "#e74c3c"
        self.text_color = "#ecf0f1"
        
        # Polices
        self.font_title = ("Segoe UI", 16, "bold")
        self.font_subtitle = ("Segoe UI", 12)
        self.font_normal = ("Segoe UI", 10)
        
        # Configurer le style des widgets
        self.root.configure(bg=self.bg_color)
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=self.font_normal)
        self.style.configure('TButton', font=self.font_normal, padding=5)
        self.style.configure('Primary.TButton', foreground='white', background=self.primary_color)
        self.style.configure('Secondary.TButton', foreground='white', background=self.secondary_color)
        self.style.configure('Accent.TButton', foreground='white', background=self.accent_color)
        self.style.configure('TEntry', font=self.font_normal, padding=5)
        self.style.configure('TCombobox', font=self.font_normal, padding=5)
        self.style.map('TButton', background=[('active', self.secondary_color)])

    def clear_window(self):
        """Efface les widgets de la fenêtre principale"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def initialize_security(self):
        """Initialise le système de chiffrement"""
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)

        with open(self.key_file, "rb") as f:
            key = f.read()
        self.cipher = Fernet(key)

    def combine_credentials(self, code, password):
        """Combine code et mot de passe pour créer la clé maîtresse"""
        return hashlib.sha256(f"{code}:{password}".encode()).hexdigest()

    def show_auth_window(self):
        """Affiche la fenêtre d'authentification"""
        self.clear_window()

        main_frame = ttk.Frame(self.root)
        main_frame.pack(pady=50, padx=50, fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=self.texts["auth_title"], font=self.font_title).pack(pady=20)
        
        # Frame pour les entrées
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(pady=20)
        
        # Code personnel
        ttk.Label(input_frame, text=self.texts["code_label"], foreground=self.text_color).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.code_entry = ttk.Entry(input_frame, width=10)
        self.code_entry.grid(row=0, column=1, padx=5, pady=5)

        # Mot de passe
        ttk.Label(input_frame, text=self.texts["password_label"], foreground=self.text_color).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(input_frame, width=15, show="•")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Bouton afficher/masquer
        def toggle_password():
            if self.password_entry['show'] == '':
                self.password_entry.config(show='•')
            else:
                self.password_entry.config(show='')

        ttk.Button(input_frame, text=self.texts["show"], width=2, command=toggle_password).grid(row=1, column=2, padx=5)

        # Boutons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        if os.path.exists(self.data_file):
            ttk.Button(btn_frame, text=self.texts["unlock_btn"], style='Primary.TButton', 
                      command=self.authenticate).pack(side=tk.LEFT, padx=10)

        # Première utilisation
        if not os.path.exists(self.data_file):
            ttk.Button(btn_frame, text=self.texts["initial_setup_btn"], style='Secondary.TButton',
                      command=self.initial_setup).pack(side=tk.LEFT, padx=35)

    def initial_setup(self):
        """Configuration initiale des identifiants maîtres"""
        code = self.code_entry.get()
        password = self.password_entry.get()
        
        if not code or not password:
            messagebox.showerror(self.texts["error"], self.texts["all_fields"])
            return
            
        self.master_code = code
        self.master_password = password
        
        # Création d'un fichier vide avec la langue choisie
        data = {"_language": self.language}
        self._save_data(data)
        messagebox.showinfo(self.texts["success"], self.texts["setup_success"])
        self.authenticate()

    def authenticate(self):
        """Authentifie l'utilisateur"""
        code = self.code_entry.get()
        password = self.password_entry.get()

        if not os.path.exists(self.data_file):
            messagebox.showerror(self.texts["error"], "Veuillez d'abord configurer les identifiants maîtres")
            return

        master_hash = self.combine_credentials(code, password)
        stored_hash = self._get_stored_master_hash()

        if master_hash == stored_hash:
            self.master_code = code
            self.master_password = password
            
            # Récupérer la langue enregistrée
            data = self._load_data()
            if "_language" in data:
                self.language = data["_language"]
                self.texts = self.load_language_texts()
            
            self.show_main_window()
        else:
            messagebox.showerror(self.texts["error"], self.texts["auth_error"])

    def _get_stored_master_hash(self):
        """Récupère le hash maître stocké"""
        try:
            data = self._load_data()
            return data.get("_master_hash", "")
        except:
            return ""

    def _load_data(self):
        """Charge et déchiffre les données"""
        if not os.path.exists(self.data_file):
            return {}

        with open(self.data_file, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

    def _save_data(self, data):
        """Chiffre et sauvegarde les données"""
        if self.master_code and self.master_password:
            data["_master_hash"] = self.combine_credentials(self.master_code, self.master_password)
        
        # Sauvegarder la langue
        data["_language"] = self.language
        
        json_data = json.dumps(data).encode()
        encrypted_data = self.cipher.encrypt(json_data)

        with open(self.data_file, "wb") as f:
            f.write(encrypted_data)

    def show_main_window(self):
        """Affiche l'interface principale"""
        self.clear_window()

        # Menu principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(main_frame, text=self.texts["main_title"], font=self.font_title, foreground=self.text_color).pack(pady=10)

        # Notebook (onglets)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # Onglet 1: Voir les enregistrements
        view_frame = ttk.Frame(notebook)
        self.setup_view_tab(view_frame)
        notebook.add(view_frame, text=self.texts["tab_records"])

        # Onglet 2: Ajouter un enregistrement
        add_frame = ttk.Frame(notebook)
        self.setup_add_tab(add_frame)
        notebook.add(add_frame, text=self.texts["tab_add"])

        # Onglet 3: Générer un mot de passe
        gen_frame = ttk.Frame(notebook)
        self.setup_generate_tab(gen_frame)
        notebook.add(gen_frame, text=self.texts["tab_generator"])

    def setup_view_tab(self, frame):
        """Configure l'onglet de visualisation"""
        # Barre de recherche
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=tk.X, pady=5)

        ttk.Label(search_frame, text=self.texts["search_label"], foreground=self.text_color).pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_entry.bind("<KeyRelease>", self.search_passwords)
        self.create_context_menu(self.search_entry)

        # Treeview pour afficher les mots de passe
        columns = ("service", "username", "password")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("service", text=self.texts["service_col"])
        self.tree.heading("username", text=self.texts["username_col"])
        self.tree.heading("password", text=self.texts["password_col"])

        self.tree.column("service", width=200)
        self.tree.column("username", width=150)
        self.tree.column("password", width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)

        # Boutons d'action
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text=self.texts["show_btn"], style='Secondary.TButton',
                  command=self.show_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=self.texts["copy_btn"], style='Secondary.TButton',
                  command=self.copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=self.texts["edit_btn"], style='Secondary.TButton',
                  command=self.edit_password).pack(side=tk.LEFT, padx=5)
        
        # Nouveaux boutons d'import/export
        ttk.Button(btn_frame, text=self.texts["import_csv_btn"], style='Secondary.TButton',
                  command=lambda: self.import_passwords('csv')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=self.texts["export_csv_btn"], style='Secondary.TButton',
                  command=lambda: self.export_passwords('csv')).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text=self.texts["delete_btn"], style='Accent.TButton',
                  command=self.delete_password).pack(side=tk.RIGHT, padx=5)

        # Charger les données
        self.load_passwords()
    
    def import_passwords(self, file_type):
        """Importe des mots de passe depuis un fichier"""
        file_path = filedialog.askopenfilename(
            title=f"Sélectionner un fichier {file_type.upper()} à importer",
            filetypes=[(f"Fichiers {file_type.upper()}", f"*.{file_type}"), ("Tous les fichiers", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            if file_type == 'csv':
                self.import_from_csv(file_path)
            elif file_type == 'json':
                self.import_from_json(file_path)
            else:
                messagebox.showerror(self.texts["error"], self.texts["file_not_supported"])
        except Exception as e:
            messagebox.showerror(self.texts["error"], self.texts["import_error"].format(str(e)))

    def import_from_csv(self, file_path):
        """Importe les mots de passe depuis un fichier CSV"""
        data = self._load_data()
        imported = 0
        skipped = 0
        
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if 'service' not in row or 'username' not in row or 'password' not in row:
                    messagebox.showerror(self.texts["error"], self.texts["import_error_columns"])
                    return
                
                service = row['service']
                if service not in data:
                    data[service] = {
                        "username": row['username'],
                        "password": row['password']
                    }
                    imported += 1
                else:
                    skipped += 1
        
        self._save_data(data)
        self.load_passwords()
        messagebox.showinfo(self.texts["success"], self.texts["import_success"].format(imported, skipped))

    def import_from_json(self, file_path):
        """Importe les mots de passe depuis un fichier JSON"""
        data = self._load_data()
        imported = 0
        skipped = 0
        
        with open(file_path, mode='r', encoding='utf-8') as file:
            imported_data = json.load(file)
            
            if isinstance(imported_data, dict):
                for service, entry in imported_data.items():
                    if service.startswith('_'):
                        continue
                        
                    if service not in data:
                        data[service] = {
                            "username": entry.get("username", ""),
                            "password": entry.get("password", "")
                        }
                        imported += 1
                    else:
                        skipped += 1
            else:
                messagebox.showerror(self.texts["error"], self.texts["json_invalid"])
                return
        
        self._save_data(data)
        self.load_passwords()
        messagebox.showinfo(self.texts["success"], self.texts["import_success"].format(imported, skipped))

    def export_passwords(self, file_type):
        """Exporte les mots de passe vers un fichier"""
        file_path = filedialog.asksaveasfilename(
            title="Enregistrer sous",
            defaultextension=f".{file_type}",
            filetypes=[(f"Fichiers {file_type.upper()}", f"*.{file_type}")]
        )
        
        if not file_path:
            return
        
        try:
            data = self._load_data()
            export_data = {k: v for k, v in data.items() if not k.startswith('_')}
            
            if file_type == 'csv':
                self.export_to_csv(file_path, export_data)
            elif file_type == 'json':
                self.export_to_json(file_path, export_data)
            
            messagebox.showinfo(self.texts["success"], self.texts["export_success"])
        except Exception as e:
            messagebox.showerror(self.texts["error"], self.texts["export_error"].format(str(e)))

    def export_to_csv(self, file_path, data):
        """Exporte les mots de passe vers un fichier CSV"""
        with open(file_path, mode='w', encoding='utf-8', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['service', 'username', 'password'])
            
            for service, entry in data.items():
                writer.writerow([
                    service,
                    entry.get('username', ''),
                    entry.get('password', '')
                ])

    def export_to_json(self, file_path, data):
        """Exporte les mots de passe vers un fichier JSON"""
        with open(file_path, mode='w', encoding='utf-8') as file:
            json.dump(data, file, indent=4, ensure_ascii=False)

    def edit_password(self):
        """Édite l'entrée sélectionnée"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning(self.texts["warning"], self.texts["select_warning"])
            return
        
        # Correction: Récupérer uniquement le nom du service (première valeur)
        item = self.tree.item(selected)
        service = item['values'][0]  # Prend le premier élément (service)
        
        data = self._load_data()
        
        if service not in data:
            messagebox.showerror(self.texts["error"], self.texts["entry_not_found"])
            return
            
        # Créer la fenêtre d'édition
        dialog = tk.Toplevel(self.root)
        dialog.title("Éditer l'enregistrement")
        dialog.geometry("400x300")
        dialog.configure(bg=self.bg_color)
        
        # Récupérer les données existantes
        entry_data = data[service]
        current_username = entry_data["username"]
        current_password = entry_data["password"]
        
        # Frame principale
        main_frame = ttk.Frame(dialog)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        main_frame.configure(style='TFrame')
        
        # Service
        ttk.Label(main_frame, text=self.texts["service_label"], foreground=self.text_color).pack(anchor="w")
        service_entry = ttk.Entry(main_frame)
        service_entry.pack(fill=tk.X)
        service_entry.insert(0, service)
        self.create_context_menu(service_entry)
        
        # Nom d'utilisateur
        ttk.Label(main_frame, text=self.texts["username_label"], foreground=self.text_color).pack(anchor="w", pady=(10,0))
        username_entry = ttk.Entry(main_frame)
        username_entry.pack(fill=tk.X)
        username_entry.insert(0, current_username)
        self.create_context_menu(username_entry)
        
        # Mot de passe
        ttk.Label(main_frame, text=self.texts["password_label"], foreground=self.text_color).pack(anchor="w", pady=(10,0))
        pwd_frame = ttk.Frame(main_frame)
        pwd_frame.pack(fill=tk.X)
        
        pwd_entry = ttk.Entry(pwd_frame, show="")
        pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        pwd_entry.insert(0, current_password)
        self.create_context_menu(pwd_entry)
        
        # Bouton coller mot de passe généré
        ttk.Button(pwd_frame, text=self.texts["paste_pwd_btn"], 
                  command=lambda: self.paste_generated_password(pwd_entry)).pack(side=tk.LEFT, padx=5)

        # Boutons de la fenêtre
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text=self.texts["updt_btn"], style='Primary.TButton',
                  command=lambda: self.save_edited_password(
                      service, service_entry.get(), 
                      username_entry.get(), pwd_entry.get(), dialog)
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text=self.texts["cancel"], 
                  command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def save_edited_password(self, old_service, new_service, username, password, dialog):
        """Sauvegarde les modifications apportées à un mot de passe"""
        if not new_service or not username or not password:
            messagebox.showerror(self.texts["error"], self.texts["all_fields"])
            return
        
        data = self._load_data()
        
        # Si le service a changé, supprimer l'ancienne entrée
        if old_service != new_service:
            if new_service in data:
                messagebox.showerror(self.texts["error"], self.texts["service_exists"])
                return
            del data[old_service]
        
        # Mettre à jour les données
        data[new_service] = {
            "username": username,
            "password": password,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        
        self._save_data(data)
        self.load_passwords()
        dialog.destroy()
        messagebox.showinfo(self.texts["success"], self.texts["record_updated"])

    def search_passwords(self, event=None):
        """Filtre les mots de passe en fonction de la recherche"""
        query = self.search_entry.get().lower()

        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            # Convertir les valeurs en chaînes pour la recherche
            service = str(values).lower()
            username = str(values[1]).lower()
            
            if query in service or query in username:
                self.tree.item(item, tags=('match',))
                self.tree.selection_set(item)
            else:
                self.tree.item(item, tags=('nomatch',))

        self.tree.tag_configure('match', background='')
        self.tree.tag_configure('nomatch', background='#95a5a6')

    def load_passwords(self):
        """Charge les mots de passe dans le Treeview"""
        data = self._load_data()
        
        # Effacer les entrées existantes
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Ajouter les entrées (en excluant le hash maître et autres métadonnées)
        for service, details in data.items():
            if not service.startswith('_'):
                self.tree.insert("", "end", values=(service, details["username"], "••••••••"))

    def show_password(self):
       """Affiche le mot de passe sélectionné et permet de le copier"""
       selected = self.tree.focus()
       if not selected:
           messagebox.showwarning(self.texts["warning"], self.texts["select_warning"])
           return
       
       # Correction: Récupérer uniquement le nom du service (première valeur)
       item = self.tree.item(selected)
       service = item['values'][0]
       
       data = self._load_data()
       
       if service in data:
            password = data[service]["password"]
            # Afficher le mot de passe dans une nouvelle fenêtre
            dialog = tk.Toplevel(self.root)
            dialog.title(f"{self.texts['password_for'].format(service)}")
            dialog.geometry("800x200")
            dialog.configure(bg=self.bg_color)
            dialog.resizable(False, False)
            
            ttk.Label(dialog, text=self.texts["password_for"].format(service), font=self.font_subtitle, foreground=self.text_color).pack(pady=10)
            pwd_entry = ttk.Entry(dialog, font=("Courier", 12), justify='center')
            pwd_entry.pack(pady=5)
            pwd_entry.insert(0, password)
            pwd_entry.configure(state='readonly')
            self.create_context_menu(pwd_entry)

            def copy_to_clipboard():
               pyperclip.copy(password)
               messagebox.showinfo(self.texts["success"], self.texts["copied"])
            
               ttk.Button(dialog, text=self.texts["copy_btn"], style='Secondary.TButton', command=copy_to_clipboard).pack(pady=10)
               ttk.Button(dialog, text=self.texts["close"], style='Accent.TButton', command=dialog.destroy).pack()
       else:
            messagebox.showerror(self.texts["error"], self.texts["password_not_found"])

    def copy_password(self):
        """Copie le mot de passe d'une entrée sélectionnée dans le presse-papiers"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning(self.texts["warning"], self.texts["select_warning"])
            return
        
        # Correction: Récupérer uniquement le nom du service (première valeur)
        item = self.tree.item(selected)
        service = item['values'][0]
        
        data = self._load_data()
      
        if service in data:
            pyperclip.copy(data[service]["password"])
            messagebox.showinfo(self.texts["success"], f"{self.texts['copied']}")
        else:
            messagebox.showerror(self.texts["error"], self.texts["password_not_found"])
      
    def setup_add_tab(self, frame):
        """Configure l'onglet d'ajout d'enregistrement"""
        form_frame = ttk.Frame(frame)
        form_frame.pack(pady=20, padx=20, fill=tk.X)

        # Service
        ttk.Label(form_frame, text=self.texts["service_label"], foreground=self.text_color).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.service_entry = ttk.Entry(form_frame)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.create_context_menu(self.service_entry)

        # Nom d'utilisateur
        ttk.Label(form_frame, text=self.texts["username_label"], foreground=self.text_color).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(form_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.create_context_menu(self.username_entry)

        # Mot de passe
        ttk.Label(form_frame, text=self.texts["password_label"], foreground=self.text_color).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.pwd_entry = ttk.Entry(form_frame, show="•")
        self.pwd_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.create_context_menu(self.pwd_entry)

        # Bouton coller mot de passe généré
        ttk.Button(form_frame, text=self.texts["paste_pwd_btn"], 
                  command=lambda: self.paste_generated_password(self.pwd_entry)).grid(row=2, column=2, padx=5)

        # Bouton afficher/masquer
        def toggle_password():
            if self.pwd_entry['show'] == '':
                self.pwd_entry.config(show='•')
                toggle_btn.config(text=self.texts["show_btn"])
            else:
                self.pwd_entry.config(show='')
                toggle_btn.config(text=self.texts["hide_btn"])

        toggle_btn = ttk.Button(form_frame, text=self.texts["show_btn"], command=toggle_password)
        toggle_btn.grid(row=2, column=3, padx=5)

        # Boutons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text=self.texts["add_btn"], style='Secondary.TButton',
                  command=self.add_to_list).pack(side=tk.LEFT, padx=5)

    def add_to_list(self):
        """Ajoute l'entrée à la liste de façon permanente"""
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.pwd_entry.get()
        
        if not service or not username or not password:
            messagebox.showerror(self.texts["error"], self.texts["all_fields"])
            return
        
        # Sauvegarder le mot de passe dans le fichier
        data = self._load_data()
        data[service] = {
            "username": username,
            "password": password,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        self._save_data(data)
        
        # Actualiser la Treeview
        self.load_passwords()
        
        messagebox.showinfo(self.texts["success"], self.texts["add_success"])
        self.clear_add_form()

    def clear_add_form(self):
        """Réinitialise le formulaire d'ajout"""
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.pwd_entry.delete(0, tk.END)

    def setup_generate_tab(self, frame):
        """Configure l'onglet de génération de mots de passe"""
        form_frame = ttk.Frame(frame)
        form_frame.pack(pady=20, padx=20, fill=tk.X)

        # Longueur
        ttk.Label(form_frame, text=self.texts["length_label"], foreground=self.text_color).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.length_spin = ttk.Spinbox(form_frame, from_=8, to=32, width=5)
        self.length_spin.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.length_spin.set(12)

        # Chiffres
        ttk.Label(form_frame, text=self.texts["digits_label"], foreground=self.text_color).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.digits_spin = ttk.Spinbox(form_frame, from_=0, to=10, width=5)
        self.digits_spin.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.digits_spin.set(2)

        # Caractères spéciaux
        ttk.Label(form_frame, text=self.texts["special_label"], foreground=self.text_color).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.special_spin = ttk.Spinbox(form_frame, from_=0, to=10, width=5)
        self.special_spin.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.special_spin.set(2)

        # Caractères à exclure
        self.exclude_chars_default = tk.StringVar(value="è`è~é°={}<[+^]%")  # Définir les caractères par défaut ici
        ttk.Label(form_frame, text=self.texts["exclude_label"], foreground=self.text_color).grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.exclude_entry = ttk.Entry(form_frame, textvariable=self.exclude_chars_default)
        self.exclude_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        # Résultat
        ttk.Label(form_frame, text=self.texts["generated_label"], foreground=self.text_color).grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.result_entry = ttk.Entry(form_frame, font=("Courier", 12))
        self.result_entry.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        self.create_context_menu(self.result_entry)

        # Forcer la force de mot de passe
        self.strength_label = ttk.Label(form_frame, text=self.texts["strength_label"] + " -", font=self.font_subtitle, foreground=self.text_color)
        self.strength_label.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        # Boutons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text=self.texts["generate_btn"], style='Primary.TButton',
                  command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=self.texts["copy_btn"], style='Secondary.TButton',
                  command=self.copy_generated_password).pack(side=tk.LEFT, padx=5)

    def generate_password(self):
        """Génère un mot de passe selon les critères"""
        try:
            length = int(self.length_spin.get())
            min_digits = int(self.digits_spin.get())
            min_special = int(self.special_spin.get())
            excluded = self.exclude_entry.get()
            
            if length < (min_digits + min_special):
                messagebox.showerror(self.texts["error"], self.texts["length_too_small"])
                return
            
            password = self._generate_password(length, min_digits, min_special, excluded)
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, password)
            
            # Évaluer la force du mot de passe
            strength = self.evaluate_password_strength(password)
            self.strength_label.config(text=f"{self.texts['strength_label']} {strength}")
            
        except ValueError:
            messagebox.showerror(self.texts["error"], self.texts["invalid_values"])

    def _generate_password(self, length=12, min_digits=2, min_special=2, excluded=""):
        """Génère un mot de passe fort"""
        letters = string.ascii_letters
        digits = string.digits
        special = ''.join(c for c in string.punctuation if c not in excluded)
        
        if not special:
            special = string.punctuation  # Fallback si tous exclus
        
        password = []
        
        # Ajout des caractères obligatoires
        password.extend(random.choice(digits) for _ in range(min_digits))
        password.extend(random.choice(special) for _ in range(min_special))
        
        # Remplissage avec des caractères aléatoires
        remaining = length - min_digits - min_special
        all_chars = letters + digits + special
        password.extend(random.choice(all_chars) for _ in range(remaining))
        
        # Mélange
        random.shuffle(password)
        
        return ''.join(password)

    def evaluate_password_strength(self, password):
        """Évalue la force d'un mot de passe"""
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        score = 0
        
        # Longueur
        if length >= 12: score += 3
        elif length >= 8: score += 2
        elif length >= 6: score += 1
        
        # Complexité
        if has_upper: score += 1
        if has_lower: score += 1
        if has_digit: score += 1
        if has_special: score += 2
        
        # Évaluation
        if score >= 7: 
            return self.texts["strength_verystrong"]
        elif score >= 5: 
            return self.texts["strength_strong"]
        elif score >= 3: 
            return self.texts["strength_medium"]
        else: 
            return self.texts["strength_weak"]

    def copy_generated_password(self):
        """Copie le mot de passe généré"""
        password = self.result_entry.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo(self.texts["success"], self.texts["copied"])
        else:
            messagebox.showwarning(self.texts["warning"], self.texts["warning_generate"])

    def use_generated_password(self):
        """Utilise le mot de passe généré dans l'onglet d'ajout"""
        password = self.result_entry.get()
        if not password:
            messagebox.showwarning(self.texts["warning"], self.texts["warning_generate"])
            return
        
        # Trouver l'onglet d'ajout
        notebook = self.root.nametowidget(self.root.children['!frame'].children['!notebook'])
        notebook.select(1)  # Sélectionne l'onglet d'ajout
        
        # Met à jour le champ de mot de passe
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, password)

    def delete_password(self):
       """Supprime le mot de passe sélectionné"""
       selected = self.tree.focus()
       if not selected:
           messagebox.showwarning(self.texts["warning"], self.texts["select_warning"])
           return
       
       # Correction: Récupérer uniquement le nom du service (première valeur)
       item = self.tree.item(selected)
       service = item['values'][0]
       
       if messagebox.askyesno("Confirmation", self.texts["delete_confirm"].format(service)):
           data = self._load_data()
           if service in data:
               del data[service]
               self._save_data(data)
               self.load_passwords()
               messagebox.showinfo(self.texts["success"], self.texts["delete_success"])

if __name__ == "__main__":
    try:
        import pyperclip
    except ImportError:
        print("Installez pyperclip avec: pip install pyperclip")
        exit(1)

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("Installez cryptography avec: pip install cryptography")
        exit(1)

    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
