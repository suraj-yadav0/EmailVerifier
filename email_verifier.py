import re
import dns.resolver
import smtplib
import socket
import threading
from typing import Dict, List
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv

class EmailVerifier:
    def __init__(self, timeout: int = 10, enable_smtp: bool = True):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        self.timeout = timeout
        self.enable_smtp = enable_smtp
        self.disposable_domains = self._load_disposable_domains()
    
    def _load_disposable_domains(self) -> set:
        return {
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'fakeinbox.com', 'maildrop.cc', 'yopmail.com', 'trashmail.com',
            'getnada.com', 'mohmal.com', 'sharklasers.com', 'guerrillamail.info',
            'grr.la', 'guerrillamail.biz', 'guerrillamail.de', 'spam4.me',
            'mailnesia.com', 'mytemp.email', 'tempail.com', 'dispostable.com'
        }
    
    def verify_email(self, email: str) -> Dict[str, any]:
        results = {
            'email': email,
            'valid_format': False,
            'dns_valid': False,
            'mx_records': [],
            'smtp_check': None,
            'disposable': False,
            'role_based': False,
            'free_provider': False,
            'score': 0,
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        if not self._validate_format(email):
            results['errors'].append('Invalid email format')
            return results
        
        results['valid_format'] = True
        results['score'] += 20
        
        local_part, domain = email.split('@')
        
        results['role_based'] = self._is_role_based(local_part)
        if results['role_based']:
            results['score'] -= 10
        
        results['free_provider'] = self._is_free_provider(domain)
        
        mx_records = self._check_mx_records(domain)
        if mx_records:
            results['dns_valid'] = True
            results['mx_records'] = mx_records
            results['score'] += 30
        else:
            results['errors'].append('No MX records found')
            return results
        
        results['disposable'] = self._is_disposable(domain)
        if results['disposable']:
            results['score'] -= 30
            results['errors'].append('Disposable email detected')
        else:
            results['score'] += 20
        
        if self.enable_smtp and mx_records:
            try:
                smtp_result = self._verify_smtp(email, mx_records[0])
                results['smtp_check'] = smtp_result
                if smtp_result:
                    results['score'] += 30
                else:
                    results['errors'].append('SMTP verification failed')
            except Exception as e:
                results['errors'].append(f'SMTP check error: {str(e)}')
        
        results['score'] = max(0, min(100, results['score']))
        return results
    
    def _validate_format(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _check_mx_records(self, domain: str) -> list:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            records = sorted(
                [(r.preference, str(r.exchange).rstrip('.')) for r in mx_records],
                key=lambda x: x[0]
            )
            return [record[1] for record in records]
        except:
            return []
    
    def _verify_smtp(self, email: str, mx_host: str) -> bool:
        try:
            host = socket.gethostname()
            server = smtplib.SMTP(timeout=self.timeout)
            server.connect(mx_host)
            server.helo(host)
            server.mail('verify@example.com')
            code, message = server.rcpt(email)
            server.quit()
            return code == 250
        except:
            return False
    
    def _is_disposable(self, domain: str) -> bool:
        return domain.lower() in self.disposable_domains
    
    def _is_role_based(self, local_part: str) -> bool:
        role_accounts = {
            'admin', 'administrator', 'support', 'info', 'contact',
            'sales', 'marketing', 'help', 'noreply', 'no-reply',
            'webmaster', 'postmaster', 'hostmaster', 'abuse'
        }
        return local_part.lower() in role_accounts
    
    def _is_free_provider(self, domain: str) -> bool:
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
            'zoho.com', 'yandex.com', 'gmx.com'
        }
        return domain.lower() in free_providers


class EmailVerifierGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Verifier Pro")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        self.verifier = EmailVerifier()
        self.results = []
        
        self.setup_ui()
    
    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill='x', pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="📧 Email Verifier Pro", 
            font=('Arial', 20, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=15)
        
        # Main container
        main_container = tk.Frame(self.root, bg='#f0f0f0')
        main_container.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Left panel - Input
        left_panel = tk.LabelFrame(
            main_container, 
            text="Input", 
            font=('Arial', 12, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Single email verification
        single_frame = tk.LabelFrame(left_panel, text="Single Email", bg='white', padx=10, pady=10)
        single_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(single_frame, text="Email Address:", bg='white').pack(anchor='w')
        self.single_email_entry = tk.Entry(single_frame, font=('Arial', 11), width=40)
        self.single_email_entry.pack(fill='x', pady=5)
        
        single_btn = tk.Button(
            single_frame,
            text="Verify Single Email",
            command=self.verify_single,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief='flat',
            padx=10,
            pady=5
        )
        single_btn.pack(pady=5)
        
        # Bulk verification
        bulk_frame = tk.LabelFrame(left_panel, text="Bulk Verification", bg='white', padx=10, pady=10)
        bulk_frame.pack(fill='both', expand=True)
        
        tk.Label(bulk_frame, text="Enter emails (one per line):", bg='white').pack(anchor='w')
        
        self.bulk_text = scrolledtext.ScrolledText(
            bulk_frame,
            height=10,
            font=('Arial', 10),
            wrap='word'
        )
        self.bulk_text.pack(fill='both', expand=True, pady=5)
        
        bulk_btn_frame = tk.Frame(bulk_frame, bg='white')
        bulk_btn_frame.pack(fill='x', pady=5)
        
        tk.Button(
            bulk_btn_frame,
            text="Import from File",
            command=self.import_emails,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2',
            relief='flat'
        ).pack(side='left', padx=5)
        
        tk.Button(
            bulk_btn_frame,
            text="Verify Bulk",
            command=self.verify_bulk,
            bg='#27ae60',
            fg='white',
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            relief='flat',
            padx=15
        ).pack(side='right')
        
        tk.Button(
            bulk_btn_frame,
            text="Clear",
            command=lambda: self.bulk_text.delete('1.0', 'end'),
            bg='#e74c3c',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2',
            relief='flat'
        ).pack(side='right', padx=5)
        
        # Right panel - Results
        right_panel = tk.LabelFrame(
            main_container,
            text="Results",
            font=('Arial', 12, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(
            right_panel,
            height=20,
            font=('Courier', 9),
            wrap='word'
        )
        self.results_text.pack(fill='both', expand=True)
        
        # Export buttons
        export_frame = tk.Frame(right_panel, bg='white')
        export_frame.pack(fill='x', pady=(10, 0))
        
        tk.Button(
            export_frame,
            text="Export JSON",
            command=lambda: self.export_results('json'),
            bg='#9b59b6',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2',
            relief='flat'
        ).pack(side='left', padx=5)
        
        tk.Button(
            export_frame,
            text="Export CSV",
            command=lambda: self.export_results('csv'),
            bg='#e67e22',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2',
            relief='flat'
        ).pack(side='left', padx=5)
        
        tk.Button(
            export_frame,
            text="Clear Results",
            command=self.clear_results,
            bg='#95a5a6',
            fg='white',
            font=('Arial', 9, 'bold'),
            cursor='hand2',
            relief='flat'
        ).pack(side='right')
        
        # Settings panel at bottom
        settings_frame = tk.LabelFrame(
            self.root,
            text="Settings",
            font=('Arial', 10, 'bold'),
            bg='white',
            padx=15,
            pady=10
        )
        settings_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        settings_inner = tk.Frame(settings_frame, bg='white')
        settings_inner.pack()
        
        self.smtp_var = tk.BooleanVar(value=True)
        smtp_check = tk.Checkbutton(
            settings_inner,
            text="Enable SMTP Verification",
            variable=self.smtp_var,
            command=self.update_settings,
            bg='white',
            font=('Arial', 10)
        )
        smtp_check.pack(side='left', padx=10)
        
        tk.Label(settings_inner, text="Timeout (seconds):", bg='white', font=('Arial', 10)).pack(side='left', padx=(20, 5))
        self.timeout_spinbox = tk.Spinbox(
            settings_inner,
            from_=5,
            to=30,
            width=5,
            font=('Arial', 10),
            command=self.update_settings
        )
        self.timeout_spinbox.delete(0, 'end')
        self.timeout_spinbox.insert(0, '10')
        self.timeout_spinbox.pack(side='left')
        
        # Status bar
        self.status_label = tk.Label(
            self.root,
            text="Ready",
            bg='#34495e',
            fg='white',
            font=('Arial', 9),
            anchor='w',
            padx=10
        )
        self.status_label.pack(fill='x', side='bottom')
    
    def update_settings(self):
        self.verifier.enable_smtp = self.smtp_var.get()
        self.verifier.timeout = int(self.timeout_spinbox.get())
        self.status_label.config(text=f"Settings updated - SMTP: {self.verifier.enable_smtp}, Timeout: {self.verifier.timeout}s")
    
    def verify_single(self):
        email = self.single_email_entry.get().strip()
        if not email:
            messagebox.showwarning("Input Required", "Please enter an email address")
            return
        
        self.status_label.config(text=f"Verifying {email}...")
        self.root.update()
        
        def verify():
            result = self.verifier.verify_email(email)
            self.results.append(result)
            self.root.after(0, lambda: self.display_single_result(result))
        
        threading.Thread(target=verify, daemon=True).start()
    
    def display_single_result(self, result):
        self.results_text.delete('1.0', 'end')
        
        output = f"{'='*60}\n"
        output += f"EMAIL VERIFICATION REPORT\n"
        output += f"{'='*60}\n\n"
        output += f"Email: {result['email']}\n"
        output += f"Timestamp: {result['timestamp']}\n\n"
        
        output += f"--- Validation Results ---\n"
        output += f"Valid Format: {'✓' if result['valid_format'] else '✗'}\n"
        output += f"DNS Valid: {'✓' if result['dns_valid'] else '✗'}\n"
        output += f"SMTP Check: {result['smtp_check'] if result['smtp_check'] is not None else 'N/A'}\n\n"
        
        output += f"--- Email Properties ---\n"
        output += f"Disposable: {'Yes ⚠' if result['disposable'] else 'No'}\n"
        output += f"Role-based: {'Yes' if result['role_based'] else 'No'}\n"
        output += f"Free Provider: {'Yes' if result['free_provider'] else 'No'}\n\n"
        
        if result['mx_records']:
            output += f"--- MX Records ---\n"
            for i, mx in enumerate(result['mx_records'][:3], 1):
                output += f"{i}. {mx}\n"
            output += "\n"
        
        if result['errors']:
            output += f"--- Errors ---\n"
            for error in result['errors']:
                output += f"• {error}\n"
            output += "\n"
        
        score = result['score']
        output += f"--- Overall Score ---\n"
        output += f"Score: {score}/100 "
        
        if score >= 80:
            output += "✓ EXCELLENT\n"
        elif score >= 60:
            output += "⚠ GOOD\n"
        elif score >= 40:
            output += "⚠ FAIR\n"
        else:
            output += "✗ POOR\n"
        
        self.results_text.insert('1.0', output)
        self.status_label.config(text=f"Verification complete - Score: {score}/100")
    
    def verify_bulk(self):
        text = self.bulk_text.get('1.0', 'end').strip()
        emails = [e.strip() for e in text.split('\n') if e.strip()]
        
        if not emails:
            messagebox.showwarning("Input Required", "Please enter email addresses")
            return
        
        self.status_label.config(text=f"Verifying {len(emails)} emails...")
        self.results_text.delete('1.0', 'end')
        self.root.update()
        
        def verify():
            results = []
            for i, email in enumerate(emails, 1):
                self.root.after(0, lambda i=i: self.status_label.config(text=f"Verifying {i}/{len(emails)}..."))
                result = self.verifier.verify_email(email)
                results.append(result)
            
            self.results.extend(results)
            self.root.after(0, lambda: self.display_bulk_results(results))
        
        threading.Thread(target=verify, daemon=True).start()
    
    def display_bulk_results(self, results):
        output = f"{'='*60}\n"
        output += f"BULK VERIFICATION REPORT\n"
        output += f"Total Emails: {len(results)}\n"
        output += f"{'='*60}\n\n"
        
        for result in results:
            score = result['score']
            status = "✓" if score >= 70 else "✗"
            output += f"{status} {result['email']:35} | Score: {score:3}/100 | "
            
            if result['disposable']:
                output += "Disposable "
            if result['role_based']:
                output += "Role-based "
            
            output += "\n"
        
        valid_count = sum(1 for r in results if r['score'] >= 70)
        output += f"\n{'='*60}\n"
        output += f"Summary: {valid_count}/{len(results)} emails passed validation\n"
        
        self.results_text.insert('1.0', output)
        self.status_label.config(text=f"Bulk verification complete - {valid_count}/{len(results)} valid")
    
    def import_emails(self):
        filename = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    if filename.endswith('.csv'):
                        reader = csv.reader(f)
                        emails = [row[0] for row in reader if row]
                    else:
                        emails = f.readlines()
                    
                    self.bulk_text.delete('1.0', 'end')
                    self.bulk_text.insert('1.0', '\n'.join(email.strip() for email in emails))
                    self.status_label.config(text=f"Imported {len(emails)} emails from {filename}")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import file:\n{str(e)}")
    
    def export_results(self, format):
        if not self.results:
            messagebox.showwarning("No Results", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format}",
            filetypes=[(f"{format.upper()} Files", f"*.{format}"), ("All Files", "*.*")]
        )
        
        if filename:
            try:
                if format == 'json':
                    with open(filename, 'w') as f:
                        json.dump(self.results, f, indent=2)
                elif format == 'csv':
                    with open(filename, 'w', newline='') as f:
                        if self.results:
                            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                            writer.writeheader()
                            for result in self.results:
                                writer.writerow(result)
                
                messagebox.showinfo("Export Success", f"Results exported to {filename}")
                self.status_label.config(text=f"Exported {len(self.results)} results to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def clear_results(self):
        self.results_text.delete('1.0', 'end')
        self.results = []
        self.status_label.config(text="Results cleared")


def main():
    root = tk.Tk()
    app = EmailVerifierGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()