import re
import dns.resolver
import smtplib
import socket
import asyncio
import aiosmtplib
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime

class EmailVerifier:
    def __init__(self, timeout: int = 10, enable_smtp: bool = True):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        self.timeout = timeout
        self.enable_smtp = enable_smtp
        self.disposable_domains = self._load_disposable_domains()
    
    def _load_disposable_domains(self) -> set:
        """Load common disposable email domains"""
        return {
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'fakeinbox.com', 'maildrop.cc', 'yopmail.com', 'trashmail.com',
            'getnada.com', 'mohmal.com', 'sharklasers.com', 'guerrillamail.info',
            'grr.la', 'guerrillamail.biz', 'guerrillamail.de', 'spam4.me',
            'mailnesia.com', 'mytemp.email', 'tempail.com', 'dispostable.com'
        }
    
    def verify_email(self, email: str) -> Dict[str, any]:
        """
        Comprehensive email verification
        Returns a dictionary with verification results
        """
        results = {
            'email': email,
            'valid_format': False,
            'dns_valid': False,
            'mx_records': [],
            'smtp_check': None,
            'disposable': False,
            'catch_all': None,
            'role_based': False,
            'free_provider': False,
            'score': 0,
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Step 1: Format validation
        if not self._validate_format(email):
            results['errors'].append('Invalid email format')
            return results
        
        results['valid_format'] = True
        results['score'] += 20
        
        # Extract domain and local part
        local_part, domain = email.split('@')
        
        # Step 2: Check if role-based
        results['role_based'] = self._is_role_based(local_part)
        if results['role_based']:
            results['score'] -= 10
        
        # Step 3: Check if free provider
        results['free_provider'] = self._is_free_provider(domain)
        
        # Step 4: DNS and MX record check
        mx_records = self._check_mx_records(domain)
        if mx_records:
            results['dns_valid'] = True
            results['mx_records'] = mx_records
            results['score'] += 30
        else:
            results['errors'].append('No MX records found')
            return results
        
        # Step 5: Check if disposable email
        results['disposable'] = self._is_disposable(domain)
        if results['disposable']:
            results['score'] -= 30
            results['errors'].append('Disposable email detected')
        else:
            results['score'] += 20
        
        # Step 6: SMTP verification
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
        
        # Normalize score to 0-100
        results['score'] = max(0, min(100, results['score']))
        
        return results
    
    def verify_bulk(self, emails: List[str], max_workers: int = 10) -> List[Dict]:
        """
        Verify multiple emails concurrently
        """
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {
                executor.submit(self.verify_email, email): email 
                for email in emails
            }
            
            for future in as_completed(future_to_email):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    email = future_to_email[future]
                    results.append({
                        'email': email,
                        'valid_format': False,
                        'errors': [f'Verification failed: {str(e)}']
                    })
        
        return results
    
    async def verify_email_async(self, email: str) -> Dict[str, any]:
        """
        Async email verification for better performance
        """
        results = {
            'email': email,
            'valid_format': False,
            'dns_valid': False,
            'mx_records': [],
            'smtp_check': None,
            'disposable': False,
            'score': 0,
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Format validation
        if not self._validate_format(email):
            results['errors'].append('Invalid email format')
            return results
        
        results['valid_format'] = True
        results['score'] += 20
        
        local_part, domain = email.split('@')
        
        # Role-based check
        results['role_based'] = self._is_role_based(local_part)
        
        # DNS check
        mx_records = await asyncio.get_event_loop().run_in_executor(
            None, self._check_mx_records, domain
        )
        
        if mx_records:
            results['dns_valid'] = True
            results['mx_records'] = mx_records
            results['score'] += 30
        else:
            results['errors'].append('No MX records found')
            return results
        
        # Disposable check
        results['disposable'] = self._is_disposable(domain)
        if results['disposable']:
            results['score'] -= 30
        else:
            results['score'] += 20
        
        # Async SMTP verification
        if self.enable_smtp and mx_records:
            try:
                smtp_result = await self._verify_smtp_async(email, mx_records[0])
                results['smtp_check'] = smtp_result
                if smtp_result:
                    results['score'] += 30
            except Exception as e:
                results['errors'].append(f'SMTP check error: {str(e)}')
        
        results['score'] = max(0, min(100, results['score']))
        return results
    
    async def verify_bulk_async(self, emails: List[str]) -> List[Dict]:
        """
        Verify multiple emails asynchronously
        """
        tasks = [self.verify_email_async(email) for email in emails]
        return await asyncio.gather(*tasks)
    
    def _validate_format(self, email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _check_mx_records(self, domain: str) -> list:
        """Check DNS MX records for the domain"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            records = sorted(
                [(r.preference, str(r.exchange).rstrip('.')) for r in mx_records],
                key=lambda x: x[0]
            )
            return [record[1] for record in records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            print(f"DNS lookup error: {e}")
            return []
    
    def _verify_smtp(self, email: str, mx_host: str) -> bool:
        """Verify email via SMTP"""
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
    
    async def _verify_smtp_async(self, email: str, mx_host: str) -> bool:
        """Async SMTP verification"""
        try:
            async with aiosmtplib.SMTP(hostname=mx_host, timeout=self.timeout) as smtp:
                await smtp.connect()
                await smtp.ehlo()
                await smtp.mail('verify@example.com')
                code, message = await smtp.rcpt(email)
                return code == 250
        except:
            return False
    
    def _is_disposable(self, domain: str) -> bool:
        """Check if domain is disposable"""
        return domain.lower() in self.disposable_domains
    
    def _is_role_based(self, local_part: str) -> bool:
        """Check if email is role-based"""
        role_accounts = {
            'admin', 'administrator', 'support', 'info', 'contact',
            'sales', 'marketing', 'help', 'noreply', 'no-reply',
            'webmaster', 'postmaster', 'hostmaster', 'abuse'
        }
        return local_part.lower() in role_accounts
    
    def _is_free_provider(self, domain: str) -> bool:
        """Check if domain is a free email provider"""
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
            'zoho.com', 'yandex.com', 'gmx.com'
        }
        return domain.lower() in free_providers
    
    def export_results(self, results: List[Dict], filename: str, format: str = 'json'):
        """Export verification results to file"""
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
        elif format == 'csv':
            import csv
            if results:
                keys = results[0].keys()
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    for result in results:
                        writer.writerow(result)


def main():
    """Example usage"""
    verifier = EmailVerifier(enable_smtp=True)
    
    print("=" * 80)
    print("EMAIL VERIFIER - Advanced Features")
    print("=" * 80)
    
    # Single email verification
    print("\n1. SINGLE EMAIL VERIFICATION")
    print("-" * 80)
    email = "user@gmail.com"
    result = verifier.verify_email(email)
    print(f"Email: {result['email']}")
    print(f"Valid Format: {result['valid_format']}")
    print(f"DNS Valid: {result['dns_valid']}")
    print(f"SMTP Check: {result['smtp_check']}")
    print(f"Disposable: {result['disposable']}")
    print(f"Role-based: {result['role_based']}")
    print(f"Free Provider: {result['free_provider']}")
    print(f"Score: {result['score']}/100")
    
    # Bulk verification
    print("\n2. BULK EMAIL VERIFICATION")
    print("-" * 80)
    emails = [
        'test@gmail.com',
        'admin@company.com',
        'user@tempmail.com',
        'invalid@nonexistent123.com'
    ]
    
    results = verifier.verify_bulk(emails, max_workers=5)
    for r in results:
        status = "✓ VALID" if r.get('score', 0) >= 70 else "✗ INVALID"
        print(f"{r['email']:30} | Score: {r.get('score', 0):3}/100 | {status}")
    
    # Export results
    print("\n3. EXPORTING RESULTS")
    print("-" * 80)
    verifier.export_results(results, 'verification_results.json', format='json')
    print("✓ Results exported to verification_results.json")
    
    # Async bulk verification example
    print("\n4. ASYNC BULK VERIFICATION")
    print("-" * 80)
    async def async_example():
        async_results = await verifier.verify_bulk_async(emails)
        print(f"Verified {len(async_results)} emails asynchronously")
        return async_results
    
    # Uncomment to run async version
    # asyncio.run(async_example())
    print("Async verification ready (uncomment in code to run)")


if __name__ == "__main__":
    main()