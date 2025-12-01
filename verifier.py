import re
import dns.resolver
import smtplib
import socket
from typing import Dict, Tuple

class EmailVerifier:
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
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
            'smtp_check': False,
            'disposable': False,
            'errors': []
        }
        
        # Step 1: Format validation
        if not self._validate_format(email):
            results['errors'].append('Invalid email format')
            return results
        
        results['valid_format'] = True
        
        # Extract domain
        domain = email.split('@')[1]
        
        # Step 2: DNS and MX record check
        mx_records = self._check_mx_records(domain)
        if mx_records:
            results['dns_valid'] = True
            results['mx_records'] = mx_records
        else:
            results['errors'].append('No MX records found')
            return results
        
        # Step 3: Check if disposable email
        results['disposable'] = self._is_disposable(domain)
        
        # Step 4: SMTP verification (optional, can be slow)
        try:
            results['smtp_check'] = self._verify_smtp(email, mx_records[0])
        except Exception as e:
            results['errors'].append(f'SMTP check failed: {str(e)}')
        
        return results
    
    def _validate_format(self, email: str) -> bool:
        """
        Validate email format using regex
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _check_mx_records(self, domain: str) -> list:
        """
        Check DNS MX records for the domain
        """
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            # Sort by priority and return exchange names
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
    
    def _verify_smtp(self, email: str, mx_host: str, timeout: int = 10) -> bool:
        """
        Verify email via SMTP without sending actual email
        """
        try:
            # Get local hostname
            host = socket.gethostname()
            
            # Connect to SMTP server
            server = smtplib.SMTP(timeout=timeout)
            server.connect(mx_host)
            server.helo(host)
            server.mail('verify@example.com')
            code, message = server.rcpt(email)
            server.quit()
            
            # 250 is success code
            return code == 250
        except smtplib.SMTPServerDisconnected:
            return False
        except smtplib.SMTPConnectError:
            return False
        except Exception as e:
            print(f"SMTP verification error: {e}")
            return False
    
    def _is_disposable(self, domain: str) -> bool:
        """
        Check if domain is a known disposable email provider
        """
        disposable_domains = {
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'fakeinbox.com', 'maildrop.cc', 'yopmail.com'
        }
        return domain.lower() in disposable_domains


def main():
    """
    Example usage of EmailVerifier
    """
    verifier = EmailVerifier()
    
    # Test emails
    test_emails = [
        'surajyadav200701@gmail.com',
        'invalid.email@',
        'test@nonexistentdomain12345.com',
        'user@tempmail.com',
        's.yadav@calin.co.in'

    ]
    
    print("Email Verification Results")
    print("=" * 80)
    
    for email in test_emails:
        print(f"\nVerifying: {email}")
        print("-" * 80)
        
        results = verifier.verify_email(email)
        
        print(f"Valid Format: {results['valid_format']}")
        print(f"DNS Valid: {results['dns_valid']}")
        
        if results['mx_records']:
            print(f"MX Records: {', '.join(results['mx_records'][:3])}")
        
        print(f"SMTP Check: {results['smtp_check']}")
        print(f"Disposable: {results['disposable']}")
        
        if results['errors']:
            print(f"Errors: {', '.join(results['errors'])}")
        
        # Overall verdict
        is_valid = (results['valid_format'] and 
                   results['dns_valid'] and 
                   not results['disposable'])
        print(f"\n✓ VALID EMAIL" if is_valid else "✗ INVALID EMAIL")


if __name__ == "__main__":
    main()