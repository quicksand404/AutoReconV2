import whois


domain = whois.whois('google.com')
print(domain.creation_date)