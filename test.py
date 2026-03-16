import airlock, json, random, string

random.seed(42)

def rand_name():
    first = random.choice(["Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hank"])
    last = random.choice(["Johnson", "Smith", "Williams", "Brown", "Jones", "Garcia", "Miller"])
    return f"{first} {last}"

def rand_email(name):
    return f"{name.split()[0].lower()}{''.join(random.choices(string.digits, k=3))}@corp.com"

def rand_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

actions = ["login", "logout", "view", "edit", "delete", "upload", "download"]

records = []
for _ in range(50):
    name = rand_name()
    records.append({
        "timestamp": f"2026-01-15T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z",
        "user": name,
        "email": rand_email(name),
        "action": random.choice(actions),
        "ip": rand_ip(),
        "status": random.choice(["success", "failure"]),
    })

result = airlock.scrub(json.dumps(records), salt="test-secret")
print(f"PII count:     {result.pii_count}")
print(f"Risk score:    {result.risk_score}")
print(f"Reduction:     {result.reduction_pct:.1f}%")
print()

result2 = airlock.compress(json.dumps(records))
print(f"Tokens before: {result2.tokens_before}")
print(f"Tokens after:  {result2.tokens_after}")
print(f"Reduction:     {result2.reduction_pct:.1f}%")
print(f"Entry count:   {result2.entry_count}")
