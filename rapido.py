import discord
import base64
import hashlib
import re
import codecs
from urllib.parse import unquote, quote
import asyncio
from typing import Optional, Dict, Pattern
import functools

# Pre-compile all regex patterns for speed
class FastSolver:
    def __init__(self):
        # Pre-compile all patterns
        self.patterns = {
            'flag': re.compile(r'FLAG\[([^\]]+)\]'),
            'reverse': re.compile(r'reverse(?:\s+the\s+string)?:\s*(\S+)', re.IGNORECASE),
            'base64_decode': re.compile(r'base64 decode:\s*(\S+)'),
            'base64_encode': re.compile(r'base64 encode:\s*(\S+)'),
            'hex_decode': re.compile(r'hex decode:\s*([0-9a-fA-F]+)'),
            'hex_encode': re.compile(r'hex encode:\s*(\S+)'),
            'digits': re.compile(r'return only digits from:\s*(\S+)'),
            'count': re.compile(r"Count '(.+?)' in:\s*(\S+)"),
            'binary_to_dec': re.compile(r'binary to decimal:\s*([01]+)'),
            'dec_to_binary': re.compile(r'decimal to binary:\s*(\d+)'),
            'hex_to_dec': re.compile(r'hex to decimal:\s*([0-9a-fA-F]+)'),
            'dec_to_hex': re.compile(r'decimal to hex:\s*(\d+)'),
            'octal_to_dec': re.compile(r'octal to decimal:\s*([0-7]+)'),
            'dec_to_octal': re.compile(r'decimal to octal:\s*(\d+)'),
            'rot13': re.compile(r'rot13 decode:\s*(\S+)'),
            'url_decode': re.compile(r'url decode:\s*(\S+)'),
            'url_encode': re.compile(r'url encode:\s*(\S+)'),
            'ascii_to_char': re.compile(r'ascii to char:\s*(\d+)'),
            'char_to_ascii': re.compile(r'char to ascii:\s*(\S)'),
            'uppercase': re.compile(r'uppercase:\s*(\S+)', re.IGNORECASE),
            'lowercase': re.compile(r'lowercase:\s*(\S+)', re.IGNORECASE),
        }
        
        # Math patterns (most common first)
        self.math_add = re.compile(r'What is (\d+)\s*\+\s*(\d+)\?')
        self.math_sub = re.compile(r'What is (\d+)\s*-\s*(\d+)\?')
        self.math_mul = re.compile(r'What is (\d+)\s*\*\s*(\d+)\?')
        self.math_div = re.compile(r'What is (\d+)\s*/\s*(\d+)\?')
        self.math_complex = re.compile(r'What is (.+?)\?')
        
        # MD5/SHA patterns
        self.md5 = re.compile(r'md5\("(.+?)"\)\[:(\d+)\]')
        self.sha256 = re.compile(r'sha256\("(.+?)"\)\[:(\d+)\]')
        self.sha1 = re.compile(r'sha1\("(.+?)"\)\[:(\d+)\]')
        self.caesar = re.compile(r'caesar\s+(?:cipher\s+)?(?:decode|shift)[:\s]+(\S+)\s+(?:shift\s+)?(\d+)', re.IGNORECASE)
    
    def solve(self, question: str) -> Optional[str]:
        # Remove leading/trailing whitespace
        q = question.strip()
        
        # FAST TRACK: Direct string operations (fastest)
        if 'FLAG[' in q:
            match = self.patterns['flag'].search(q)
            if match:
                return match.group(1).strip()
        
        # Reverse (very fast - no regex needed for simple case)
        if q.startswith('reverse') or 'reverse this:' in q:
            if 'reverse this:' in q:
                text = q.split('reverse this:')[-1].strip()
            else:
                match = self.patterns['reverse'].search(q)
                if match:
                    text = match.group(1)
                else:
                    return None
            return text[::-1]
        
        # Simple addition (most common math)
        match = self.math_add.search(q)
        if match:
            return str(int(match.group(1)) + int(match.group(2)))
        
        match = self.math_sub.search(q)
        if match:
            return str(int(match.group(1)) - int(match.group(2)))
        
        match = self.math_mul.search(q)
        if match:
            return str(int(match.group(1)) * int(match.group(2)))
        
        match = self.math_div.search(q)
        if match:
            return str(int(int(match.group(1)) / int(match.group(2))))
        
        # ROT13 (common)
        if 'rot13' in q:
            match = self.patterns['rot13'].search(q)
            if match:
                return codecs.decode(match.group(1), 'rot_13')
        
        # Base64
        if 'base64 decode' in q:
            match = self.patterns['base64_decode'].search(q)
            if match:
                try:
                    return base64.b64decode(match.group(1)).decode()
                except:
                    pass
        
        if 'base64 encode' in q:
            match = self.patterns['base64_encode'].search(q)
            if match:
                return base64.b64encode(match.group(1).encode()).decode()
        
        # Binary/Decimal conversions
        if 'binary to decimal' in q:
            match = self.patterns['binary_to_dec'].search(q)
            if match:
                return str(int(match.group(1), 2))
        
        if 'decimal to binary' in q:
            match = self.patterns['dec_to_binary'].search(q)
            if match:
                return bin(int(match.group(1)))[2:]
        
        if 'hex to decimal' in q:
            match = self.patterns['hex_to_dec'].search(q)
            if match:
                return str(int(match.group(1), 16))
        
        if 'decimal to hex' in q:
            match = self.patterns['dec_to_hex'].search(q)
            if match:
                return hex(int(match.group(1)))[2:]
        
        # Continue with other patterns...
        for pattern_name, pattern in self.patterns.items():
            if pattern_name in ['flag', 'reverse', 'base64_decode', 'base64_encode', 
                               'hex_decode', 'hex_encode', 'digits', 'count', 
                               'octal_to_dec', 'dec_to_octal', 'url_decode', 
                               'url_encode', 'ascii_to_char', 'char_to_ascii',
                               'uppercase', 'lowercase']:
                match = pattern.search(q)
                if match:
                    if pattern_name == 'hex_decode':
                        try:
                            return bytes.fromhex(match.group(1)).decode()
                        except:
                            continue
                    elif pattern_name == 'hex_encode':
                        return match.group(1).encode().hex()
                    elif pattern_name == 'digits':
                        return re.sub(r'\D', '', match.group(1))
                    elif pattern_name == 'count':
                        return str(match.group(2).count(match.group(1)))
                    elif pattern_name in ['octal_to_dec', 'url_decode', 'ascii_to_char', 'uppercase', 'lowercase']:
                        if pattern_name == 'octal_to_dec':
                            return str(int(match.group(1), 8))
                        elif pattern_name == 'url_decode':
                            return unquote(match.group(1))
                        elif pattern_name == 'ascii_to_char':
                            return chr(int(match.group(1)))
                        elif pattern_name == 'uppercase':
                            return match.group(1).upper()
                        elif pattern_name == 'lowercase':
                            return match.group(1).lower()
                    else:
                        return match.group(1)
        
        # Hashes
        match = self.md5.search(q)
        if match:
            h = hashlib.md5(match.group(1).encode()).hexdigest()
            return h[:int(match.group(2))]
        
        match = self.sha256.search(q)
        if match:
            h = hashlib.sha256(match.group(1).encode()).hexdigest()
            return h[:int(match.group(2))]
        
        match = self.sha1.search(q)
        if match:
            h = hashlib.sha1(match.group(1).encode()).hexdigest()
            return h[:int(match.group(2))]
        
        # Caesar
        match = self.caesar.search(q)
        if match:
            text, shift = match.group(1), int(match.group(2))
            result = ""
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    result += chr((ord(c) - base - shift) % 26 + base)
                else:
                    result += c
            return result
        
        # Complex math as last resort
        match = self.math_complex.search(q)
        if match:
            expr = match.group(1).strip()
            if re.match(r'^[\d\s\+\-\*\/\(\)]+$', expr):
                try:
                    return str(int(eval(expr)))
                except:
                    pass
        
        return None

# Initialize solver
solver = FastSolver()
client = discord.Client()
BOT_ID = 1506207114480062484
USER_TOKEN = "YOUR_DISCORD_USER_TOKEN"  # REPLACE THIS

@client.event
async def on_ready():
    print(f"✅ Logged in: {client.user}")
    print(f"🎯 Targeting bot: {BOT_ID}")
    print(f"⚡ Ultra-fast mode ACTIVE")

@client.event
async def on_message(message):
    # Ignore self
    if message.author.id == client.user.id:
        return
    
    # Only respond to target bot
    if message.author.id != BOT_ID:
        return
    
    content = message.content
    
    # Skip "Correct." messages immediately
    if content == "Correct." or content.startswith("Correct."):
        return
    
    # Extract question if formatted as "Q#/100: question"
    if ':' in content and content[0] == 'Q' and '/' in content:
        question = content.split(':', 1)[1].strip()
    else:
        question = content
    
    # Solve instantly
    answer = solver.solve(question)
    
    if answer:
        print(f"⚡ Q: {question[:50]}")
        print(f"💡 A: {answer}")
        # Send response immediately
        await message.channel.send(answer)

if __name__ == "__main__":
    if USER_TOKEN == "YOUR_USER_TOKEN_HERE":
        print("❌ ERROR: Replace USER_TOKEN with your Discord user token!")
        print("Get it from: Discord Web > F12 > Network > Authorization header")
    else:
        client.run(USER_TOKEN)
