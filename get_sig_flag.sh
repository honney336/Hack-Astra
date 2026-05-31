#!/bin/bash

# Complete automated flag retriever
# Usage: ./get_flag.sh

echo "[+] Starting flag extraction..."

# Get all prefix hashes (1-43)
echo "[+] Extracting prefix hashes..."
for i in {1..43}; do
    hash=$(/usr/local/bin/hasher -f /flag.txt -o $i 2>/dev/null)
    echo "$i:$hash"
done > /tmp/prefix_hashes.txt

echo "[+] Hashes extracted. Starting brute force..."

# Full character set
chars="A B C D E F G H I J K L M N O P Q R S T U V W X Y Z a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 _ { } -"

# Read hashes into array
mapfile -t hashes < <(cut -d: -f2 /tmp/prefix_hashes.txt)

flag=""
found_flag=""

for len in {1..43}; do
    target="${hashes[$((len-1))]}"
    found=0
    
    for char in $chars; do
        candidate="$flag$char"
        echo -n "$candidate" > /tmp/candidate
        hash=$(/usr/local/bin/hasher -f /tmp/candidate 2>/dev/null)
        
        if [ "$hash" = "$target" ]; then
            flag="$candidate"
            echo "  [$len/43] Found: $flag"
            found=1
            
            # Check if we reached the end (flag should end with })
            if [[ "$flag" == *"}" ]]; then
                found_flag="$flag"
                echo ""
                echo "[+] Complete flag found!"
                echo "=========================================="
                echo "FLAG: $flag"
                echo "=========================================="
                exit 0
            fi
            break
        fi
    done
    
    if [ $found -eq 0 ]; then
        echo "[-] Failed at length $len"
        echo "[-] Target hash: $target"
        echo "[-] Current flag: $flag"
        exit 1
    fi
done

echo ""
echo "=========================================="
echo "FLAG: $flag"
echo "=========================================="
