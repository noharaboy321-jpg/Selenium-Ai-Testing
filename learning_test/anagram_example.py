from collections import defaultdict
import string
from typing import List


"""
Problem A: Group Anagrams (Highly popular for validating array manipulation)Scenario: 
You are given an array of strings. You need to group anagrams together 
(e.g., Input: ["eat", "tea", "tan", "ate", "nat", "bat"] \(\rightarrow \) Output: [["eat","tea","ate"], ["tan","nat"], ["bat"]]).

"""

def group_anagrams_fast(strs: List[str]) -> List[List[str]]:
    """
    Groups anagrams together in O(N * K) time complexity using 
    a fixed-size character frequency array as a dictionary key.
    """
    # Initialize the map with 'list' as the factory blueprint
    anagram_map = defaultdict(list)
    
    for string in strs:
        # Step 1: Create a frequency tracker of 26 zeros for 'a' through 'z'
        count = [0] * 26 
        
        # Step 2: Map each character to its respective index using ASCII math
        for char in string:
            # ord('a') is 97. If char is 'e' (101), 101 - 97 = index 4
            count[ord(char) - ord('a')] += 1
            
        # Step 3: Convert the mutable list into an immutable tuple key
        count_key = tuple(count)
        
        # Step 4: Append the original string to its anagram family list
        anagram_map[count_key].append(string)
        
    # Step 5: Extract and return only the grouped lists from the map values
    return list(anagram_map.values())

# Example usage: string checker
def is_anagram(s: str, t: str) -> bool:
    # Quick length check
    if len(s) != len(t):
        return False
        
    # Step 1: Create frequency trackers for both strings
    count_s = [0] * 26
    count_t = [0] * 26
    
    # Step 2: Fill tracker for string s
    for char in s:
        count_s[ord(char) - ord('a')] += 1
        
    # Step 3: Fill tracker for string t
    for char in t:
        count_t[ord(char) - ord('a')] += 1
        
    # Step 4: Compare both lists directly
    return count_s == count_t

def is_anagram_optimized(s: str, t: str) -> bool:
    if len(s) != len(t): return False
    
    count = [0] * 26
    for i in range(len(s)):
        count[ord(s[i]) - ord('a')] += 1
        count[ord(t[i]) - ord('a')] -= 1
        
    # If all items are 0, return True
    return count == [0] * 26
