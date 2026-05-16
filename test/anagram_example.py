from collections import defaultdict
import string
from typing import List


"""
Problem A: Group Anagrams (Highly popular for validating array manipulation)Scenario: 
You are given an array of strings. You need to group anagrams together 
(e.g., Input: ["eat", "tea", "tan", "ate", "nat", "bat"] \(\rightarrow \) Output: [["eat","tea","ate"], ["tan","nat"], ["bat"]]).

"""
def example_group(strs: list[str]) -> List[List[str]]:
    
    dict=defaultdict(list)
    for string in strs:
        count = [0]*26
        for char in string:
            count[ord(char)-ord('a')] +=1
        dict[tuple(count)].append(string)

    return list(dict.values())
        















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