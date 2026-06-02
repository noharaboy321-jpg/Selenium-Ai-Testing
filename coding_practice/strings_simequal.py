def same_word_pattern(s: str, t: str):
    if len(s) != len(t):
        return False
    s_map_t = {}
    t_map_s = {}
    for char_s, char_t in zip(s,t):
        if char_s in s_map_t:
            if s_map_t[char_s] != char_t:
                return False
        else: 
            s_map_t[char_s] = char_t
                
        if char_t in t_map_s:
            if t_map_s[char_t] != char_s:
                return False
        else: 
            t_map_s[char_t] = char_s
                
    return True
    
print(same_word_pattern("addq","eggc"))
print(same_word_pattern("egg", "add"))  # True  (e->a, g->d)
print(same_word_pattern("foo", "bar"))  # False (o tries to map to both a and r)
print(same_word_pattern("paper", "title"))  # True (p->t, a->i, e->l, r->e)
print(same_word_pattern("ab", "aa"))
                
def is_isomorphic(s: str, t: str) -> bool:
    if len(s) != len(t):
        return False
        
    map_s_to_t = {}
    map_t_to_s = {}
    
    # Zip lets us look at s[i] and t[i] together simultaneously
    for char_s, char_t in zip(s, t):
        
        # Check mapping from s to t
        if char_s in map_s_to_t:
            if map_s_to_t[char_s] != char_t:
                return False
        
        # Check mapping from t to s (prevents two characters from mapping to the same target)
        if char_t in map_t_to_s:
            if map_t_to_s[char_t] != char_s:
                return False
                
        # Establish the bidirectional link
        map_s_to_t[char_s] = char_t
        map_t_to_s[char_t] = char_s
        
    return True

# Test Cases
print(is_isomorphic("egg", "add"))     # Output: True
print(is_isomorphic("foo", "bar"))     # Output: False
print(is_isomorphic("paper", "title")) # Output: True
print(is_isomorphic("badc", "baba"))   # Output: False
