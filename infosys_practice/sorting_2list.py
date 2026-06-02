def merge_sortedlist(l1,l2):
    merged=[]
    i,j=0,0
    while i < len(l1) and j < len(l2):
        if l1[i] < l2[j]:
            merged.append(l1[i])
            i+=1
        else:
            merged.append(l2[j])
            j+=1
    
    merged.extend(l1[i:])
    merged.extend(l2[j:])
    
    return merged
    
print(merge_sortedlist([1, 3, 5], [2, 4, 6]))
    